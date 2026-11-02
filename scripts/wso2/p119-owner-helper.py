#!/usr/bin/env python3
"""WSO2 P1.19: existing tenant owner Basic authentication, GET-only governance readback.
No prints of secrets, IDs, raw HTTP responses, URL query params, or account data.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys

BRANDS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}
FINGERPRINT = '2ba361a032ffd4b34f7df066de72b61c5e836a09f7a7bd7105eb87b4094d9712'
KEYS = ('SelfRegistration.Enable', 'SelfRegistration.LockOnCreation',
        'Recovery.Notification.Password.Enable', 'Recovery.Question.Password.Enable',
        'Recovery.Notification.Username.Enable', 'Recovery.Notification.InternallyManage')
CERT = Path.home() / 'Library/Application Support/ciam-p118-p119-lab-trust/wso2-issuer-9444.pem'

class Stop(Exception):
    pass

def need(condition, reason):
    if not condition:
        raise Stop(reason)

def classify(value):
    if type(value) is bool: return str(value).lower()
    if type(value) is str and value.strip().lower() in ('true', 'false'):
        return value.strip().lower()
    return 'UNRECOGNIZED'

def collect(data, out):
    if isinstance(data, dict):
        key = data.get('name')
        if key in KEYS and 'value' in data:
            value = classify(data['value'])
            previous = out[key]
            out[key] = value if previous in ('NOT_OBSERVED', value) else 'CONFLICT'
        for value in data.values():
            if isinstance(value, (dict, list)):
                collect(value, out)
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, (dict, list)):
                collect(value, out)

def private_journal(path):
    need(path.is_file() and not path.is_symlink(), 'V10_TENANT_JOURNAL_UNAVAILABLE')
    s = path.stat()
    need(s.st_uid == os.getuid() and stat.S_ISREG(s.st_mode) and
         stat.S_IMODE(s.st_mode) == 0o600 and s.st_size < 262144,
         'V10_TENANT_JOURNAL_UNSAFE')
    data = json.loads(path.read_text('utf-8'))
    need(isinstance(data, dict) and data.get('domains') == BRANDS,
         'V10_TENANT_DOMAIN_DRIFT')
    creds = {}
    for brand, domain in BRANDS.items():
        item = data.get('tenants', {}).get(brand, {})
        owner = item.get('owner', {})
        need(item.get('domain') == domain and item.get('status') == 'readback-verified'
             and owner.get('username') == 'labtenantadmin'
             and isinstance(owner.get('password'), str)
             and len(owner['password']) >= 12,
             'TENANT_OWNER_JOURNAL_NOT_VERIFIED_' + brand.upper())
        creds[brand] = (f'labtenantadmin@{domain}', owner['password'])
    return creds

def tls_context():
    need(CERT.is_file() and not CERT.is_symlink(), 'PINNED_TLS_CERT_UNAVAILABLE')
    text = CERT.read_text('ascii')
    der = ssl.PEM_cert_to_DER_cert(text)
    need(hashlib.sha256(der).hexdigest() == FINGERPRINT,
         'PINNED_TLS_FINGERPRINT_DRIFT')
    context = ssl.create_default_context(cafile=str(CERT))
    need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
         'STRICT_TLS_REQUIRED')
    return context

def get(context, domain, auth_header, category=None):
    path = f'/t/{domain}/api/server/v1/identity-governance/'
    if category is not None:
        need(isinstance(category, str) and
             re.fullmatch(r'[A-Za-z0-9_-]{1,160}={0,2}', category) is not None,
             'GOVERNANCE_CATEGORY_UNSAFE')
        path += category
    conn = http.client.HTTPSConnection('localhost', 9444, context=context, timeout=12)
    try:
        conn.request('GET', path, headers={
            'Accept': 'application/json', 'Authorization': auth_header
        })
        resp = conn.getresponse()
        body = resp.read(262145)
        if resp.status != 200:
            return resp.status, None
        need(len(body) <= 262144, 'GOVERNANCE_RESPONSE_TOO_LARGE')
        data = json.loads(body)
        need(isinstance(data, (dict, list)), 'GOVERNANCE_RESPONSE_UNEXPECTED')
        return 200, data
    finally:
        conn.close()

def read_brand(ctx, brand, creds):
    username, password = creds
    auth = 'Basic ' + base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii')
    status, data = get(ctx, BRANDS[brand], auth)
    result = {'identity': 'EXISTING_VERIFIED_TENANT_OWNER', 'governance_http': status,
              'categories_inspected': 0,
              'settings': {key: 'NOT_OBSERVED' for key in KEYS}}
    if status != 200:
        result['assessment'] = 'GOVERNANCE_READ_UNAVAILABLE_NO_SETTINGS_INFERRED'
        return result
    collect(data, result['settings'])
    if isinstance(data, list):
        categories = data
    else:
        categories = data.get('categories', [])
    need(isinstance(categories, list) and len(categories) <= 30,
         'GOVERNANCE_CATEGORIES_UNEXPECTED')
    for category in categories:
        need(isinstance(category, dict), 'GOVERNANCE_CATEGORY_UNEXPECTED')
        id_ = category.get('id')
        need(isinstance(id_, str) and
             re.fullmatch(r'[A-Za-z0-9_-]{1,160}={0,2}', id_) is not None,
             'GOVERNANCE_CATEGORY_ID_UNEXPECTED')
        code, detail = get(ctx, BRANDS[brand], auth, id_)
        if code == 200:
            result['categories_inspected'] += 1
            collect(detail, result['settings'])
        else:
            result.setdefault('category_http_non_200', []).append(code)
    result['assessment'] = ('TENANT_SETTINGS_READBACK'
                            if any(x != 'NOT_OBSERVED' for x in result['settings'].values())
                            else 'SETTINGS_NOT_EXPOSED_BY_THIS_API')
    return result

def offline_tests():
    values = {key: 'NOT_OBSERVED' for key in KEYS}
    collect({'connectors':[{'properties':[
        {'name':'SelfRegistration.Enable', 'value':'true'},
        {'name':'Recovery.Notification.Password.Enable','value':False},
        {'name':'irrelevant','value':'secret'}]}]}, values)
    assert values['SelfRegistration.Enable'] == 'true'
    assert values['Recovery.Notification.Password.Enable'] == 'false'
    assert values['Recovery.Notification.Username.Enable'] == 'NOT_OBSERVED'
    collect([{'name':'SelfRegistration.Enable','value':'false'}], values)
    assert values['SelfRegistration.Enable'] == 'CONFLICT'
    print('P119_TENANT_OWNER_GOVERNANCE_SELF_TEST_OK')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        offline_tests(); return
    need(args.repo is not None and (args.repo / 'services/identity-bff/src/server.js').is_file(),
         'WRONG_CIAM_REPOSITORY')
    base = Path(os.environ.get('CIAM_V10_HOME', str(Path.home()/'wso2-ciam-v10')))
    need(base.is_dir() and not base.is_symlink(), 'V10_HOME_UNSAFE')
    creds = private_journal(base / 'private/bootstrap-tenants-v10.private.json')
    ctx = tls_context()
    out = {brand: read_brand(ctx, brand, creds[brand]) for brand in BRANDS}
    print(json.dumps({
        'status': 'P119_TENANT_OWNER_GOVERNANCE_READ_ONLY',
        'auth': 'EXISTING_JOURNALED_OWNER_BASIC_GET_ONLY',
        'tls': 'STRICT_PINNED_9444', 'tenants': out,
        'raw_responses_or_credentials_printed': False,
        'account_changes': 0, 'wso2_configuration_writes': 0,
        'database_writes': 0,
    }, indent=2))

if __name__ == '__main__':
    try:
        main()
    except (Stop, OSError, ssl.SSLError, http.client.HTTPException,
            UnicodeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        code = str(exc) if isinstance(exc, Stop) else type(exc).__name__
        print('P119_TENANT_OWNER_GOVERNANCE_STOP: ' + code, file=sys.stderr)
        sys.exit(2)
