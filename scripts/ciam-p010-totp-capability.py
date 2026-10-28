#!/usr/bin/env python3
"""P0.10: GET-only WSO2 tenant TOTP capability evidence.

This only establishes that the authenticator is enabled. It deliberately cannot
attest enrollment, policy enforcement, signed AMR/ACR, or a successful OTP.
"""
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOMAINS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}
PATH_NEW = '/t/{domain}/api/server/v1/authenticators'
PATH_OLD = '/t/{domain}/api/server/v1/configs/authenticators?type=LOCAL'

class Refused(Exception):
    pass

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Refused('BOOTSTRAP_MODULE_UNAVAILABLE')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def entries(body):
    if isinstance(body, list):
        rows = body
    elif isinstance(body, dict):
        candidates = [body[k] for k in ('authenticators', 'items') if k in body]
        if len(candidates) != 1 or not isinstance(candidates[0], list):
            raise Refused('AUTHENTICATOR_LIST_SHAPE_UNATTESTED')
        rows = candidates[0]
    else:
        raise Refused('AUTHENTICATOR_LIST_SHAPE_UNATTESTED')
    if len(rows) > 256 or any(not isinstance(x, dict) for x in rows):
        raise Refused('AUTHENTICATOR_LIST_INVALID')
    return rows

def summarize(body):
    rows = entries(body)
    matches = []
    for row in rows:
        name = row.get('name')
        display = row.get('displayName')
        if (isinstance(name, str) and name.lower() in ('totp', 'totpauthenticator')) or (
            isinstance(display, str) and display.lower() in ('totp', 'time-based one-time password')):
            matches.append(row)
    if len(matches) > 1:
        raise Refused('AMBIGUOUS_TOTP_AUTHENTICATOR_LIST')
    if not matches:
        return {'totpAuthenticatorListed': False, 'totpEnabled': False,
                'totpLocal': False, 'identityEnrollmentVerified': False}
    row = matches[0]
    enabled = row.get('isEnabled')
    typ = row.get('type')
    if type(enabled) is not bool or (typ is not None and typ != 'LOCAL'):
        raise Refused('TOTP_ENABLEMENT_OR_TYPE_UNATTESTED')
    return {'totpAuthenticatorListed': True, 'totpEnabled': enabled,
            'totpLocal': typ == 'LOCAL', 'identityEnrollmentVerified': False}

class GetOnly:
    def __init__(self, transport):
        self.transport = transport
        self.requests = 0
    def call(self, method, path, *, auth=None, data=None, form=None):
        allowed = {p.format(domain=d) for d in DOMAINS.values() for p in (PATH_NEW, PATH_OLD)}
        if method != 'GET' or path not in allowed or data is not None or form is not None:
            raise Refused('GET_ONLY_AUTHENTICATOR_PATH_ENFORCED')
        self.requests += 1
        return self.transport.call(method, path, auth=auth)

def probe(client, domain, auth):
    resp = client.call('GET', PATH_NEW.format(domain=domain), auth=auth)
    if not isinstance(resp, (tuple, list)) or len(resp) < 2 or type(resp[0]) is not int:
        raise Refused('AUTHENTICATOR_RESPONSE_INVALID')
    endpoint = 'authenticators'
    # WSO2 installations may expose either API; fallback only for unsupported paths.
    if resp[0] in (404, 501):
        resp = client.call('GET', PATH_OLD.format(domain=domain), auth=auth)
        endpoint = 'configs/authenticators'
    if resp[0] in (401, 403):
        raise Refused('AUTHENTICATOR_READ_PERMISSION_REQUIRED_' + domain)
    if resp[0] != 200:
        raise Refused('AUTHENTICATOR_GET_UNAVAILABLE_' + domain + '_' + str(resp[0]))
    return {**summarize(resp[1]), 'readbackEndpoint': endpoint}

def audit(client, tenant, *, basic, owner):
    if not isinstance(tenant, dict) or tenant.get('domains') != DOMAINS or not isinstance(tenant.get('tenants'), dict):
        raise Refused('TENANT_JOURNAL_CONTEXT_DRIFT')
    results = {}
    for brand, domain in DOMAINS.items():
        row = tenant['tenants'].get(brand, {})
        user = row.get('owner', {})
        if row.get('domain') != domain or user.get('username') != owner:
            raise Refused('TENANT_OWNER_CONTEXT_DRIFT_' + brand)
        auth = basic(owner + '@' + domain, user.get('password'))
        results[brand] = probe(client, domain, auth)
    aurora = results['aurora']
    if aurora['totpAuthenticatorListed'] and aurora['totpEnabled'] and aurora['totpLocal']:
        status = 'AURORA_TOTP_AUTHENTICATOR_AVAILABLE_POLICY_AND_ENROLLMENT_PENDING'
    else:
        status = 'AURORA_TOTP_CAPABILITY_NOT_READY'
    return {'stage': 'P010_WSO2_TOTP_CAPABILITY_GET_ONLY_V3', 'mode': 'GET_ONLY',
            'remoteWrites': 0, 'getRequests': client.requests,
            'status': status, 'tenants': results,
            'assertionsNotMade': ['TOTP_ENROLLMENT', 'ACTUAL_TOTP_CHALLENGE',
               'CONDITIONAL_AUTHENTICATION_POLICY', 'SIGNED_ACR_AMR_AUTH_TIME',
               'SUCCESSFUL_APPROVAL'],
            'nextGate': 'SEPARATE_OPERATOR_APPROVAL_FOR_AURORA_WEB_AND_APP_AUTHENTICATION_POLICY'}

def main():
    if not (REPO / '.git').exists():
        raise Refused('NOT_IN_CIAM_GIT_CHECKOUT')
    oidc = load('ciam_p010_oidc_probe', REPO / 'deploy/ciam-v10/oidc/bootstrap.py')
    resources = load('ciam_p010_resources_probe', REPO / 'deploy/ciam-v10/resources/bootstrap.py')
    ts = oidc.read_private(oidc.TENANTS)
    if ts.get('schema') != 'identity.wso2.ciam.v10.tenants' or ts.get('base') != oidc.BASE:
        raise Refused('TENANT_JOURNAL_SCHEMA_DRIFT')
    client = GetOnly(oidc.HTTPS())
    result = audit(client, ts, basic=resources.basic, owner=resources.OWNER)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'].startswith('AURORA_TOTP_AUTHENTICATOR_AVAILABLE') else 2

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Refused, KeyError, TypeError, ValueError, OSError) as error:
        # No raw upstream body, URL, credentials, session or token in errors.
        print('REFUSED:', str(error) if isinstance(error, Refused) else type(error).__name__, file=sys.stderr)
        sys.exit(2)
