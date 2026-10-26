#!/usr/bin/env python3
"""Read-only, secret-free WSO2 v10 business-authz and consent capability audit."""
import base64
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import urllib.parse

ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10')))
DOMAINS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}

def private_json(filename):
    p = ROOT / 'private' / filename
    if p.is_symlink() or not p.is_file(): raise RuntimeError('UNSAFE_PRIVATE_SOURCE')
    s = p.stat()
    if s.st_uid != os.getuid() or not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) != 0o600:
        raise RuntimeError('UNSAFE_PRIVATE_PERMISSIONS')
    return json.loads(p.read_text())

def safe_report(client=None):
    state = private_json('bootstrap-tenants-v10.private.json')
    if state.get('base') != 'https://localhost:9444' or state.get('domains') != DOMAINS:
        raise RuntimeError('TENANT_CONTEXT_MISMATCH')
    if client is None:
        cert = ssl.get_server_certificate(('localhost', 9444))
        tls = ssl.create_default_context(cadata=cert)
        tls.check_hostname = False
        def client(path, user, password):
            conn = http.client.HTTPSConnection('localhost', 9444, context=tls, timeout=10)
            auth = 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()
            try:
                conn.request('GET', path, headers={'Authorization': auth, 'Accept': 'application/json'})
                r = conn.getresponse()
                r.read(65537)
                return r.status
            finally:
                conn.close()
    report = {'stage':'CIAM_V10_AUTHORITY_CAPABILITY_GET_ONLY', 'server':'https://localhost:9444',
              'methods':['GET'], 'remoteWrites':0, 'tenantStates':{}}
    for brand, domain in DOMAINS.items():
        t = state.get('tenants', {}).get(brand, {})
        owner=t.get('owner', {})
        if t.get('domain')!=domain or t.get('status')!='readback-verified' or owner.get('username')!='labtenantadmin' or not owner.get('password'):
            raise RuntimeError('TENANT_JOURNAL_NOT_VERIFIED_'+brand)
        user='labtenantadmin@'+domain
        paths = {
          'apiResourceCatalog':f'/t/{domain}/api/server/v1/api-resources?limit=1',
          'rolesV3':f'/t/{domain}/scim2/v3/Roles?count=1&startIndex=1',
          'consentV2PurposeList':f'/t/{domain}/api/identity/consent-mgt/v2.0/purposes?limit=1',
        }
        report['tenantStates'][brand] = {name: client(path, user, owner['password']) for name,path in paths.items()}
    report['authorizationBootstrap'] = 'NOT_YET_PROVISIONED'
    report['consentV2Contract'] = 'NOT_VERIFIED_LIVE'
    return report

if __name__=='__main__':
    try: print(json.dumps(safe_report(),indent=2))
    except Exception as e: print(json.dumps({'stage':'CIAM_V10_AUTHORITY_CAPABILITY_GET_ONLY', 'result':'FAILED_CLOSED','errorType':type(e).__name__}))
