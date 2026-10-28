#!/usr/bin/env python3
"""Read-only WSO2 CIAM v10 Aurora Web OIDC audience plan.

No application writes, Docker changes, journals or secret output. Uses existing
repository-owned private journals; only tenant-scoped management view OAuth token
request (POST /oauth2/token) and GET calls are permitted.

The resulting fingerprint is an opaque digest of the full OIDC GET representation;
future apply tools must re-read and compare before making any change. This script
has deliberately NO apply entry point.
"""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import urllib.parse

AUDIENCE = 'https://api.ciam-v10.test/profile'
EXPECTED_HEAD = '04f4751525f02535f4f8b9880b776eb98e2f6f1d'
CONTAINER = 'wso2-ciam-v10-is-1'
IMAGE = 'wso2/wso2is:7.3.0'
DOMAIN = 'aurora.identity.test'
ROOT = Path(__file__).resolve().parents[3]
RESOURCE_SOURCE = ROOT / 'deploy/ciam-v10/resources/bootstrap.py'
AUTH_SOURCE = ROOT / 'deploy/ciam-v10/authority/bootstrap.py'
PIN = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10'))).expanduser() / 'private/wso2-9444-leaf.pem'

class Refuse(Exception):
    pass

def run(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=12)
    if p.returncode:
        raise Refuse('PREFLIGHT_COMMAND_FAILED')
    return p.stdout.strip()

def canonical(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('utf-8')

def digest(o):
    return hashlib.sha256(canonical(o)).hexdigest()

def ensure_target():
    inspect = json.loads(run(['docker', 'inspect', CONTAINER]))
    if not isinstance(inspect, list) or len(inspect) != 1:
        raise Refuse('V10_DOCKER_INSPECT_UNEXPECTED')
    node = inspect[0]
    if (node.get('Name') != '/' + CONTAINER or
        node.get('Config', {}).get('Image') != IMAGE or
        node.get('State', {}).get('Running') is not True):
        raise Refuse('UNEXPECTED_CONTAINER_IDENTITY')
    ports = node.get('NetworkSettings', {}).get('Ports', {}).get('9444/tcp', [])
    if not isinstance(ports, list) or not any(p.get('HostPort') == '9444' and
            p.get('HostIp') in ('127.0.0.1', '0.0.0.0', '::', '') for p in ports if isinstance(p, dict)):
        raise Refuse('CONTAINER_HOST_PORT_9444_NOT_VERIFIED')

def ensure_repo():
    if (not (ROOT / 'scripts/ciam-v10.sh').is_file() or
        not RESOURCE_SOURCE.is_file() or not AUTH_SOURCE.is_file()):
        raise Refuse('NOT_V10_REPO_CHECKOUT')
    if run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']) != EXPECTED_HEAD:
        raise Refuse('HEAD_CHANGED_REVIEW_SOURCE_AGAIN')
    # Unrelated dirty worktree is intentionally allowed and never touched.
    for path in [RESOURCE_SOURCE, AUTH_SOURCE, ROOT / 'deploy/ciam-v10/oidc/bootstrap.py']:
        rel = str(path.relative_to(ROOT))
        p = subprocess.run(['git', '-C', str(ROOT), 'diff', '--quiet', 'HEAD', '--', rel],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
        if p.returncode != 0:
            raise Refuse('AUDIT_DEPENDENCY_LOCALLY_MODIFIED_' + path.name)

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Refuse('REPO_MODULE_LOAD_FAILED')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def https_client_context():
    if PIN.is_symlink() or not PIN.is_file():
        raise Refuse('PINNED_LEAF_CERT_MISSING_OR_SYMLINK')
    st = PIN.stat()
    if st.st_uid != os.getuid() or (st.st_mode & 0o777) != 0o600:
        raise Refuse('PINNED_LEAF_CERT_UNSAFE_PERMISSIONS')
    pem = PIN.read_text(encoding='ascii')
    if len(pem) > 20000 or '-----BEGIN CERTIFICATE-----' not in pem:
        raise Refuse('PINNED_CERT_FORMAT_INVALID')
    ctx = ssl.create_default_context(cadata=pem)
    # WSO2's local certificate is explicitly pinned; never trust arbitrary certs.
    ctx.check_hostname = False
    return ctx

def api_call(ctx, method, path, auth, form=None):
    if method not in ('GET', 'POST') or not path.startswith('/t/' + DOMAIN + '/'):
        raise Refuse('UNSAFE_API_PATH_OR_METHOD')
    if method == 'POST' and (path != '/t/' + DOMAIN + '/oauth2/token' or form is None):
        raise Refuse('ONLY_TOKEN_POST_ALLOWED')
    if method == 'GET' and (form is not None or not re.fullmatch(
            r'/t/aurora\.identity\.test/api/server/v1/applications/[A-Za-z0-9_-]{5,256}(?:/inbound-protocols/oidc|/authorized-apis)?', path)):
        raise Refuse('ONLY_APPLICATION_GET_ALLOWED')
    headers = {'Authorization': auth, 'Accept': 'application/json'}
    body = None
    if form is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        body = urllib.parse.urlencode(form)
    con = http.client.HTTPSConnection('localhost', 9444, context=ctx, timeout=15)
    try:
        con.request(method, path, headers=headers, body=body)
        response = con.getresponse()
        raw = response.read(262145)
        if len(raw) > 262144 or response.status != 200:
            raise Refuse('MANAGEMENT_READ_OR_TOKEN_FAILED_HTTP_' + str(response.status))
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise Refuse('INVALID_MANAGEMENT_RESPONSE') from None
        if not isinstance(obj, dict):
            raise Refuse('MANAGEMENT_RESPONSE_NOT_OBJECT')
        return obj
    finally:
        con.close()

def require(condition, code):
    if not condition:
        raise Refuse(code)

def make_plan(app, oidc, node, app_id, expected_name):
    """Pure; never returns credentials, client ID or raw API representations."""
    require(isinstance(app, dict) and isinstance(oidc, dict), 'APP_SHAPE_INVALID')
    require(app.get('id') == app_id and app.get('name') == expected_name and
            app.get('description') == node.get('description') and
            app.get('isManagementApp') is False, 'APP_IDENTITY_DRIFT')
    require(app.get('associatedRoles', {}).get('allowedAudience') == 'APPLICATION',
            'APP_ROLE_AUDIENCE_DRIFT')
    require(oidc.get('clientId') == node.get('clientId') and bool(oidc.get('clientId')),
            'OIDC_CLIENT_ID_DRIFT')
    require(oidc.get('callbackURLs') == [node.get('callback')] and
            oidc.get('publicClient') is False and
            'authorization_code' in oidc.get('grantTypes', []) and
            oidc.get('pkce', {}).get('mandatory') is True and
            oidc.get('subject', {}).get('subjectType') == 'pairwise' and
            oidc.get('accessToken', {}).get('type') == 'JWT',
            'OIDC_SECURITY_CONTRACT_DRIFT')
    field = oidc.get('idToken')
    require(isinstance(field, dict) and isinstance(field.get('audience'), list),
            'OIDC_AUDIENCE_FIELD_NOT_EXPLICIT_LIST')
    current = field['audience']
    require(all(isinstance(x, str) and x for x in current) and len(set(current)) == len(current),
            'OIDC_AUDIENCES_INVALID')
    require(current == [], 'AUDIENCE_NONEMPTY_REQUIRES_SEPARATE_REVIEW')
    # No raw config, secrets or client identifier are ever returned.
    return {
        'stage': 'CIAM_V10_AURORA_WEB_AUDIENCE_PLAN',
        'mode': 'READ_ONLY_PLAN_NO_APPLY',
        'status': 'VERIFIED_READBACK',
        'applicationIdentity': 'MATCHES_PRIVATE_OIDC_JOURNAL',
        'oidcSecurityConfiguration': 'VERIFIED_UNCHANGED',
        'currentConfiguredCustomAudiences': 0,
        'proposedChange': {'path': '/idToken/audience', 'operation': 'ADD_ONE_TO_EMPTY_ARRAY',
                           'after': [AUDIENCE]},
        'impact': 'ID_TOKEN_AUDIENCE_MAY_ALSO_CHANGE; TEST_BEFORE_FURTHER_CLIENTS',
        'oidcGetFingerprintSha256': digest(oidc),
        'applicationGetFingerprintSha256': digest(app),
        'safeForAutomaticApply': False,
        'requiresExplicitFutureApplyApproval': True,
        'runtimeInMemoryAudienceFlag': 'NOT_VERIFIED',
        'freshTokenAudienceAcceptance': 'BLOCKED',
        'consentV2': 'BLOCKED',
        'managementResourceWrites': 0,
        'dockerOrConfigurationWrites': 0,
        'browserLogins': 0,
    }

def main():
    require(len(sys.argv) == 1, 'THIS_SCRIPT_HAS_NO_APPLY_OR_EXTRA_ARGS')
    ensure_repo()
    ensure_target()
    resources = load_module('ciam_aud_resources_read_only', RESOURCE_SOURCE)
    authority = load_module('ciam_aud_authority_read_only', AUTH_SOURCE)
    tenants, rs, saved = authority.private_context()
    node = saved['tenants']['aurora']['clients']['web']
    require(node.get('state') == 'verified' and node.get('domain') == DOMAIN,
            'AURORA_WEB_JOURNAL_NOT_VERIFIED')
    app_id = node.get('id')
    require(bool(resources.ID.fullmatch(str(app_id))), 'AURORA_APP_ID_INVALID')
    require(node.get('name') == 'Identity Lab v10 Aurora Web', 'APP_NAME_UNEXPECTED')
    m = rs['tenants']['aurora']['management']
    ctx = https_client_context()
    path = '/t/' + DOMAIN + '/api/server/v1/applications/' + app_id
    token_resp = api_call(ctx, 'POST', '/t/' + DOMAIN + '/oauth2/token',
                resources.basic(m['clientId'], m['clientSecret']),
                form={'grant_type': 'client_credentials', 'scope': 'internal_application_mgt_view'})
    require(token_resp.get('token_type', '').lower() == 'bearer' and
            token_resp.get('access_token') and
            'internal_application_mgt_view' in str(token_resp.get('scope', '')).split(),
            'MANAGEMENT_VIEW_SCOPE_NOT_GRANTED')
    bearer = 'Bearer ' + token_resp['access_token']
    app = api_call(ctx, 'GET', path, bearer)
    oidc = api_call(ctx, 'GET', path + '/inbound-protocols/oidc', bearer)
    plan = make_plan(app, oidc, node, app_id, node['name'])
    plan['dockerTarget'] = 'VERIFIED_READBACK_V10_9444_ONLY'
    plan['gitCheckpoint'] = 'VERIFIED_LOCAL_HEAD'
    plan['managementOAuthTokenRequests'] = 1
    plan['managementGetRequests'] = 2
    print(json.dumps(plan, indent=2, sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except (Refuse, OSError, KeyError, TypeError, AttributeError, ValueError,
            ssl.SSLError, http.client.HTTPException, subprocess.TimeoutExpired):
        # Generic error prevents accidental disclosure via server error messages.
        e = sys.exc_info()[1]
        code = str(e) if isinstance(e, Refuse) else type(e).__name__
        print(json.dumps({'stage':'CIAM_V10_AURORA_WEB_AUDIENCE_PLAN',
                          'status':'NOT_VERIFIED', 'reason':code,
                          'managementResourceWrites':0,
                          'dockerOrConfigurationWrites':0}),file=sys.stdout)
        sys.exit(1)
