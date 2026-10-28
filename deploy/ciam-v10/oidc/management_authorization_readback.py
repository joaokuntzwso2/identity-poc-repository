#!/usr/bin/env python3
"""Read-only WSO2 CIAM v10 Aurora management-app API authorization audit.

Uses the already-pinned local audience_plan.py and repository-owned 0600
journals. Network calls: one tenant-scoped OAuth token POST for VIEW and
exactly two tenant-scoped management GETs. No management mutations.

Never prints client IDs, secrets, tokens, raw JSON, application IDs, or URLs.
"""
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import re
import ssl
import sys

DOMAIN = 'aurora.identity.test'
APP_API = '/api/server/v1/applications'
APP_NAME = 'Identity Lab AURORA Management Bootstrap'
UPDATE = 'internal_application_mgt_update'
KNOWN_SCOPES = frozenset({
    'internal_application_mgt_view',
    'internal_application_mgt_create',
    'internal_application_mgt_client_secret_view',
    UPDATE,
})
EXPECTED_PLAN_SHA256 = '104702e05bd926d730227fdc0b2bfd432c640d3ef54cba7d0bc22741c3301a94'
PLAN_FILE = Path(__file__).resolve().parent / 'audience_plan.py'
MAX_BYTES = 262144

class Refuse(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Refuse(reason)

def load_plan():
    require(PLAN_FILE.is_file() and not PLAN_FILE.is_symlink(), 'PINNED_PLAN_MISSING')
    require(hashlib.sha256(PLAN_FILE.read_bytes()).hexdigest() == EXPECTED_PLAN_SHA256,
            'PINNED_PLAN_CHECKSUM_CHANGED')
    spec = importlib.util.spec_from_file_location('ciam_v10_management_auth_readback_base', PLAN_FILE)
    require(spec is not None and spec.loader is not None, 'PLAN_IMPORT_UNAVAILABLE')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def unwrap_authorizations(value):
    """WSO2 deployment schemas may return an array or a known wrapper.

    Fail closed on unknown wrapper or inconsistent duplicate keys.
    """
    if isinstance(value, list):
        arr = value
    elif isinstance(value, dict):
        names = [name for name in ('authorizedAPIs', 'authorizedApis', 'apis', 'resources') if name in value]
        require(len(names) == 1, 'AUTHORIZED_APIS_UNRECOGNIZED_OR_AMBIGUOUS_WRAPPER')
        arr = value[names[0]]
    else:
        raise Refuse('AUTHORIZED_APIS_INVALID_SHAPE')
    require(isinstance(arr, list) and len(arr) <= 200, 'AUTHORIZED_APIS_INVALID_LIST')
    require(all(isinstance(x, dict) for x in arr), 'AUTHORIZED_APIS_NON_OBJECT_ITEM')
    return arr

def parse_scope_names(value):
    require(isinstance(value, list) and len(value) <= 100, 'AUTHORIZED_SCOPE_LIST_INVALID')
    names = []
    for obj in value:
        if isinstance(obj, dict):
            name = obj.get('name')
        elif isinstance(obj, str):
            name = obj
        else:
            raise Refuse('AUTHORIZED_SCOPE_ENTRY_INVALID')
        require(isinstance(name, str) and 0 < len(name) <= 256,
                'AUTHORIZED_SCOPE_NAME_INVALID')
        names.append(name)
    require(len(names) == len(set(names)), 'AUTHORIZED_SCOPE_DUPLICATE')
    return set(names)

def classify_authorization(data, journal_resource_id):
    require(isinstance(journal_resource_id, str) and journal_resource_id,
            'JOURNALED_APP_API_ID_MISSING')
    apps = unwrap_authorizations(data)
    matched = [app for app in apps if app.get('id') == journal_resource_id]
    require(len(matched) == 1, 'JOURNALED_APP_API_AUTH_MISSING_OR_DUPLICATE')
    match = matched[0]
    if 'identifier' in match:
        require(match['identifier'] == APP_API, 'APP_RESOURCE_IDENTIFIER_CHANGED')
    policy = match.get('policyId', match.get('policyIdentifier'))
    require(policy in (None, 'RBAC'), 'APPLICATION_API_POLICY_UNEXPECTED')
    names = parse_scope_names(match.get('authorizedScopes'))
    known_granted = sorted(names & KNOWN_SCOPES)
    if UPDATE in names:
        condition = 'UPDATE_AUTHORIZED_ON_MANAGEMENT_APP_BUT_TOKEN_NOT_GRANTED'
        next_action = 'INVESTIGATE_TOKEN_AUTHORIZATION_CONTRACT_NO_WRITES'
    else:
        condition = 'UPDATE_NOT_AUTHORIZED_ON_EXISTING_MANAGEMENT_APP'
        next_action = 'PREPARE_SEPARATE_GUARDED_SCOPE_ADD_PLAN_NO_AUTO_GRANT'
    return {
        'managementApplication': 'MATCHES_PRIVATE_RESOURCE_JOURNAL',
        'applicationApiResource': 'MATCHES_PRIVATE_RESOURCE_JOURNAL',
        'authorizationPolicy': 'RBAC' if policy == 'RBAC' else 'NOT_EXPOSED',
        'authorizedRelevantScopes': known_granted,
        'otherAuthorizedScopeCount': len(names - KNOWN_SCOPES),
        'updateScopeAuthorized': UPDATE in names,
        'condition': condition,
        'nextAction': next_action,
    }

def only_get(ctx, path, bearer, expected_root):
    require(path in (expected_root, expected_root + '/authorized-apis'), 'UNAPPROVED_GET_PATH')
    require(re.fullmatch(r'/t/aurora\.identity\.test/api/server/v1/applications/[A-Za-z0-9_-]{5,256}={0,2}', expected_root) is not None,
            'INVALID_JOURNALED_MANAGEMENT_APP_PATH')
    conn = http.client.HTTPSConnection('localhost', 9444, context=ctx, timeout=15)
    try:
        conn.request('GET', path, headers={'Authorization': bearer, 'Accept': 'application/json'})
        response = conn.getresponse()
        body = response.read(MAX_BYTES + 1)
        require(response.status == 200, f'MANAGEMENT_GET_HTTP_{response.status}')
        require(len(body) <= MAX_BYTES, 'MANAGEMENT_RESPONSE_TOO_LARGE')
        try:
            return json.loads(body)
        except (ValueError, UnicodeError):
            raise Refuse('MANAGEMENT_JSON_INVALID') from None
    finally:
        conn.close()

def main():
    require(len(sys.argv) == 1, 'NO_ARGUMENTS_SUPPORTED')
    plan = load_plan()
    plan.ensure_repo()
    plan.ensure_target()
    resources = plan.load_module('v10_management_auth_resources', plan.RESOURCE_SOURCE)
    authority = plan.load_module('v10_management_auth_authority', plan.AUTH_SOURCE)
    _, rs, saved = authority.private_context()
    app = saved['tenants']['aurora']['clients']['web']
    require(app.get('state') == 'verified' and app.get('domain') == DOMAIN and
            app.get('name') == 'Identity Lab v10 Aurora Web', 'AURORA_WEB_JOURNAL_UNEXPECTED')
    management = rs['tenants']['aurora']['management']
    management_id = management.get('id')
    require(management.get('state') == 'verified' and
            management.get('domain') == DOMAIN and
            management.get('name') == APP_NAME and
            isinstance(management_id, str) and
            resources.ID.fullmatch(management_id) is not None,
            'MANAGEMENT_JOURNAL_IDENTITY_UNEXPECTED')
    auth_record = management.get('authorized')
    require(isinstance(auth_record, dict), 'MANAGEMENT_JOURNAL_AUTH_UNAVAILABLE')
    resource_id = auth_record.get(APP_API)
    require(isinstance(resource_id, str) and resources.ID.fullmatch(resource_id) is not None,
            'APP_API_RESOURCE_JOURNAL_ID_UNAVAILABLE')
    require(set(resources.APP_SCOPES) == {
        'internal_application_mgt_view',
        'internal_application_mgt_create',
        'internal_application_mgt_client_secret_view',
    }, 'BOOTSTRAP_SOURCE_SCOPE_CONTRACT_CHANGED')
    tls = plan.https_client_context()
    token = plan.api_call(tls, 'POST', f'/t/{DOMAIN}/oauth2/token',
                          resources.basic(management['clientId'], management['clientSecret']),
                          form={'grant_type': 'client_credentials',
                                'scope': 'internal_application_mgt_view'})
    require(isinstance(token.get('access_token'), str) and token['access_token'] and
            token.get('token_type', '').lower() == 'bearer' and
            'internal_application_mgt_view' in str(token.get('scope', '')).split(),
            'VIEW_SCOPE_TOKEN_NOT_GRANTED')
    bearer = 'Bearer ' + token['access_token']
    root = f'/t/{DOMAIN}/api/server/v1/applications/{management_id}'
    remote_app = only_get(tls, root, bearer, root)
    require(isinstance(remote_app, dict) and remote_app.get('id') == management_id and
            remote_app.get('name') == APP_NAME and remote_app.get('isManagementApp') is True,
            'REMOTE_MANAGEMENT_APPLICATION_IDENTITY_MISMATCH')
    remote_auth = only_get(tls, root + '/authorized-apis', bearer, root)
    result = classify_authorization(remote_auth, resource_id)
    result.update({
        'stage': 'CIAM_V10_AURORA_MANAGEMENT_API_AUTHORIZATION_READBACK',
        'status': 'VERIFIED_READBACK',
        'dockerTarget': 'VERIFIED_V10_9444_ONLY',
        'tenant': DOMAIN,
        'managementOAuthTokenRequests': 1,
        'managementGetRequests': 2,
        'managementResourceWrites': 0,
        'dockerOrConfigurationWrites': 0,
        'privateJournalWrites': 0,
        'browserLogins': 0,
        'freshTokenAudienceAcceptance': 'BLOCKED',
        'consentV2': 'BLOCKED',
    })
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except (Refuse, OSError, ValueError, KeyError, TypeError, AttributeError,
            ssl.SSLError, http.client.HTTPException) as err:
        code = str(err) if isinstance(err, Refuse) else type(err).__name__
        print(json.dumps({'stage': 'CIAM_V10_AURORA_MANAGEMENT_API_AUTHORIZATION_READBACK',
                          'status': 'NOT_VERIFIED', 'reason': code,
                          'managementResourceWrites': 0,
                          'dockerOrConfigurationWrites': 0,
                          'nextAction': 'STOP_NO_APPLICATION_OR_AUTHORIZATION_CHANGES'},
                         sort_keys=True, indent=2))
        sys.exit(1)
