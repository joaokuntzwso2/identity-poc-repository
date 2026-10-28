#!/usr/bin/env python3
"""WSO2 CIAM v10: read-only v4 scope-add plan bound to live evidence; no grant or apply.

No PATCH/PUT/POST to management resources. Exactly one tenant OAuth token POST
(requesting VIEW only) and two tenant application-management GETs.

Requires the existing repository-managed private journals and pinned, unmodified
reader sources. This does NOT authorize a permission change or perform one.
"""
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import sys

DOMAIN = 'aurora.identity.test'
APP_NAME = 'Identity Lab AURORA Management Bootstrap'
APP_API = '/api/server/v1/applications'
NEW_SCOPE = 'internal_application_mgt_update'
EXPECTED_APP_SHA = '2b0121de738802c643d30f84d3b123a2f3b4e22b8874a34950a5fc148a22f756'
EXPECTED_AUTH_LIST_SHA = '69ed9885664735f171c4d2327987fde5f7b2fd8e277ff025e6686aac92bb756f'
EXPECTED_TARGET_AUTH_SHA = 'd7c89a7cbc4f1bb85b9404a83d5610121147b0c8da0108d47b320cdb91d69972'
REQUIRED_BEFORE = frozenset({
    'internal_application_mgt_view',
    'internal_application_mgt_create',
    'internal_application_mgt_client_secret_view',
})
# Pinned to the two exact companion scripts previously delivered and audited.
READER_SHA = 'df21470c6c542537f364708d075cd7a11a14118712afaa70f4f1a8a6fac463bc'
PLAN_SHA = '104702e05bd926d730227fdc0b2bfd432c640d3ef54cba7d0bc22741c3301a94'
BASE = Path(__file__).resolve().parent

class Refuse(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Refuse(reason)

def safe_import(path, digest, name):
    require(path.is_file() and not path.is_symlink(), 'PINNED_DEPENDENCY_MISSING_OR_LINK')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
            'PINNED_DEPENDENCY_CHANGED')
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, 'DEPENDENCY_IMPORT_FAILED')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def evaluate(reader, remote_app, api_authorizations, management, expected_resource_id):
    """Pure function. Reports only bounded type metadata, never raw responses or IDs."""
    require(isinstance(remote_app, dict) and remote_app.get('id') == management['id'] and
            remote_app.get('name') == APP_NAME and remote_app.get('isManagementApp') is True,
            'MANAGEMENT_APP_IDENTITY_DRIFT')
    require(management.get('name') == APP_NAME and
            management.get('domain') == DOMAIN and management.get('state') == 'verified',
            'JOURNALED_MANAGEMENT_APP_DRIFT')
    entries = reader.unwrap_authorizations(api_authorizations)
    require(len(entries) <= 50, 'TOO_MANY_AUTHORIZED_APIS')
    matches = [a for a in entries if a.get('id') == expected_resource_id]
    require(len(matches) == 1, 'JOURNALED_API_RESOURCE_MISSING_OR_DUPLICATED')
    auth = matches[0]
    require(auth.get('identifier') == APP_API, 'APPLICATION_API_RESOURCE_DRIFT')
    require(auth.get('policyId', auth.get('policyIdentifier')) == 'RBAC',
            'APPLICATION_API_RBAC_POLICY_DRIFT')
    # The exact Authorized APIs GET entry was observed as TENANT in live v3.
    # This is NOT equated to the distinct API Resource Management type SYSTEM.
    # Require exact journaled ID, API path, policy, baseline AND this observed value.
    require(auth.get('type') == 'TENANT', 'AUTHORIZED_API_TYPE_NOT_OBSERVED_TENANT')
    names = frozenset(reader.parse_scope_names(auth.get('authorizedScopes')))
    require(names == REQUIRED_BEFORE, 'AUTHORIZED_SCOPES_NOT_EXACT_BASELINE')
    require(NEW_SCOPE not in names, 'UPDATE_SCOPE_ALREADY_AUTHORIZED')
    canonical = lambda obj: json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    app_sha = hashlib.sha256(canonical(remote_app)).hexdigest()
    list_sha = hashlib.sha256(canonical(api_authorizations)).hexdigest()
    target_sha = hashlib.sha256(canonical(auth)).hexdigest()
    require(app_sha == EXPECTED_APP_SHA, 'APP_FINGERPRINT_CHANGED_SINCE_V3')
    require(list_sha == EXPECTED_AUTH_LIST_SHA, 'API_LIST_FINGERPRINT_CHANGED_SINCE_V3')
    require(target_sha == EXPECTED_TARGET_AUTH_SHA, 'TARGET_API_FINGERPRINT_CHANGED_SINCE_V3')
    return {
        'stage': 'CIAM_V10_AURORA_MANAGEMENT_SCOPE_ADD_PLAN_V4',
        'status': 'VERIFIED_READBACK',
        'mode': 'READ_ONLY_PLAN_NO_APPLY',
        'tenant': DOMAIN,
        'managementApplication': 'MATCHES_PRIVATE_RESOURCE_JOURNAL',
        'authorizedApi': 'APPLICATION_MANAGEMENT_MATCHES_PRIVATE_RESOURCE_JOURNAL',
        'authorizationPolicy': 'RBAC',
        'observedAuthorizedApiType': 'TENANT',
        'typeEvidence': 'EXACT_LIVE_AUTHORIZED_API_VALUE_NOT_RESOURCE_TYPE_EQUIVALENCE',
        'existingAuthorizedScopes': sorted(names),
        'updateScopeAuthorized': False,
        'proposedOperation': 'PATCH_AUTHORIZED_API_SCOPES',
        'proposedPatch': {'addedScopes': [NEW_SCOPE], 'removedScopes': []},
        'proposedTarget': 'EXACT_JOURNALED_MANAGEMENT_APP_AND_API_IDS',
        'expectedPreviousAuthorizedScopeCount': len(names),
        'expectedNextAuthorizedScopeCount': len(names) + 1,
        'applicationReadbackSha256': app_sha,
        'authorizedApiReadbackSha256': list_sha,
        'targetApiAuthorizationSha256': target_sha,
        'adminSideRequiredPermissionsToVerify': [
            'internal_application_mgt_update',
            'internal_application_internal_api_update',
        ],
        'adminAuthorizationVerified': False,
        'requiresExplicitSeparateAdminApproval': True,
        'safeForAutomaticApply': False,
        'mutationImplementedHere': False,
        'nextAction': 'ADMIN_AUTHORIZATION_PREFLIGHT_THEN_SEPARATE_CONFIRMED_PATCH',
        'managementResourceWrites': 0,
        'dockerOrConfigurationWrites': 0,
        'privateJournalWrites': 0,
        'browserLogins': 0,
        'freshTokenAudienceAcceptance': 'BLOCKED',
        'consentV2': 'BLOCKED',
    }

def main():
    require(len(sys.argv) == 1, 'NO_APPLY_ARGUMENTS_SUPPORTED')
    reader = safe_import(BASE / 'management_authorization_readback.py', READER_SHA,
                         'ciam_v10_pinned_management_readback')
    plan = safe_import(BASE / 'audience_plan.py', PLAN_SHA,
                       'ciam_v10_pinned_audience_plan')
    plan.ensure_repo()
    plan.ensure_target()
    resources = plan.load_module('ciam_v10_plan_resources', plan.RESOURCE_SOURCE)
    authority = plan.load_module('ciam_v10_plan_authority', plan.AUTH_SOURCE)
    _, rs, saved = authority.private_context()
    management = rs['tenants']['aurora']['management']
    require(management.get('state') == 'verified' and
            management.get('name') == APP_NAME and management.get('domain') == DOMAIN and
            isinstance(management.get('clientId'), str) and management['clientId'] and
            isinstance(management.get('clientSecret'), str) and management['clientSecret'],
            'MANAGEMENT_JOURNAL_IDENTITY_UNEXPECTED')
    app_node = saved['tenants']['aurora']['clients']['web']
    require(app_node.get('state') == 'verified' and
            app_node.get('name') == 'Identity Lab v10 Aurora Web' and
            app_node.get('domain') == DOMAIN, 'AURORA_WEB_IDENTITY_DRIFT')
    app_id = management.get('id')
    require(isinstance(app_id, str) and resources.ID.fullmatch(app_id) is not None,
            'JOURNALED_MANAGEMENT_APP_ID_INVALID')
    record = management.get('authorized')
    require(isinstance(record, dict), 'JOURNALED_AUTH_RECORD_MISSING')
    resource_id = record.get(APP_API)
    require(isinstance(resource_id, str) and resources.ID.fullmatch(resource_id) is not None,
            'JOURNALED_RESOURCE_ID_INVALID')
    require(set(resources.APP_SCOPES) == REQUIRED_BEFORE, 'BOOTSTRAP_SCOPE_CONTRACT_CHANGED')
    ctx = plan.https_client_context()
    token = plan.api_call(
        ctx, 'POST', '/t/' + DOMAIN + '/oauth2/token',
        resources.basic(management['clientId'], management['clientSecret']),
        form={'grant_type': 'client_credentials', 'scope': 'internal_application_mgt_view'})
    require(isinstance(token.get('access_token'), str) and token['access_token'] and
            token.get('token_type', '').lower() == 'bearer' and
            'internal_application_mgt_view' in str(token.get('scope', '')).split(),
            'READ_ONLY_MANAGEMENT_TOKEN_NOT_GRANTED')
    bearer = 'Bearer ' + token['access_token']
    root = '/t/' + DOMAIN + '/api/server/v1/applications/' + app_id
    app = reader.only_get(ctx, root, bearer, root)
    authorizations = reader.only_get(ctx, root + '/authorized-apis', bearer, root)
    output = evaluate(reader, app, authorizations, management, resource_id)
    output.update({
        'dockerTarget': 'VERIFIED_V10_9444_ONLY',
        'gitCheckpoint': 'VERIFIED_LOCAL_HEAD',
        'managementOAuthTokenRequests': 1,
        'managementGetRequests': 2,
    })
    print(json.dumps(output, indent=2, sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        # Deliberately never print server responses, paths, identities, tokens or secrets.
        code = str(err) if isinstance(err, Refuse) else type(err).__name__
        print(json.dumps({
            'stage': 'CIAM_V10_AURORA_MANAGEMENT_SCOPE_ADD_PLAN_V4',
            'status': 'NOT_VERIFIED',
            'reason': code,
            'nextAction': 'STOP_NO_GRANTS_NO_WRITES',
            'managementResourceWrites': 0,
            'dockerOrConfigurationWrites': 0,
        }, indent=2, sort_keys=True))
        sys.exit(1)
