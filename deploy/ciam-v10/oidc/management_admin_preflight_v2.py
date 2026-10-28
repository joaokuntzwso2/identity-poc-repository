#!/usr/bin/env python3
"""Read-only admin authorization preflight for Aurora v10 management-scope change.

Requires a SEPARATE EXISTING tenant client, via private owner-only JSON under
~/wso2-ciam-v10/private/. No admin client creation, new secrets, application
resource writes, role changes, or server mutation. Never print secrets or IDs.

Network: one OAuth client_credentials token POST; two application GETs.
The OAuth response is trusted to report granted scope names; a read-only GET
is additionally required. This DOES NOT prove that a PATCH would succeed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

TENANT = 'aurora.identity.test'
APP_NAME = 'Identity Lab AURORA Management Bootstrap'
API_ID = '/api/server/v1/applications'
REQUIRED_SCOPES = frozenset({
    'internal_application_mgt_view',
    'internal_application_mgt_update',
    'internal_application_internal_api_update',
})
BASE = Path(__file__).resolve().parent
V4_SHA = 'f5cbc2430a1e8a8dd2edcb895846060962d5f5e3db45162d7d5fe5378da9524a'
STAGE = 'CIAM_V10_AURORA_MANAGEMENT_ADMIN_PREFLIGHT_V2'

class Refuse(Exception):
    def __init__(self, reason, missing=()):
        super().__init__(reason)
        self.reason = reason
        self.missing = tuple(missing)


def require(ok, reason):
    if not ok:
        raise Refuse(reason)


def import_v4():
    path = BASE / 'management_scope_add_plan_v4.py'
    require(path.is_file() and not path.is_symlink(), 'PINNED_V4_PLAN_MISSING')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == V4_SHA,
            'PINNED_V4_PLAN_CHANGED')
    spec = importlib.util.spec_from_file_location('ciam_v10_scope_plan_v4_pinned_admin', path)
    require(spec is not None and spec.loader is not None, 'PINNED_V4_IMPORT_FAILED')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_owner_only_file(p):
    st = p.lstat()
    return (stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 4096
            and st.st_size > 0)


def read_existing_admin_credentials(path):
    """Only accept a pre-existing, private file. Do not create or overwrite it."""
    supplied = Path(path).expanduser()
    raw = supplied.absolute()
    private = (Path.home() / 'wso2-ciam-v10' / 'private').absolute()
    # Do not accept relative escapes, even if the final target resolves inside.
    require('..' not in supplied.parts, 'ADMIN_FILE_PATH_NOT_CANONICAL')
    require(raw != private and raw.is_relative_to(private), 'ADMIN_FILE_OUTSIDE_PRIVATE_HOME')
    # macOS may transparently alias /var/... to /private/var/.... Compare
    # canonical targets on BOTH sides, never a canonical path to its alias.
    # Symlinks below the private root remain forbidden by the lstat checks.
    try:
        canonical_private = private.resolve(strict=True)
        canonical_raw = raw.resolve(strict=True)
        require(canonical_raw != canonical_private and
                canonical_raw.is_relative_to(canonical_private),
                'ADMIN_FILE_PATH_NOT_CANONICAL')
    except (OSError, RuntimeError):
        raise Refuse('ADMIN_FILE_PATH_UNAVAILABLE') from None
    # Refuse a redirected wso2-ciam-v10 directory, but allow trusted OS
    # path aliases *above* the home directory (e.g. macOS /var).
    require(private.parent.is_dir() and not private.parent.is_symlink(),
            'PRIVATE_BASE_UNSAFE')
    require(private.is_dir() and not private.is_symlink(), 'PRIVATE_HOME_UNAVAILABLE')
    dstat = private.stat()
    require(dstat.st_uid == os.getuid() and
            (stat.S_IMODE(dstat.st_mode) & 0o077) == 0,
            'PRIVATE_HOME_PERMISSIONS_UNSAFE')
    cursor = raw.parent
    while cursor != private:
        require(cursor.is_dir() and not cursor.is_symlink(), 'ADMIN_PARENT_DIR_UNSAFE')
        st = cursor.stat()
        require(st.st_uid == os.getuid() and
                (stat.S_IMODE(st.st_mode) & 0o077) == 0,
                'ADMIN_PARENT_DIR_PERMISSIONS_UNSAFE')
        cursor = cursor.parent
    require(raw.is_file() and not raw.is_symlink() and is_owner_only_file(raw),
            'ADMIN_FILE_UNSAFE_OR_MISSING')
    try:
        data = json.loads(raw.read_text(encoding='utf-8'))
    except (ValueError, UnicodeError, OSError):
        raise Refuse('ADMIN_FILE_INVALID_JSON') from None
    require(isinstance(data, dict) and set(data) == {'tenant', 'clientId', 'clientSecret'},
            'ADMIN_FILE_SCHEMA_UNEXPECTED')
    require(data['tenant'] == TENANT, 'ADMIN_TENANT_UNEXPECTED')
    for key in ('clientId', 'clientSecret'):
        value = data[key]
        require(isinstance(value, str) and 5 <= len(value) <= 1024 and
                value == value.strip() and not any(ord(c) < 32 for c in value),
                'ADMIN_CREDENTIAL_FORMAT_UNEXPECTED')
    return data


def validate_token_response(response):
    require(isinstance(response, dict) and
            isinstance(response.get('access_token'), str) and
            bool(response['access_token']) and
            response.get('token_type', '').lower() == 'bearer',
            'ADMIN_TOKEN_RESPONSE_UNUSABLE')
    granted_str = response.get('scope')
    require(isinstance(granted_str, str), 'ADMIN_TOKEN_SCOPE_NOT_STRING')
    names = granted_str.split()
    require(len(names) == len(set(names)) and all(len(n) <= 256 for n in names),
            'ADMIN_GRANTED_SCOPE_FORMAT_UNEXPECTED')
    granted = frozenset(names)
    missing = sorted(REQUIRED_SCOPES - granted)
    if missing:
        raise Refuse('ADMIN_REQUIRED_SCOPES_NOT_GRANTED', missing)
    return response['access_token'], sorted(REQUIRED_SCOPES)


def evaluate(v4, reader, remote_app, auth_list, management, resource_id):
    # Reuse v4's pinned identity checks, exact 3-scope baseline and 3 SHA digests.
    result = v4.evaluate(reader, remote_app, auth_list, management, resource_id)
    require(result['status'] == 'VERIFIED_READBACK' and
            result['proposedPatch'] == {
                'addedScopes': ['internal_application_mgt_update'],
                'removedScopes': [],
            }, 'UNEXPECTED_SCOPE_PLAN')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only preflight: existing separate WSO2 admin M2M client')
    parser.add_argument('--credentials-file', required=True, type=Path,
                        help='Existing mode-0600 JSON under ~/wso2-ciam-v10/private (never printed)')
    args = parser.parse_args(argv)
    v4 = import_v4()
    reader = v4.safe_import(v4.BASE / 'management_authorization_readback.py',
                            v4.READER_SHA, 'ciam_admin_pinned_reader')
    plan = v4.safe_import(v4.BASE / 'audience_plan.py',
                          v4.PLAN_SHA, 'ciam_admin_pinned_plan')
    plan.ensure_repo()
    plan.ensure_target()
    creds = read_existing_admin_credentials(args.credentials_file)
    resources = plan.load_module('ciam_admin_existing_resources', plan.RESOURCE_SOURCE)
    authority = plan.load_module('ciam_admin_existing_authority', plan.AUTH_SOURCE)
    _, rs, saved = authority.private_context()
    management = rs['tenants']['aurora']['management']
    require(management.get('state') == 'verified' and
            management.get('domain') == TENANT and management.get('name') == APP_NAME,
            'MANAGEMENT_JOURNAL_UNEXPECTED')
    require(creds['clientId'] != management.get('clientId'),
            'SELF_ELEVATION_NOT_PERMITTED')
    require(creds['clientId'] != saved['tenants']['aurora']['clients']['web'].get('clientId'),
            'AURORA_WEB_NOT_AN_ADMIN_CLIENT')
    mgmt_id = management.get('id')
    resource_id = management.get('authorized', {}).get(API_ID)
    require(isinstance(mgmt_id, str) and resources.ID.fullmatch(mgmt_id) is not None and
            isinstance(resource_id, str) and resources.ID.fullmatch(resource_id) is not None,
            'JOURNAL_IDS_UNEXPECTED')
    require(set(resources.APP_SCOPES) == v4.REQUIRED_BEFORE,
            'BOOTSTRAP_SCOPE_CONTRACT_CHANGED')
    ctx = plan.https_client_context()
    token_data = plan.api_call(
        ctx, 'POST', '/t/' + TENANT + '/oauth2/token',
        resources.basic(creds['clientId'], creds['clientSecret']),
        form={'grant_type': 'client_credentials', 'scope': ' '.join(sorted(REQUIRED_SCOPES))})
    token, granted = validate_token_response(token_data)
    root = '/t/' + TENANT + '/api/server/v1/applications/' + mgmt_id
    app = reader.only_get(ctx, root, 'Bearer ' + token, root)
    auth_list = reader.only_get(ctx, root + '/authorized-apis', 'Bearer ' + token, root)
    snapshot = evaluate(v4, reader, app, auth_list, management, resource_id)
    return {
        'stage': STAGE,
        'status': 'VERIFIED_READBACK',
        'mode': 'READ_ONLY_ADMIN_PREFLIGHT',
        'tenant': TENANT,
        'dockerTarget': 'VERIFIED_V10_9444_ONLY',
        'applicationAndAuthorizedApi': 'EXACT_JOURNAL_AND_V3_FINGERPRINTS_MATCH',
        'observedAuthorizedApiType': snapshot['observedAuthorizedApiType'],
        'adminClient': 'EXISTING_SEPARATE_CLIENT_ID_VERIFIED',
        'adminScopesGrantedByWSO2TokenEndpoint': granted,
        'adminPatchPermissionLiveTested': False,
        'plannedPatch': snapshot['proposedPatch'],
        'applicationReadbackSha256': snapshot['applicationReadbackSha256'],
        'authorizedApiReadbackSha256': snapshot['authorizedApiReadbackSha256'],
        'targetApiAuthorizationSha256': snapshot['targetApiAuthorizationSha256'],
        'adminApprovalForWrite': False,
        'managementOAuthTokenRequests': 1,
        'managementGetRequests': 2,
        'managementResourceWrites': 0,
        'dockerOrConfigurationWrites': 0,
        'privateJournalWrites': 0,
        'nextAction': 'REVIEW_GUARDED_ONE_SHOT_PATCH_IMPLEMENTATION_SEPARATE_APPROVAL',
        'freshTokenAudienceAcceptance': 'BLOCKED',
        'consentV2': 'BLOCKED',
    }


if __name__ == '__main__':
    try:
        print(json.dumps(main(), indent=2, sort_keys=True))
    except Exception as exc:
        # Never print response text, credentials, raw token, IDs, paths or exception args.
        reason = exc.reason if isinstance(exc, Refuse) else type(exc).__name__
        result = {
            'stage': STAGE,
            'status': 'NOT_VERIFIED',
            'reason': reason,
            'managementResourceWrites': 0,
            'dockerOrConfigurationWrites': 0,
            'nextAction': 'STOP_NO_GRANTS_NO_WRITES',
        }
        if isinstance(exc, Refuse) and exc.missing:
            result['missingAdminScopes'] = list(exc.missing)
        print(json.dumps(result, indent=2, sort_keys=True))
        sys.exit(1)
