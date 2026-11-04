#!/usr/bin/env python3
"""P2.24 v46: independent, GET-only partner directory audit (no SCIM or management mutations).

The OAuth client-credentials TOKEN request is a POST to issue a short-lived token;
it is NOT a WSO2 management mutation. All SCIM and management requests are GET.
No journal, source, or WSO2 configuration is changed by this script.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

TENANT = 'aurora.identity.test'
EXPECTED_V18_SHA = 'bd160f2cd0c53508abb26f2c1d58bf13943a0de12884845d8f6066961c46cee9'
EXPECTED_V36_SHA = '41a5db35a6f789b6d03665274da7e4f3fb52efb43af38819532c238be377f72f'
SCOPES = tuple(sorted((
    'internal_org_group_mgt_create', 'internal_org_group_mgt_view',
    'internal_org_user_mgt_create', 'internal_org_user_mgt_list',
    'internal_org_user_mgt_view',
)))
UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')

class AuditBlocked(Exception):
    pass

def need(ok, code):
    if not ok:
        raise AuditBlocked(code)

def load_module(path: Path):
    spec = importlib.util.spec_from_file_location('p224_v46_v36', path)
    need(spec is not None and spec.loader is not None, 'BOOTSTRAP_MODULE_NOT_LOADABLE')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class OnlyGet:
    """Defensive adapter around WSO2 management HTTP client."""
    def __init__(self, api):
        self.api = api
    def call(self, method, path, body=None):
        need(method == 'GET' and body is None, 'MANAGEMENT_WRITE_FORBIDDEN')
        return self.api.call(method, path)
    def get(self, path):
        status, doc, _ = self.call('GET', path)
        need(status == 200, 'MANAGEMENT_GET_NOT_200')
        return doc

class OnlyGetScim:
    """Allow SCIM read requests only, regardless of capabilities of underlying client."""
    def __init__(self, scim):
        self.scim = scim
    def request(self, method, resource, body=None):
        need(method == 'GET' and body is None, 'SCIM_WRITE_FORBIDDEN')
        need(isinstance(resource, str) and (resource.startswith('Users?') or
             resource.startswith('Groups?') or
             re.fullmatch(r'(?:Users|Groups)/[0-9a-fA-F-]{36}', resource)),
             'SCIM_RESOURCE_NOT_ALLOWED')
        return self.scim.request(method, resource)

def one_named(rows, key, value, code):
    need(type(rows) is list and len(rows) <= 1000 and all(type(x) is dict for x in rows),
         'SCIM_COLLECTION_NOT_COMPLETE')
    found = [x for x in rows if x.get(key) == value]
    need(len(found) == 1, code)
    return found[0]

def uuid(value):
    return type(value) is str and UUID.fullmatch(value) is not None

def check_directory(users, groups, details, members):
    """Pure directory evidence check; injectable detail callback for negative tests."""
    need(type(members) in (tuple, list) and len(members) == 2,
         'EXPECTED_SEED_DEFINITION_CHANGED')
    seen_users = set()
    seen_groups = set()
    for username, _, groupname in members:
        need(type(username) is str and type(groupname) is str and
             username not in seen_users and groupname not in seen_groups,
             'EXPECTED_SEED_DUPLICATE')
        seen_users.add(username)
        seen_groups.add(groupname)
        listed_user = one_named(users, 'userName', username, 'PARTNER_USER_MISSING_OR_DUPLICATE')
        uid = listed_user.get('id')
        need(uuid(uid), 'PARTNER_USER_ID_INVALID')
        usr = details('Users', uid)
        need(type(usr) is dict and usr.get('id') == uid and
             usr.get('userName') == username and usr.get('active') is False,
             'PARTNER_USER_NOT_DISABLED_OR_DETAIL_DRIFT')
        need(usr.get('roles') in (None, []), 'PARTNER_USER_HAS_UNEXPECTED_ROLES')
        listed_group = one_named(groups, 'displayName', groupname,
                                 'PARTNER_GROUP_MISSING_OR_DUPLICATE')
        gid = listed_group.get('id')
        need(uuid(gid), 'PARTNER_GROUP_ID_INVALID')
        grp = details('Groups', gid)
        need(type(grp) is dict and grp.get('id') == gid and
             grp.get('displayName') == groupname, 'PARTNER_GROUP_DETAIL_DRIFT')
        member_rows = grp.get('members')
        need(type(member_rows) is list and len(member_rows) == 1 and
             type(member_rows[0]) is dict and member_rows[0].get('value') == uid,
             'PARTNER_GROUP_MEMBERSHIP_NOT_EXACT')
    return {'disabledUsersVerified': len(seen_users),
            'groupsVerified': len(seen_groups),
            'exactMembershipsVerified': len(seen_groups),
            'noAssignedRolesVerified': True}

def main(argv):
    need(argv == ['audit'], 'USE_AUDIT_ONLY')
    repo = Path.cwd().resolve(strict=True)
    need((repo / 'scripts/ciam-v10.sh').is_file(), 'RUN_FROM_PROJECT_ROOT')
    source = repo / 'scripts/p2/p2_24_v36_full_automatic_directory_bootstrap.py'
    directory = repo / 'scripts/p2/partner_directory_v18.py'
    need(source.is_file() and directory.is_file() and not source.is_symlink() and
         not directory.is_symlink(), 'PINNED_SOURCE_MISSING')
    need(hashlib.sha256(source.read_bytes()).hexdigest() == EXPECTED_V36_SHA,
         'V45_PATCHED_BOOTSTRAP_SOURCE_DRIFT')
    need(hashlib.sha256(directory.read_bytes()).hexdigest() == EXPECTED_V18_SHA,
         'V36_PATCHED_DIRECTORY_SOURCE_DRIFT')
    impl = load_module(source)
    ctx = impl.context()  # Already verifies GA 7.3.0 target, pinned TLS, v17 share.
    v18 = ctx['v18']
    need(tuple(v18.SCOPES) == SCOPES and len(v18.MEMBERS) == 2,
         'DIRECTORY_CONTRACT_DRIFT')
    api = OnlyGet(impl.Api(ctx))
    store = impl.Store(ctx['private'] / impl.JOURNAL)
    need(store.doc is not None and store.doc.get('partnerId') == ctx['partner'] and
         store.doc.get('name') == impl.NAME and store.doc.get('actorRecordCreated') is True,
         'OWNED_ACTOR_BOOTSTRAP_JOURNAL_INCOMPLETE')
    app = store.doc.get('applicationId')
    need(uuid(app), 'OWNED_ACTOR_APPLICATION_INVALID')
    need(impl.app_detail(api, app).get('isManagementApp') is True,
         'OWNED_ACTOR_APP_NOT_VERIFIED')
    need(impl.oidc_exact(impl.oidc_state(api, app), store),
         'OIDC_CLIENT_READBACK_NOT_EXACT')
    resources = impl.resource_discovery(api, SCOPES)
    need(set(resources) == {'Users', 'Groups'}, 'ORG_API_RESOURCES_NOT_EXACT')
    authorizations = impl.api_authorizations(api, app)
    need(impl.authorizations_exact(authorizations, resources, SCOPES),
         'FIVE_SCOPES_OR_RBAC_AUTHORIZATION_DRIFT')
    need(impl.share_exact(ctx, app), 'ACTOR_SHARING_NOT_PARTNER_EXCLUSIVE')
    attempts = store.doc.get('attempts', {})
    for stage in ('CREATE_APP', 'SET_OIDC', 'AUTH_USERS', 'AUTH_GROUPS', 'SHARE_ACTOR'):
        need(type(attempts.get(stage)) is dict and attempts[stage].get('state') == 'VERIFIED',
             'OWNED_MANAGEMENT_ATTEMPT_NOT_VERIFIED_' + stage)
    actorfile = ctx['private'] / v18.ACTOR_FILE
    need(ctx['m'].safe_private_file(actorfile, required=False),
         'PARTNER_ACTOR_PRIVATE_RECORD_INVALID')
    record = ctx['m'].read_json_private(actorfile)
    need(type(record) is dict and record.get('applicationId') == app and
         record.get('clientId') == store.doc.get('clientId') and
         record.get('clientSecret') == store.doc.get('clientSecret'),
         'PARTNER_ACTOR_CREDENTIAL_OWNERSHIP_DRIFT')
    client, secret = v18.actor_check(ctx['m'], ctx['http'], ctx['admin'], record, ctx['partner'])
    # OAuth token issuance uses a POST but DOES NOT modify WSO2 directory/management data.
    # v18.actor_token validates JWT's org_id, issuer and all five exact scopes.
    token = v18.actor_token(ctx['ca'], ctx['partner'], client, secret)
    scim = OnlyGetScim(v18.Scim(ctx['ca'], ctx['partner'], token))
    users = v18.full_list(scim, 'Users')
    groups = v18.full_list(scim, 'Groups')
    def detail(kind, item_id):
        status, doc = scim.request('GET', f'{kind}/{item_id}')
        need(status == 200 and type(doc) is dict, 'PARTNER_SCIM_DETAIL_GET_FAILED')
        return doc
    verified = check_directory(users, groups, detail, v18.MEMBERS)
    return {
        'status': 'VERIFIED',
        'code': 'P2_24_PARTNER_DIRECTORY_LIVE_READBACK_VERIFIED',
        'phase': 'P2.24', 'tenant': TENANT,
        'businessApplicationSharingVerified': True,
        'directoryActorVerified': True,
        'actorSharedExclusivelyWithPartner': True,
        'orgIdAndFiveScopesVerifiedOnIssuedToken': True,
        'apiResourcesAuthorized': 2,
        **verified,
        'managementWritesAttempted': 0,
        'scimWritesAttempted': 0,
        'tokenIssuedForReadback': True,
        'privateJournalsModified': False,
        'wso2DeploymentModified': False,
        'partnerLoginEnabled': False,
        'delegatedAdministrationVerified': False,
        'businessAuthorizationVerified': False,
    }

if __name__ == '__main__':
    try:
        result = main(sys.argv[1:])
        exitcode = 0
    except AuditBlocked as ex:
        result = {'status': 'BLOCKED', 'code': str(ex), 'phase': 'P2.24',
                  'managementWritesAttempted': 0, 'scimWritesAttempted': 0}
        exitcode = 2
    except Exception as ex:
        # Only print a bounded, sanitized classifier; no raw HTTP data or secrets.
        name = type(ex).__name__
        msg = str(ex)
        safe = msg if re.fullmatch(r'[A-Z0-9_]{4,120}', msg) else 'REDACTED'
        result = {'status': 'BLOCKED', 'code': 'DEPENDENCY_VALIDATION_FAILED',
                  'dependencyException': name, 'dependencyCode': safe,
                  'phase': 'P2.24', 'managementWritesAttempted': 0,
                  'scimWritesAttempted': 0}
        exitcode = 3
    print(json.dumps(result, sort_keys=True, indent=2), flush=True)
    raise SystemExit(exitcode)
