#!/usr/bin/env python3
"""CIAM v10: guarded one-shot add of management update scope, using the EXISTING tenant owner.

Revision v2: fixes v1's truncated TARGET_SHA; asserts all snapshot pins match the byte-for-byte pinned v4 planner before any remote access.

Only Aurora management application's exact journaled Application Management API auth.
plan is read-only, apply requires explicit approval and pinned fingerprints.
Never touches WSO2 :9443, Docker, credentials, clients, roles or databases.
Never automatically retries or rolls back an uncertain PATCH.
"""
import argparse
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile

HERE = Path(__file__).resolve().parent
DOMAIN = 'aurora.identity.test'
APP_API = '/api/server/v1/applications'
ADD = 'internal_application_mgt_update'
REQUIRED_BEFORE = frozenset({'internal_application_mgt_view', 'internal_application_mgt_create',
                             'internal_application_mgt_client_secret_view'})
APP_SHA = '2b0121de738802c643d30f84d3b123a2f3b4e22b8874a34950a5fc148a22f756'
LIST_SHA = '69ed9885664735f171c4d2327987fde5f7b2fd8e277ff025e6686aac92bb756f'
TARGET_SHA = 'd7c89a7cbc4f1bb85b9404a83d5610121147b0c8da0108d47b320cdb91d69972'
V4_SHA = 'f5cbc2430a1e8a8dd2edcb895846060962d5f5e3db45162d7d5fe5378da9524a'
CONFIRM = 'I_AUTHORIZE_AURORA_V10_MANAGEMENT_SCOPE_ONLY_ONCE'
SCHEMA = 'ciam.v10.aurora.management-scope-patch.v2'
MUTATION_PATH = re.compile(r'^/t/aurora\.identity\.test/api/server/v1/applications/[A-Za-z0-9_-]{5,256}={0,2}/authorized-apis/[A-Za-z0-9_-]{5,256}={0,2}$')
class Refuse(Exception): pass

def require(ok, reason):
    if not ok: raise Refuse(reason)

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def load_v4():
    path = HERE / 'management_scope_add_plan_v4.py'
    require(path.is_file() and not path.is_symlink(), 'PINNED_V4_MISSING')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == V4_SHA, 'PINNED_V4_CHANGED')
    spec = importlib.util.spec_from_file_location('ciam_p0_2_pinned_v4', path)
    require(spec is not None and spec.loader is not None, 'V4_IMPORT_UNAVAILABLE')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def verify_snapshot_pins(v4):
    """Refuse any handwritten/truncated snapshot value or v4 drift."""
    pins = ((APP_SHA, 'APP_SHA', 'EXPECTED_APP_SHA'),
            (LIST_SHA, 'LIST_SHA', 'EXPECTED_AUTH_LIST_SHA'),
            (TARGET_SHA, 'TARGET_SHA', 'EXPECTED_TARGET_AUTH_SHA'))
    for value, label, expected_name in pins:
        require(re.fullmatch(r'[0-9a-f]{64}', value) is not None,
                label + '_INVALID_SHA256')
        require(getattr(v4, expected_name, None) == value,
                label + '_DOES_NOT_MATCH_PINNED_V4')

def target_and_context(v4):
    reader = v4.safe_import(HERE / 'management_authorization_readback.py', v4.READER_SHA,
                            'ciam_p0_2_pinned_reader')
    plan = v4.safe_import(HERE / 'audience_plan.py', v4.PLAN_SHA, 'ciam_p0_2_pinned_audience')
    plan.ensure_repo()
    plan.ensure_target()
    resources = plan.load_module('ciam_p0_2_resources', plan.RESOURCE_SOURCE)
    authority = plan.load_module('ciam_p0_2_authority', plan.AUTH_SOURCE)
    tenants, rs, oidc = authority.private_context()
    management = rs['tenants']['aurora']['management']
    require(management.get('name') == v4.APP_NAME and management.get('state') == 'verified' and
            management.get('domain') == DOMAIN, 'JOURNALED_MANAGEMENT_IDENTITY_DRIFT')
    owner = tenants['tenants']['aurora']['owner']
    require(owner.get('username') == resources.OWNER and isinstance(owner.get('password'), str) and
            bool(owner['password']), 'JOURNALED_OWNER_UNAVAILABLE')
    app_id = management.get('id')
    api_id = management.get('authorized', {}).get(APP_API)
    require(isinstance(app_id, str) and resources.ID.fullmatch(app_id) is not None and
            isinstance(api_id, str) and resources.ID.fullmatch(api_id) is not None,
            'JOURNALED_RESOURCE_IDS_UNSAFE')
    root = f'/t/{DOMAIN}/api/server/v1/applications/{app_id}'
    target = root + '/authorized-apis/' + api_id
    require(MUTATION_PATH.fullmatch(target) is not None, 'MUTATION_TARGET_INVALID')
    require(set(resources.APP_SCOPES) == REQUIRED_BEFORE, 'BOOTSTRAP_SCOPE_CONTRACT_CHANGED')
    tls = plan.https_client_context()
    return reader, plan, resources, authority, tenants, rs, management, root, target, tls

def only_get(ctx, path, auth, root):
    require(path in (root, root + '/authorized-apis'), 'UNAPPROVED_READ_PATH')
    require(MUTATION_PATH.fullmatch(root + '/authorized-apis/abcde') is not None, 'UNSAFE_ROOT')
    con = http.client.HTTPSConnection('localhost', 9444, context=ctx, timeout=15)
    try:
        con.request('GET', path, headers={'Authorization': auth, 'Accept': 'application/json'})
        response = con.getresponse()
        raw = response.read(262145)
        require(response.status == 200, 'ADMIN_READ_HTTP_' + str(response.status))
        require(len(raw) <= 262144, 'ADMIN_READ_TOO_LARGE')
        try: return json.loads(raw)
        except (ValueError, UnicodeError): raise Refuse('ADMIN_READ_INVALID_JSON') from None
    finally:
        con.close()

def read_pair(ctx, owner_auth, root):
    return only_get(ctx, root, owner_auth, root), only_get(ctx, root + '/authorized-apis', owner_auth, root)

def match_target(reader, entries, api_id):
    rows = reader.unwrap_authorizations(entries)
    targets = [x for x in rows if x.get('id') == api_id]
    require(len(targets) == 1, 'TARGET_API_AUTHORIZATION_AMBIGUOUS')
    return targets[0]

def is_exact_scope_delta(reader, before, after, api_id):
    """Verify only a single scope was added to the journaled target, preserving all others."""
    xs = reader.unwrap_authorizations(before)
    ys = reader.unwrap_authorizations(after)
    require(len(xs) == len(ys), 'OTHER_AUTHORIZATIONS_COUNT_CHANGED')
    before_target = match_target(reader, before, api_id)
    after_target = match_target(reader, after, api_id)
    require(reader.parse_scope_names(before_target.get('authorizedScopes')) == set(REQUIRED_BEFORE),
            'BASELINE_SCOPES_NOT_EXACT')
    require(reader.parse_scope_names(after_target.get('authorizedScopes')) == set(REQUIRED_BEFORE) | {ADD},
            'SCOPE_ADD_READBACK_FAILED')
    # Compare full other API authorizations; do not accept silent changes to any of them.
    require([x for x in xs if x.get('id') != api_id] ==
            [x for x in ys if x.get('id') != api_id], 'OTHER_AUTHORIZATION_CHANGED')
    def without_scopes(obj):
        y = copy.deepcopy(obj); y.pop('authorizedScopes', None); return y
    require(without_scopes(before_target) == without_scopes(after_target),
            'TARGET_AUTHORIZATION_OTHER_FIELDS_CHANGED')
    # Preserve all previous scope records verbatim even if new scope has a server-generated ID.
    old = {x.get('name') if isinstance(x, dict) else x: x for x in before_target['authorizedScopes']}
    new = {x.get('name') if isinstance(x, dict) else x: x for x in after_target['authorizedScopes']}
    require(all(new.get(name) == item for name, item in old.items()), 'EXISTING_SCOPE_RECORD_CHANGED')
    return True

def check_safe_dir(private):
    require(private.is_dir() and not private.is_symlink(), 'PRIVATE_DIR_INVALID')
    st = private.stat()
    require(st.st_uid == os.getuid() and (stat.S_IMODE(st.st_mode) & 0o077) == 0,
            'PRIVATE_DIR_NOT_OWNER_ONLY')

def private_state_dir(private, create=False):
    check_safe_dir(private)
    target = private / 'management-scope-aurora-v1'
    require(not target.is_symlink(), 'STATE_DIR_SYMLINK')
    if create and not target.exists(): target.mkdir(mode=0o700)
    if target.exists():
        st = target.stat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
                stat.S_IMODE(st.st_mode) == 0o700, 'STATE_DIR_NOT_OWNER_ONLY')
    return target

def exclusive_json(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(canonical(obj) + b'\n'); f.flush(); os.fsync(f.fileno())
    dfd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(dfd)
    finally: os.close(dfd)

def private_json(path):
    require(path.is_file() and not path.is_symlink(), 'STATE_FILE_MISSING_OR_SYMLINK')
    st = path.stat()
    require(st.st_uid == os.getuid() and stat.S_ISREG(st.st_mode) and
            stat.S_IMODE(st.st_mode) == 0o600 and st.st_size < 1_000_000,
            'STATE_FILE_UNSAFE')
    return json.loads(path.read_bytes())

def persist_existing(path, value):
    private_json(path)
    fd, temp = tempfile.mkstemp(prefix='.scope-stage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(canonical(value) + b'\n'); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def patch_once(ctx, path, basic_auth):
    require(MUTATION_PATH.fullmatch(path) is not None, 'UNAPPROVED_MUTATION_TARGET')
    con = http.client.HTTPSConnection('localhost', 9444, context=ctx, timeout=20)
    try:
        con.request('PATCH', path, body=canonical({'addedScopes':[ADD], 'removedScopes':[]}),
                    headers={'Authorization':basic_auth, 'Content-Type':'application/json',
                             'Accept':'application/json'})
        response = con.getresponse()
        _ = response.read(262145)
        require(response.status in (200, 204), 'PATCH_STATUS_UNCERTAIN_HTTP_' + str(response.status))
    finally: con.close()

def report(status, reason, **fields):
    obj = {'stage':'CIAM_V10_P0_2_AURORA_MANAGEMENT_SCOPE_PATCH_V2', 'status':status,
           'reason':reason, 'tenant':DOMAIN, 'managementResourceWrites':0,
           'dockerOrConfigurationWrites':0, 'browserLogins':0,
           'consentV2':'BLOCKED', 'freshBusinessTokenAcceptance':'BLOCKED'}
    obj.update(fields)
    print(json.dumps(obj, indent=2, sort_keys=True))

def main():
    parser = argparse.ArgumentParser(description='Only Aurora, one management API scope, confirmed write')
    parser.add_argument('mode', choices=('plan','apply','reconcile'))
    parser.add_argument('--approve', default='')
    parser.add_argument('--expected-target-sha', default='')
    args = parser.parse_args()
    require(args.mode == 'apply' or (not args.approve and not args.expected_target_sha),
            'WRITE_FLAGS_ALLOWED_ONLY_IN_APPLY')
    v4 = load_v4()
    verify_snapshot_pins(v4)
    reader, plan, resources, authority, tenants, rs, management, root, target, tls = target_and_context(v4)
    api_id = management['authorized'][APP_API]
    owner = tenants['tenants']['aurora']['owner']
    owner_auth = resources.basic(resources.OWNER + '@' + DOMAIN, owner['password'])
    state_dir = private_state_dir(resources.ROOT / 'private', create=False)
    state_path = state_dir / 'write-ahead.private.json'
    if args.mode == 'reconcile':
        require(state_dir.is_dir(), 'NO_PREVIOUS_ATTEMPT_TO_RECONCILE')
        journal = private_json(state_path)
        require(journal.get('schema') == SCHEMA and journal.get('targetHash') ==
                hashlib.sha256(target.encode()).hexdigest(), 'WRITE_JOURNAL_CONTEXT_DRIFT')
        app_now, list_now = read_pair(tls, owner_auth, root)
        backup = private_json(state_dir / 'before.private.json')
        require(digest(backup['app']) == APP_SHA and digest(backup['authorizedApis']) == LIST_SHA,
                'BACKUP_CHECKSUM_CHANGED')
        try:
            require(app_now == backup['app'], 'MANAGEMENT_APP_CHANGED_AFTER_WRITE')
            is_exact_scope_delta(reader, backup['authorizedApis'], list_now, api_id)
        except Refuse:
            report('NOT_VERIFIED', 'WRITE_OUTCOME_UNKNOWN_OR_DRIFT_STOP_NO_RETRY', previousStage=journal.get('stage'))
            return
        report('VERIFIED_READBACK', 'UPDATE_SCOPE_PRESENT_AND_BASELINE_PRESERVED',
               previousStage=journal.get('stage'), updateScopeAuthorized=True)
        return
    if state_dir.exists():
        require(not state_path.exists() and not state_path.is_symlink(), 'EXISTING_WRITE_JOURNAL_USE_RECONCILE')
        require(not (state_dir / 'before.private.json').exists(), 'EXISTING_BACKUP_REVIEW_REQUIRED')
    # Read target as journaled VIEW client first, using pinned v4 logic.
    scope_token = plan.api_call(tls, 'POST', '/t/' + DOMAIN + '/oauth2/token',
                                resources.basic(management['clientId'], management['clientSecret']),
                                form={'grant_type':'client_credentials', 'scope':'internal_application_mgt_view'})
    require(scope_token.get('token_type','').lower() == 'bearer' and
            isinstance(scope_token.get('access_token'),str) and scope_token['access_token'] and
            'internal_application_mgt_view' in str(scope_token.get('scope','')).split(),
            'MANAGEMENT_VIEW_SCOPE_NOT_GRANTED')
    bearer = 'Bearer ' + scope_token['access_token']
    app_view = reader.only_get(tls, root, bearer, root)
    list_view = reader.only_get(tls, root + '/authorized-apis', bearer, root)
    v4.evaluate(reader, app_view, list_view, management, api_id)
    # Independent owner Basic GET. Existing owner credential previously produced HTTP 200.
    app_owner, list_owner = read_pair(tls, owner_auth, root)
    require(digest(app_owner) == APP_SHA and digest(list_owner) == LIST_SHA,
            'OWNER_GET_NOT_EQUAL_PINNED_VIEW_SNAPSHOT')
    require(digest(match_target(reader, list_owner, api_id)) == TARGET_SHA,
            'OWNER_TARGET_SHA_NOT_PINNED')
    require(app_owner == app_view and list_owner == list_view, 'ADMIN_AND_VIEW_READBACK_DIVERGE')
    if args.mode == 'plan':
        report('VERIFIED_READBACK', 'SINGLE_SCOPE_OWNER_BASIC_PATCH_PLAN_ONLY',
               operation='PATCH', ownerBasicGetVerified=True, safeForAutomaticApply=False,
               requiredExplicitApproval=True, updateScopeAuthorized=False,
               expectedTargetSha256=TARGET_SHA, proposedPatch={'addedScopes':[ADD], 'removedScopes':[]})
        return
    require(args.approve == CONFIRM and args.expected_target_sha == TARGET_SHA,
            'EXPLICIT_APPROVAL_OR_PINNED_TARGET_SHA_MISSING')
    state_dir = private_state_dir(resources.ROOT / 'private', create=True)
    backup = state_dir / 'before.private.json'
    journal_path = state_dir / 'write-ahead.private.json'
    require(not backup.exists() and not backup.is_symlink() and not journal_path.exists() and
            not journal_path.is_symlink(), 'PREVIOUS_BACKUP_OR_ATTEMPT_PRESENT')
    exclusive_json(backup, {'schema':SCHEMA, 'app':app_owner, 'authorizedApis':list_owner})
    journal = {'schema':SCHEMA, 'stage':'PATCH_ATTEMPT_STARTED_NO_AUTOMATIC_RETRY',
               'targetHash':hashlib.sha256(target.encode()).hexdigest(),
               'appSha256':APP_SHA, 'authorizationListSha256':LIST_SHA,
               'targetAuthorizationSha256':TARGET_SHA,
               'patch':{'addedScopes':[ADD], 'removedScopes':[]}}
    exclusive_json(journal_path, journal)
    # Immediately re-read after the durable write-ahead record, before sending PATCH.
    app_last, list_last = read_pair(tls, owner_auth, root)
    require(app_last == app_owner and list_last == list_owner, 'LAST_SECOND_DRIFT_NO_PATCH')
    try:
        patch_once(tls, target, owner_auth)
    except Exception:
        # Any network or HTTP ambiguity leaves the journal in PATCH_ATTEMPT_STARTED.
        # Operator MUST reconcile read-only; never retry blindly.
        report('NOT_VERIFIED','PATCH_OUTCOME_UNKNOWN_STOP_RECONCILE_NO_RETRY',
               managementResourceWrites='AT_MOST_ONE_ATTEMPT', journalExists=True)
        return
    try:
        after_app, after_list = read_pair(tls, owner_auth, root)
        require(after_app == app_owner, 'MANAGEMENT_APP_CHANGED_AFTER_PATCH')
        is_exact_scope_delta(reader, list_owner, after_list, api_id)
        journal['stage'] = 'SCOPE_ADD_VERIFIED_READBACK'
        persist_existing(journal_path, journal)
        report('VERIFIED_READBACK', 'ONE_SCOPE_ADDED_WITH_EXACT_READBACK',
               managementResourceWrites=1, updateScopeAuthorized=True)
    except Exception:
        report('NOT_VERIFIED', 'PATCH_READBACK_AMBIGUOUS_RUN_RECONCILE_NO_RETRY',
               managementResourceWrites='AT_MOST_ONE_ATTEMPT', journalExists=True)

if __name__ == '__main__':
    try: main()
    except Exception as e:
        # Never print raw exception text: may embed request content or private paths.
        code = str(e) if isinstance(e, Refuse) else type(e).__name__
        report('NOT_VERIFIED', code)
        sys.exit(1)
