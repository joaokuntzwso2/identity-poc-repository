#!/usr/bin/env python3
"""P1.23: restore exactly four journaled administrator `ciam:cases:approve` grants.

Default --plan and --verify are GET-only. --apply requires an exact confirmation
and writes a distinct, fsynced private recovery journal before each remote PATCH.
Never creates roles, changes audiences/memberships, or edits existing journals.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PHASE4 = ROOT / 'deploy/ciam-v10/phase4/business-bootstrap.py'
RESOURCES = ROOT / 'deploy/ciam-v10/resources/bootstrap.py'
EXPECTED_SHA = {
    PHASE4.name: '2e519c7239d6a638a9622bff7638e3d8e09b6524ef00f740b62080d96eb773c4',
    RESOURCES.name: 'c53e50f270acf83b7f3126bdd85ac945001323752218005f5b97df74fd5ecae1',
}
APPROVE = 'ciam:cases:approve'
BASE = frozenset(('ciam:cases:read', 'ciam:cases:review'))
TARGET = BASE | {APPROVE}
SCHEMA = 'ciampoc.v4.admin-approval-reconciliation.v1'
CONFIRM = 'GRANT_CIAM_CASES_APPROVE_TO_FOUR_JOURNALED_ADMIN_ROLES'
CONFIRM_ENV = 'WSO2_CIAM_ADMIN_APPROVAL_CONFIRM'
PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
KEYS = tuple(f'{brand}:{channel}' for brand in ('aurora', 'brisa') for channel in ('web', 'app'))
ALLOWED_CODES = re.compile(r'^[A-Z0-9_]+$')

class Stop(Exception):
    def __init__(self, code):
        super().__init__(code if ALLOWED_CODES.fullmatch(code) else 'UNCLASSIFIED_REFUSAL')

def hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_check():
    for source in (PHASE4, RESOURCES):
        if not source.is_file() or source.is_symlink() or hash_file(source) != EXPECTED_SHA[source.name]:
            raise Stop('SOURCE_DIGEST_MISMATCH')

def module_load():
    source_check()
    spec = importlib.util.spec_from_file_location('ciam_phase4_v4_admin_grant', PHASE4)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def patch_payload():
    return {'schemas': [PATCH_SCHEMA], 'Operations': [
        {'op': 'add', 'path': 'permissions', 'value': [{'value': APPROVE}]}
    ]}

def permissions(obj):
    values = obj.get('permissions')
    if not isinstance(values, list) or not all(isinstance(v, dict) and isinstance(v.get('value'), str) for v in values):
        raise Stop('ROLE_PERMISSION_SHAPE_REFUSED')
    p = [v['value'] for v in values]
    if len(set(p)) != len(p):
        raise Stop('DUPLICATE_ROLE_PERMISSION_REFUSED')
    return frozenset(p)

def validate_role(obj, *, role_id, name, app_id, member_ids, expected_set=None, admin=False):
    if not isinstance(obj, dict) or obj.get('id') != role_id or obj.get('displayName') != name:
        raise Stop('ROLE_IDENTITY_DRIFT')
    aud = obj.get('audience')
    if not isinstance(aud, dict) or aud.get('type') != 'application' or aud.get('value') != app_id:
        raise Stop('ROLE_AUDIENCE_DRIFT')
    members = obj.get('users')
    if (not isinstance(members, list) or
        not all(isinstance(v, dict) and isinstance(v.get('value'), str) for v in members)):
        raise Stop('ROLE_MEMBERS_SHAPE_REFUSED')
    values = [v['value'] for v in members]
    if len(values) != len(set(values)) or set(values) != set(member_ids):
        raise Stop('ROLE_MEMBERS_DRIFT')
    actual = permissions(obj)
    if admin:
        if actual not in (BASE, TARGET):
            raise Stop('ADMIN_PERMISSIONS_UNEXPECTED_DRIFT')
    elif actual != frozenset(expected_set):
        raise Stop('NONADMIN_PERMISSIONS_DRIFT')
    return 'granted' if admin and actual == TARGET else 'missing' if admin else 'match'

def next_action(stage, remote):
    if stage == 'prepared' and remote == 'missing':
        return 'patch'
    if stage == 'patch-started' and remote == 'granted':
        return 'recover'
    if stage == 'verified' and remote == 'granted':
        return 'skip'
    if stage == 'patch-started' and remote == 'missing':
        raise Stop('UNCERTAIN_PREVIOUS_PATCH_REFUSE_RETRY')
    if stage == 'prepared' and remote == 'granted':
        raise Stop('UNJOURNALED_ROLE_CHANGE_REFUSED')
    raise Stop('JOURNAL_REMOTE_STATE_CONFLICT')

def build_state(spec_digest, orig_digest, targets):
    return {
        'schema': SCHEMA,
        'specSha256': spec_digest,
        'phase4JournalSha256': orig_digest,
        'policy': 'ADMIN_APPROVE_WITH_TOTP_STEPUP_AND_SELF_APPROVAL_DENIAL',
        'targets': {k: {'roleId': targets[k]['id'], 'appId': targets[k]['app'], 'state': 'prepared'}
                    for k in KEYS}
    }

def validate_state(state, expected):
    if not isinstance(state, dict) or set(state) != set(expected):
        raise Stop('GRANT_JOURNAL_SCHEMA_DRIFT')
    for k in ('schema', 'specSha256', 'phase4JournalSha256', 'policy'):
        if state.get(k) != expected[k]:
            raise Stop('GRANT_JOURNAL_CONTEXT_DRIFT')
    rows = state.get('targets')
    if not isinstance(rows, dict) or set(rows) != set(KEYS):
        raise Stop('GRANT_JOURNAL_TARGET_DRIFT')
    for k in KEYS:
        r = rows[k]
        if (not isinstance(r, dict) or set(r) != {'roleId','appId','state'} or
            r['roleId'] != expected['targets'][k]['roleId'] or
            r['appId'] != expected['targets'][k]['appId'] or
            r['state'] not in ('prepared','patch-started','verified')):
            raise Stop('GRANT_JOURNAL_TARGET_DRIFT')

def git_clean():
    for args in (('rev-parse', '--is-inside-work-tree'), ('status', '--porcelain=v1', '--untracked-files=normal')):
        p = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True, timeout=10)
        if p.returncode or (args[0] == 'rev-parse' and p.stdout.strip() != 'true') or (
            args[0] == 'status' and p.stdout.strip()):
            raise Stop('SOURCE_WORKTREE_NOT_CLEAN')

def verified_app_auth(phase4, client, credential, brand, app_id, api):
    r = phase4.read(client, phase4.api_base(brand)+'/applications/'+app_id+'/authorized-apis', credential)
    if not isinstance(r, list):
        raise Stop('APP_AUTH_RESPONSE_SHAPE_REFUSED')
    m = [x for x in r if isinstance(x, dict) and x.get('identifier') == api['identifier']]
    if len(m) != 1 or m[0].get('policyId', m[0].get('policyIdentifier')) != 'RBAC':
        raise Stop('APP_AUTH_POLICY_DRIFT')
    names = m[0].get('authorizedScopes')
    if (not isinstance(names, list) or
        not all(isinstance(v, dict) and isinstance(v.get('name'), str) for v in names) or
        {v['name'] for v in names} != {v['name'] for v in api['scopes']} or
        len(names) != len(api['scopes'])):
        raise Stop('APP_AUTH_SCOPE_DRIFT')

def take_snapshot(phase4):
    spec, tenants, oidc, identities = phase4.context()
    business = spec.get('businessApi', {})
    if business.get('identifier') != 'urn:ciampoc:service-requests:v1' or business.get('requiresAuthorization', True) is False:
        raise Stop('BUSINESS_RESOURCE_IDENTIFIER_DRIFT')
    roles = business.get('rolePermissions', {})
    if set(roles) != {'customer', 'seller', 'administrator'}:
        raise Stop('SPEC_ROLE_KINDS_DRIFT')
    if frozenset(roles.get('administrator', [])) != TARGET or len(roles.get('administrator', [])) != 3:
        raise Stop('SPEC_ADMIN_GRANT_NOT_APPROVED')
    # Do not permit arbitrary changes in other desired role scope definitions.
    if frozenset(roles.get('customer', [])) != {'ciam:cases:create','ciam:cases:read'} or (
        frozenset(roles.get('seller', [])) != TARGET):
        raise Stop('SPEC_NONADMIN_GRANTS_DRIFT')
    state = phase4.read_private(phase4.JOURNAL)
    if state.get('schema') != 'ciampoc.v4.business-journal.v1' or (
            state.get('specSha256') != hash_file(phase4.SPEC_FILE)):
        raise Stop('PHASE4_JOURNAL_SPEC_DRIFT')
    client = phase4.resources.HTTPS()
    targets = {}
    remote_states = {}
    roles_checked = 0
    for brand in ('aurora', 'brisa'):
        cred = phase4.auth(tenants, brand)
        node = state['tenants'][brand]
        api_id = node['api'].get('id')
        if not isinstance(api_id, str) or not phase4.resources.ID.fullmatch(api_id):
            raise Stop('API_ID_NOT_JOURNALED')
        phase4.verified_api(client, cred, brand, api_id, business)
        for channel in ('web', 'app'):
            appid = oidc['tenants'][brand]['clients'][channel]['id']
            japp = node['apps'].get(channel)
            if not japp or japp.get('id') != appid or japp.get('state') != 'verified':
                raise Stop('PHASE4_APP_JOURNAL_DRIFT')
            verified_app_auth(phase4, client, cred, brand, appid, business)
            for kind, expected_scopes in roles.items():
                member_ids = [x['id'] for x in identities['tenants'][brand]['users'].values() if x['kind'] == kind]
                if not member_ids:
                    continue
                role_journal = node['roles'].get(channel+':'+kind)
                if not isinstance(role_journal, dict) or role_journal.get('state') != 'verified':
                    raise Stop('PHASE4_ROLE_JOURNAL_DRIFT')
                rid = role_journal.get('id')
                if not isinstance(rid, str) or not phase4.resources.ID.fullmatch(rid):
                    raise Stop('PHASE4_ROLE_ID_DRIFT')
                obj = phase4.read(client, phase4.role_base(brand)+'/'+rid, cred)
                status = validate_role(obj, role_id=rid,
                                       name='CIAM Business '+kind.title()+' '+channel.upper(),
                                       app_id=appid, member_ids=member_ids,
                                       expected_set=expected_scopes, admin=kind=='administrator')
                roles_checked += 1
                if kind == 'administrator':
                    key=brand+':'+channel
                    targets[key] = {'id':rid,'app':appid,'cred':cred,'brand':brand,
                                    'channel':channel,'members':member_ids}
                    remote_states[key]=status
    if roles_checked != 10:
        raise Stop('EXPECTED_TEN_BUSINESS_ROLES_NOT_FOUND')
    if set(targets) != set(KEYS):
        raise Stop('EXPECTED_FOUR_ADMIN_ROLES_NOT_FOUND')
    return spec, state, targets, remote_states, client

def patch_role(phase4, remote, target):
    path = phase4.role_base(target['brand']) + '/' + target['id']
    if not path.startswith('/t/'+phase4.resources.DOMAINS[target['brand']]+'/scim2/v2/Roles/'):
        raise Stop('PATCH_PATH_REFUSED')
    conn = http.client.HTTPSConnection(phase4.resources.HOST, phase4.resources.PORT,
                                     context=remote.context, timeout=20)
    try:
        conn.request('PATCH', path, body=json.dumps(patch_payload()), headers={
            'Authorization': target['cred'], 'Accept': 'application/scim+json',
            'Content-Type': 'application/scim+json'})
        response = conn.getresponse()
        # Ignore response bodies, which may contain private role membership.
        response.read(300001)
        return response.status
    finally:
        conn.close()

def read_current_admin(phase4, remote, target):
    obj = phase4.read(remote, phase4.role_base(target['brand'])+'/'+target['id'], target['cred'])
    return validate_role(obj, role_id=target['id'], name='CIAM Business Administrator '+target['channel'].upper(),
                         app_id=target['app'], member_ids=target['members'], admin=True)

def acquire_lock(path):
    if path.exists() or path.is_symlink():
        raise Stop('EXISTING_GRANT_LOCK_REFUSED')
    fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode('ascii')); os.fsync(fd)
        return fd
    except Exception:
        os.close(fd); raise

def do_run(mode):
    phase4 = module_load()
    spec, base_journal, targets, remote_states, remote = take_snapshot(phase4)
    private = phase4.resources.ROOT / 'private'
    journal_file = private / 'bootstrap-admin-approval-grant-v1.private.json'
    lock_file = private / 'bootstrap-admin-approval-grant-v1.lock'
    expected = build_state(hash_file(phase4.SPEC_FILE), hash_file(phase4.JOURNAL), targets)
    stored = phase4.resources.private_read(journal_file, False)
    if stored is not None:
        validate_state(stored, expected)
    elif any(s == 'granted' for s in remote_states.values()):
        raise Stop('EXTERNAL_ADMIN_GRANT_WITHOUT_JOURNAL')
    if mode != 'apply':
        rows = [{'tenant':t.split(':')[0], 'channel':t.split(':')[1],
                 'approval': remote_states[t],
                 'migration': stored['targets'][t]['state'] if stored else 'not-started'} for t in KEYS]
        return {'stage':'CIAM_ADMIN_APPROVAL_GRANT_V1','mode':'GET_ONLY_'+mode.upper(),
                'remoteWrites':0,'rolesChecked':10,'targets':rows,
                'allGranted':all(s=='granted' for s in remote_states.values()),
                'roleApiVersion':'v2','existingJournalUnmodified':True}
    git_clean()
    if os.environ.get(CONFIRM_ENV) != CONFIRM:
        raise Stop('EXPLICIT_FOUR_ROLE_GRANT_CONFIRMATION_REQUIRED')
    # A fresh inventory must be valid before we permit any remote mutation.
    fd = acquire_lock(lock_file)
    try:
        state = stored if stored is not None else expected
        if stored is None:
            phase4.resources.atomic_save(journal_file, state)
        for key in KEYS:
            target = targets[key]
            stage = state['targets'][key]['state']
            # Prevent stale inventory after a previous PATCH or external change.
            current = read_current_admin(phase4, remote, target)
            action = next_action(stage, current)
            if action == 'skip':
                continue
            if action == 'recover':
                state['targets'][key]['state']='verified'
                phase4.resources.atomic_save(journal_file,state)
                continue
            state['targets'][key]['state']='patch-started'
            phase4.resources.atomic_save(journal_file,state)
            try:
                status = patch_role(phase4, remote, target)
            except Exception:
                raise Stop('PATCH_OUTCOME_UNCERTAIN_NO_RETRY')
            if status != 200:
                raise Stop('PATCH_OUTCOME_UNCERTAIN_NO_RETRY')
            if read_current_admin(phase4,remote,target) != 'granted':
                raise Stop('PATCH_READBACK_MISMATCH_NO_RETRY')
            state['targets'][key]['state']='verified'
            phase4.resources.atomic_save(journal_file,state)
        # Check the original Phase4 contract and every business grant, not just targeted roles.
        verified = phase4.execute('verify')
        if verified != {'stage':'CIAM_BUSINESS_V4', 'mode':'VERIFY', 'readback':'VERIFIED', 'businessRuntime':'NOT_TESTED'}:
            raise Stop('POST_GRANT_BUSINESS_VERIFY_FAILED')
        return {'stage':'CIAM_ADMIN_APPROVAL_GRANT_V1','mode':'APPLY', 'result':'FOUR_ADMIN_ROLES_VERIFIED',
                'targetsVerified':4,'phase4ManagementReadback':'VERIFIED',
                'businessRuntime':'NOT_TESTED','mfaPositive':'NOT_TESTED',
                'originalJournalsUnmodified':True}
    finally:
        os.close(fd)
        lock_file.unlink()

def self_test():
    assert patch_payload() == {'schemas':[PATCH_SCHEMA], 'Operations':[
        {'op':'add','path':'permissions','value':[{'value':'ciam:cases:approve'}]}]}
    def role(p, members=('u1',), audience='app1', name='CIAM Business Administrator WEB'):
        return {'id':'role1','displayName':name,'audience':{'type':'application','value':audience},
                'users':[{'value':m} for m in members],
                'permissions':[{'value':v} for v in p]}
    kwargs={'role_id':'role1','name':'CIAM Business Administrator WEB', 'app_id':'app1','member_ids':['u1'],'admin':True}
    assert validate_role(role(BASE),**kwargs) == 'missing'
    assert validate_role(role(TARGET),**kwargs) == 'granted'
    for bad in (role(BASE|{'ciam:cases:create'}),role({'ciam:cases:read'}),
                role(['ciam:cases:read','ciam:cases:read','ciam:cases:review'])):
        try: validate_role(bad,**kwargs)
        except Stop: pass
        else: raise AssertionError('unsafe grant state accepted')
    for bad in (role(BASE,members=['u2']),role(BASE,audience='app2'),role(BASE,name='Other')):
        try: validate_role(bad,**kwargs)
        except Stop: pass
        else: raise AssertionError('role identity drift accepted')
    for stage, remote, outcome in (('prepared','missing','patch'),('patch-started','granted','recover'),('verified','granted','skip')):
        assert next_action(stage,remote)==outcome
    for stage, remote in (('patch-started','missing'),('prepared','granted'),('verified','missing')):
        try: next_action(stage,remote)
        except Stop: pass
        else: raise AssertionError('unsafe retry accepted')
    targets={k:{'id':'role_'+str(i), 'app':'app_'+str(i)} for i,k in enumerate(KEYS)}
    state=build_state('spec','journal',targets)
    validate_state(state,state)
    state['targets']['aurora:web']['roleId']='changed'
    try: validate_state(state,build_state('spec','journal',targets))
    except Stop: pass
    else: raise AssertionError('journal drift accepted')
    print('SELF_TEST_PASS: scoped PATCH, exact grants, role binding, recovery and journal checks')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    opts=parser.add_mutually_exclusive_group()
    opts.add_argument('--plan',action='store_true',help='GET-only preview (default)')
    opts.add_argument('--verify',action='store_true',help='GET-only proof after migration')
    opts.add_argument('--apply',action='store_true',help='Explicitly confirmed four-role grant')
    opts.add_argument('--self-test',action='store_true')
    args=parser.parse_args()
    if args.self_test:
        self_test();return 0
    try:
        result=do_run('apply' if args.apply else 'verify' if args.verify else 'plan')
        print(json.dumps(result,indent=2))
        if args.verify and not result['allGranted']:
            return 2
        return 0
    except Exception as e:
        # Never print secrets/URLs/private journal contents from WSO2 exceptions.
        code=str(e) if isinstance(e,Stop) else 'REMOTE_OR_LOCAL_UNCLASSIFIED_FAILURE'
        print(json.dumps({'stage':'CIAM_ADMIN_APPROVAL_GRANT_V1','result':'REFUSED',
                          'reasonCode':code,'detail':'No raw server data or private identifiers displayed.'},indent=2))
        return 2

if __name__=='__main__':
    sys.exit(main())
