#!/usr/bin/env python3
"""Existing WSO2 IS 7.3 Roles v2: precisely remove administrator case approval.

No creations, deletions, PUTs, resource/application/user/group modifications.
One operator-confirmed, journaled, permission-filter PATCH per invocation.
Without an attested server-enforced If-Match, there is no atomic compare-and-swap.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.parse
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
MODULE = HERE / 'bootstrap.py'
PINNED = 'urn:ciampoc:service-requests:v1'
REMOVE = 'ciam:cases:approve'
BEFORE = frozenset(('ciam:cases:approve','ciam:cases:read','ciam:cases:review'))
AFTER = frozenset(('ciam:cases:read','ciam:cases:review'))
ROLE_KEYS = ('aurora:app','aurora:web','brisa:app','brisa:web')
CONFIRM = 'REMOVE_CASE_APPROVE_ONLY_FROM_FOUR_BUSINESS_ADMIN_ROLES'
PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
JOURNAL_NAME = 'bootstrap-cases-admin-approve-removal-v10.private.json'
LOCK_NAME = 'bootstrap-cases-admin-approve-removal-v10.lock'
SCHEMA = 'identity.wso2.ciam.v10.cases-admin-approve-removal.v1'

class Refuse(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refuse(code)


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def refs(detail, field, *, mandatory):
    if field not in detail:
        need(not mandatory, 'MISSING_' + field.upper())
        return None
    entries = detail[field]
    need(isinstance(entries, list), 'BAD_' + field.upper())
    values = []
    for item in entries:
        value = item.get('value') if isinstance(item, dict) else None
        need(isinstance(value, str) and bool(value), 'INVALID_' + field.upper())
        values.append(value)
    need(len(values) == len(set(values)), 'DUPLICATED_' + field.upper())
    return frozenset(values)


def patch_payload():
    # SCIM filter operation: no replacement of the entire permission array.
    return {'schemas': [PATCH_SCHEMA], 'Operations': [
        {'op': 'remove', 'path': 'permissions[value eq "ciam:cases:approve"]'}
    ]}


def load_stage():
    need(MODULE.is_file(), 'EXISTING_CASES_STAGE_NOT_INSTALLED')
    spec = importlib.util.spec_from_file_location('ciam_v10_admin_permission_stage', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tenant_auth(m, ctx, brand):
    ts = ctx[0]
    return m.resources.basic(m.resources.OWNER + '@' + m.DOMAINS[brand],
                             ts['tenants'][brand]['owner']['password'])


def expected_admin(m, ctx, brand):
    identities, seed = ctx[3], ctx[4]
    people = [p for p in seed['people'] if p['type'] == 'administrator' and brand in p['brands']]
    need(len(people) == 1, 'ADMINISTRATOR_SEED_NOT_UNIQUE_' + brand)
    node = identities['tenants'][brand]['users'].get(people[0]['key'], {})
    need(node.get('state') == 'verified' and m.resources.ID.fullmatch(str(node.get('id',''))),
         'ADMINISTRATOR_JOURNAL_UNVERIFIED_' + brand)
    return frozenset((node['id'],))


class Transport:
    """Local-only HTTPS transport; always uses the repository's TLS context.

    Unlike the original resources.HTTPS, adds ONLY a narrowly scoped PATCH.
    This cannot target an API resource, an application, or a user/group.
    """
    def __init__(self, m):
        self.m = m
        need(m.resources.BASE == 'https://localhost:9444' and
             m.resources.HOST == 'localhost' and m.resources.PORT == 9444,
             'UNEXPECTED_WSO2_ENDPOINT')
        self.ctx = m.resources.HTTPS().context
        self.get_count = 0
        self.patch_count = 0

    @staticmethod
    def allowed(method, path, data):
        if not isinstance(path, str) or not path.startswith('/t/') or '\\' in path or '..' in path or '#' in path:
            raise Refuse('INVALID_HTTP_PATH')
        if method == 'GET' and data is None:
            # bounded, tenant-pinned GETs, no redirect following.
            return bool(re.fullmatch(
                r'/t/(?:aurora\.identity\.test|brisa\.identity\.test)/scim2/(?:v2/Roles(?:/[A-Za-z0-9_-]{5,256}={0,2})?|Groups(?:/[A-Za-z0-9_-]{5,256}={0,2})?)(?:\?[^#]{1,500})?', path))
        if method == 'PATCH':
            return bool(re.fullmatch(
                r'/t/(?:aurora\.identity\.test|brisa\.identity\.test)/scim2/v2/Roles/[A-Za-z0-9_-]{5,256}={0,2}', path)
                and data == patch_payload())
        return False

    def request(self, method, path, *, auth, data=None, etag=None):
        need(self.allowed(method, path, data), 'HTTP_OPERATION_NOT_ALLOWED')
        need(isinstance(auth,str) and auth.startswith('Basic '), 'ADMIN_AUTH_NOT_VERIFIED')
        headers = {'Authorization': auth, 'Accept': 'application/scim+json'}
        body = None
        if method == 'PATCH':
            headers['Content-Type'] = 'application/scim+json'
            if etag is not None:
                need(isinstance(etag, str) and 1 <= len(etag) <= 200 and '\r' not in etag and '\n' not in etag,
                     'UNSAFE_ETAG')
                headers['If-Match'] = etag
            body = json.dumps(data, separators=(',', ':'))
            self.patch_count += 1
        else:
            self.get_count += 1
        c = http.client.HTTPSConnection('localhost', 9444, context=self.ctx, timeout=15)
        try:
            c.request(method, path, body=body, headers=headers)
            r = c.getresponse()
            raw = r.read(300001)
            need(len(raw) <= 300000, 'OVERSIZED_RESPONSE')
            need(not (300 <= r.status < 400), 'REDIRECT_REFUSED')
            try:
                obj = json.loads(raw) if raw else {}
            except (ValueError, UnicodeDecodeError):
                obj = None
            if 200 <= r.status < 300:
                need(isinstance(obj, dict), 'SUCCESS_RESPONSE_NOT_JSON_OBJECT')
            return r.status, obj, r.getheader('ETag')
        finally:
            c.close()

    def call(self, method, path, *, auth, data=None, form=None):
        need(form is None, 'FORM_REQUEST_REFUSED')
        code, body, etag = self.request(method, path, auth=auth, data=data)
        return code, body, etag


def read_role(m, client, ctx, brand, channel):
    version = ctx[5]
    need(version == 'v2', 'ROLE_V2_NOT_JOURNAL_PINNED')
    app = ctx[1]['tenants'][brand]['clients'][channel]
    need(app.get('state') == 'verified' and
         m.resources.ID.fullmatch(str(app.get('id', ''))), 'OIDC_APP_JOURNAL_INVALID')
    auth = tenant_auth(m, ctx, brand)
    role_name = 'CIAM Business Administrator ' + channel.upper()
    item = m.exact_role(client, brand, auth, version, role_name)
    need(isinstance(item, dict) and m.resources.ID.fullmatch(str(item.get('id',''))),
         'BUSINESS_ADMIN_ROLE_NOT_FOUND_' + brand + '_' + channel)
    rid = item['id']
    path = m.path(brand, '/scim2/v2/Roles/' + rid)
    status, detail, etag = client.request('GET', path, auth=auth)
    need(status == 200 and isinstance(detail, dict) and detail.get('id') == rid and
         detail.get('displayName') == role_name, 'ROLE_DETAIL_ID_OR_NAME_DRIFT')
    audience = detail.get('audience')
    need(isinstance(audience, dict) and audience.get('type') == 'application' and
         audience.get('value') == app['id'], 'ROLE_APPLICATION_AUDIENCE_DRIFT')
    permissions = refs(detail, 'permissions', mandatory=True)
    users = refs(detail, 'users', mandatory=True)
    groups = refs(detail, 'groups', mandatory=False)
    need(users == expected_admin(m, ctx, brand), 'ADMINISTRATOR_DIRECT_MEMBERSHIP_DRIFT')
    need(groups is None or not groups, 'ROLE_DIRECT_GROUPS_NOT_EMPTY')
    need(permissions in (BEFORE, AFTER), 'ROLE_PERMISSION_SCOPE_DRIFT')
    snapshot = {'id': rid, 'name': role_name, 'audience': audience,
                'permissions': sorted(permissions), 'users': sorted(users),
                'groups': sorted(groups) if groups is not None else None}
    return {'tenant': brand, 'channel': channel, 'roleId': rid, 'name': role_name,
            'roleIdSha256': hashlib.sha256(rid.encode()).hexdigest(),
            'snapshotSha256': digest(snapshot), 'membersSha256': digest(sorted(users)),
            'permissions': permissions, 'etag': etag, 'groupStatus': 'OMITTED' if groups is None else 'EMPTY',
            'path': path, 'auth': auth}


def list_groups(m, client, brand, auth):
    root = m.path(brand, '/scim2/Groups')
    seen = set()
    total = None
    for _ in range(30):
        query = urllib.parse.urlencode({'startIndex': len(seen) + 1, 'count': 100})
        status, doc, _ = client.request('GET', root + '?' + query, auth=auth)
        need(status == 200 and isinstance(doc, dict), 'SCIM_GROUP_LIST_FAILED')
        count = doc.get('totalResults')
        need(type(count) is int and 0 <= count <= 3000, 'GROUP_TOTAL_NOT_ATTESTED')
        if total is None:
            total = count
        need(count == total, 'GROUP_TOTAL_CHANGED_DURING_READ')
        rows = m.list_items(doc, 'Resources', 'resources')
        need(isinstance(rows, list) and len(rows) <= 100, 'INVALID_GROUP_PAGE')
        need(rows or len(seen) == total, 'INCOMPLETE_GROUP_PAGINATION')
        for row in rows:
            gid = row.get('id') if isinstance(row, dict) else None
            need(isinstance(gid, str) and m.resources.ID.fullmatch(gid) and gid not in seen,
                 'DUPLICATE_OR_INVALID_GROUP_ID')
            seen.add(gid)
        need(len(seen) <= total, 'GROUP_COUNT_INCONSISTENCY')
        if len(seen) == total:
            return sorted(seen)
    raise Refuse('GROUP_PAGINATION_LIMIT')


def group_proof(m, client, ctx, brand, admin_role_ids):
    auth = tenant_auth(m, ctx, brand)
    ids = list_groups(m, client, brand, auth)
    proof = []
    for gid in ids:
        path = m.path(brand, '/scim2/Groups/' + gid)
        selected = path + '?attributes=' + urllib.parse.quote('id,roles')
        code, base, _ = client.request('GET', path, auth=auth)
        code2, view, _ = client.request('GET', selected, auth=auth)
        need(code == 200 and code2 == 200 and isinstance(base, dict) and isinstance(view, dict)
             and base.get('id') == gid and view.get('id') == gid, 'GROUP_DETAIL_NOT_ATTESTED')
        one = refs(base, 'roles', mandatory=False)
        two = refs(view, 'roles', mandatory=False)
        need(one is None or two is None or one == two, 'CONTRADICTORY_GROUP_ROLE_READBACK')
        actual = one if one is not None else two
        need(actual is not None, 'GROUP_ROLE_FIELD_NOT_ATTESTED')
        need(not set(actual) & set(admin_role_ids), 'ADMINISTRATOR_CASE_ROLE_GROUP_LINK_PRESENT')
        proof.append([gid, sorted(actual)])
    return {'count': len(ids), 'fingerprint': digest(proof)}


def initial_journal(m, ctx):
    return {'schema': SCHEMA, 'base': m.resources.BASE, 'apiIdentifier': PINNED,
            'roleApiVersion': 'v2',
            'tenantIdsSha256': digest({b: ctx[0]['tenants'][b]['tenantId'] for b in ('aurora','brisa')}),
            'clientIdsSha256': digest({b: {c: ctx[1]['tenants'][b]['clients'][c]['id'] for c in ('web','app')}
                                       for b in ('aurora','brisa')}),
            'roles': {}}


def read_journal(m, ctx):
    target = m.resources.ROOT / 'private' / JOURNAL_NAME
    data = m.resources.private_read(target, False)
    expected = initial_journal(m, ctx)
    if data is None:
        return expected
    need(isinstance(data, dict), 'INVALID_JOURNAL')
    for field in expected:
        if field == 'roles':
            continue
        need(data.get(field) == expected[field], 'JOURNAL_CONTEXT_DRIFT_' + field)
    role_entries = data.get('roles')
    need(isinstance(role_entries, dict) and set(role_entries).issubset(set(ROLE_KEYS)),
         'JOURNAL_ROLE_SET_DRIFT')
    for key, node in role_entries.items():
        need(isinstance(node,dict) and node.get('state') in ('patch-started', 'verified') and
             isinstance(node.get('roleIdSha256'),str), 'INVALID_JOURNAL_ROLE_STATE_' + key)
    return data


def build_plan(m, client, ctx, journal):
    roles = {}
    for brand in ('aurora','brisa'):
        for channel in ('app','web'):
            key = brand + ':' + channel
            roles[key] = read_role(m, client, ctx, brand, channel)
    group_summary = {}
    for brand in ('aurora','brisa'):
        group_summary[brand] = group_proof(m, client, ctx, brand,
                                          {roles[brand + ':' + c]['roleId'] for c in ('app','web')})
    actionable = []
    clean = []
    for key in ROLE_KEYS:
        role = roles[key]
        node = journal['roles'].get(key)
        if node:
            need(node['roleIdSha256'] == role['roleIdSha256'], 'ROLE_JOURNAL_ID_DRIFT_' + key)
            need(node.get('memberSha256') == role['membersSha256'], 'ROLE_JOURNAL_MEMBERSHIP_DRIFT_' + key)
            need(node.get('groupProofSha256') == group_summary[key.split(':')[0]]['fingerprint'],
                 'GROUP_PROOF_CHANGED_' + key)
            need(node['state'] == 'verified', 'UNCERTAIN_PREVIOUS_PATCH_MANUAL_RECONCILIATION_REQUIRED_' + key)
            need(role['permissions'] == AFTER, 'VERIFIED_ROLE_SCOPE_DRIFT_' + key)
            clean.append(key)
        else:
            need(role['permissions'] == BEFORE, 'UNJOURNALED_ROLE_CHANGED_' + key)
            actionable.append(key)
    output_roles = {key: {
        'roleName': roles[key]['name'],
        'roleIdSha256': roles[key]['roleIdSha256'],
        'preconditionSha256': roles[key]['snapshotSha256'],
        'etagPresent': bool(roles[key]['etag']),
        'groupStatus': roles[key]['groupStatus'],
        'permissions': sorted(roles[key]['permissions']),
        'state': 'READY_TO_REMOVE_APPROVE' if key in actionable else 'JOURNALED_VERIFIED',
    } for key in ROLE_KEYS}
    plan = {'stage': 'CIAM_V10_ADMIN_APPROVE_EXACT_PATCH_V1',
            'apiIdentifier': PINNED, 'roleApiVersion': 'v2',
            'roles': output_roles,
            'groupProof': {b: {'groupsEnumerated': v['count'],
                                'snapshotSha256': v['fingerprint'],
                                'adminCaseRoleGroupReferences': 0} for b,v in group_summary.items()},
            'pending': actionable, 'verified': clean, 'remoteWrites': 0,
            'mutationLimitPerInvocation': 1,
            'writeMethod': 'PATCH', 'change': 'REMOVE_ONLY_ciam:cases:approve',
            'conditionalUpdateEnforcement': 'NOT_INDEPENDENTLY_VERIFIED',
            'status': 'READY_FOR_EXPLICIT_ONE_ROLE_APPROVAL' if actionable else 'ALL_FOUR_ROLES_READBACK_VERIFIED'}
    plan['planSha256'] = digest(plan)
    return plan, roles, group_summary


def prepare_private(m):
    folder = m.resources.ROOT / 'private'
    need(folder.is_dir() and not folder.is_symlink() and
         folder.stat().st_uid == os.getuid() and
         not (stat.S_IMODE(folder.stat().st_mode) & 0o077), 'PRIVATE_DIR_PERMISSIONS_UNSAFE')
    return folder


class Lock:
    def __init__(self, folder):
        self.folder = folder
        self.path = folder / LOCK_NAME
        self.fd = None
    def __enter__(self):
        need(not self.path.is_symlink(), 'LOCK_SYMLINK_REFUSED')
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise Refuse('EXISTING_LOCK_REQUIRES_MANUAL_REVIEW')
        os.write(self.fd, str(os.getpid()).encode())
        os.fsync(self.fd)
        return self
    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            os.close(self.fd)
            self.path.unlink()


def save(m, state):
    m.resources.atomic_save(m.resources.ROOT / 'private' / JOURNAL_NAME, state)


def approved_patch(m, client, ctx, journal, key, observed, proof):
    role = observed[key]
    need(role['permissions'] == BEFORE, 'ROLE_NOT_IN_EXPECTED_BEFORE_STATE')
    brand = key.split(':')[0]
    node = {'state': 'patch-started', 'roleIdSha256': role['roleIdSha256'],
            'memberSha256': role['membersSha256'],
            'groupProofSha256': proof[brand]['fingerprint'],
            'beforeSha256': role['snapshotSha256'],
            'startedAtUtc': datetime.now(timezone.utc).isoformat(),
            'operation': 'REMOVE_ONLY_ciam:cases:approve',
            'etagWasProvided': bool(role['etag'])}
    need(key not in journal['roles'], 'NO_RETRY_FOR_ATTEMPTED_ROLE')
    journal['roles'][key] = node
    # Write-ahead journal before sending the PATCH. This is intentional:
    # a network failure will block ALL automatic attempts to this role.
    save(m, journal)
    try:
        code, _, _ = client.request('PATCH', role['path'], auth=role['auth'],
                                    data=patch_payload(), etag=role['etag'])
        need(code == 200 or code == 204, 'PATCH_OUTCOME_UNCERTAIN_RECONCILE_MANUALLY')
        after = read_role(m, client, ctx, brand, key.split(':')[1])
        need(after['roleIdSha256'] == node['roleIdSha256'] and
             after['membersSha256'] == node['memberSha256'] and
             after['permissions'] == AFTER,
             'POST_PATCH_READBACK_UNCERTAIN_MANUAL_REVIEW')
        again = group_proof(m, client, ctx, brand,
                           {read_role(m, client, ctx, brand, c)['roleId'] for c in ('app','web')})
        need(again['fingerprint'] == node['groupProofSha256'], 'POST_PATCH_GROUP_READBACK_DRIFT')
        node['state'] = 'verified'
        node['afterSha256'] = after['snapshotSha256']
        node['verifiedAtUtc'] = datetime.now(timezone.utc).isoformat()
        save(m, journal)
    except Exception:
        # Intentional: no rollback, no automatic retry. Journal remains started.
        raise Refuse('PATCH_OUTCOME_OR_POST_READBACK_UNCERTAIN_STOP_NO_RETRY')
    return {'status': 'ROLE_APPROVE_PERMISSION_REMOVED_AND_READBACK_VERIFIED',
            'role': key, 'remoteWrites': 1, 'readback': 'EXACT_PERMISSIONS_AND_DIRECT_MEMBERSHIP',
            'localGroupProof': 'UNCHANGED', 'journal': 'PRIVATE_WRITE_AHEAD_VERIFIED'}


def execute(argv=None, *, stage=None, client=None, ctx=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan','apply','verify'))
    parser.add_argument('--role', choices=ROLE_KEYS)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--confirm')
    parser.add_argument('--allow-no-etag', action='store_true')
    args = parser.parse_args(argv)
    need(os.getenv('WSO2_CIAM_CASES_API_IDENTIFIER') == PINNED,
         'PINNED_CASES_API_IDENTIFIER_REQUIRED')
    m = stage if stage is not None else load_stage()
    c = ctx if ctx is not None else m.context()
    need(c[5] == 'v2', 'JOURNAL_ROLE_VERSION_NOT_V2')
    if client is None:
        client = Transport(m)
    if args.command != 'apply':
        need(not any((args.role, args.plan_sha256, args.confirm, args.allow_no_etag)),
             'PLAN_VERIFY_NO_MUTATION_ARGUMENTS')
        plan, _, _ = build_plan(m, client, c, read_journal(m,c))
        if args.command == 'verify':
            need(not plan['pending'], 'VERIFICATION_REQUIRES_ALL_FOUR_ROLES_COMPLETE')
        print(json.dumps(plan, indent=2, sort_keys=True))
        return plan
    need(args.role in ROLE_KEYS and args.confirm == CONFIRM and
         isinstance(args.plan_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', args.plan_sha256),
         'EXPLICIT_ROLE_PLAN_HASH_AND_CONFIRMATION_REQUIRED')
    folder = prepare_private(m)
    with Lock(folder):
        journal = read_journal(m,c)
        plan, roles, proof = build_plan(m,client,c,journal)
        need(args.plan_sha256 == plan['planSha256'], 'FRESH_PLAN_HASH_MISMATCH')
        need(args.role in plan['pending'], 'ROLE_NOT_PENDING_OR_ALREADY_ATTEMPTED')
        need(roles[args.role]['etag'] is not None or args.allow_no_etag,
             'NO_ETAG_REQUIRES_EXPLICIT_NONATOMIC_ACKNOWLEDGEMENT')
        # Pre-write second read of the role and local group references.
        brand, channel = args.role.split(':')
        fresh = read_role(m, client, c, brand, channel)
        need(fresh['snapshotSha256'] == roles[args.role]['snapshotSha256'] and
             fresh['etag'] == roles[args.role]['etag'], 'PRE_PATCH_ROLE_CHANGED')
        newer = group_proof(m, client, c, brand,
                            {roles[brand + ':' + v]['roleId'] for v in ('app','web')})
        need(newer['fingerprint'] == proof[brand]['fingerprint'], 'PRE_PATCH_GROUP_CHANGED')
        result = approved_patch(m, client, c, journal, args.role, roles, proof)
        print(json.dumps(result, indent=2, sort_keys=True))
        return result


def main():
    try:
        execute()
    except Refuse as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        raise SystemExit(2)
    except Exception:
        # Do not reveal transport exceptions, passwords or request headers.
        print('REFUSED: UNEXPECTED_ERROR_NO_AUTOMATIC_RETRY', file=sys.stderr)
        raise SystemExit(2)


if __name__ == '__main__':
    main()
