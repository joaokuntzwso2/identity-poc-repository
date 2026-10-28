#!/usr/bin/env python3
"""Guarded, additive WSO2 IS 7.3 cases API/application-role provisioning.

NO modifications to existing journals, users, OIDC clients or profile roles.
All remote writes require explicit confirmation, a matched plan hash, and a
private write-ahead journal; uncertain writes are NEVER retried automatically.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse
import secrets

HERE = Path(__file__).resolve().parent
RESOURCE_FILE = HERE.parent / 'resources/bootstrap.py'
spec = importlib.util.spec_from_file_location('ciam_cases_resource_v10', RESOURCE_FILE)
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)
Refuse = resources.Refuse
DOMAINS = resources.DOMAINS
PRIVATE = resources.ROOT / 'private'
TENANT_FILE = resources.TENANT_FILE
OIDC_FILE = PRIVATE / 'bootstrap-oidc-v10.private.json'
AUTHORITY_FILE = PRIVATE / 'bootstrap-authority-v10.private.json'
IDENTITIES_FILE = PRIVATE / 'bootstrap-identities-v10.private.json'
SEED_FILE = HERE.parent / 'identities/seed.json'
JOURNAL = PRIVATE / 'bootstrap-cases-rbac-v10.private.json'
LOCK = PRIVATE / 'bootstrap-cases-rbac-v10.lock'
API_NAME = 'CIAM v10 Cases API'
SCOPE_DESCRIPTIONS = {
    'ciam:cases:create': 'Create customer cases',
    'ciam:cases:read': 'Read permitted customer cases',
    'ciam:cases:review': 'Review permitted brand cases',
    'ciam:cases:approve': 'Approve brand cases after verified MFA',
}
SCOPES = tuple(SCOPE_DESCRIPTIONS)
CUSTOMER_SCOPES = ('ciam:cases:create', 'ciam:cases:read')
SELLER_SCOPES = ('ciam:cases:read', 'ciam:cases:review', 'ciam:cases:approve')
CONFIRM_VALUE = 'CREATE_JOURNALED_V10_CASES_RESOURCES_AND_APP_ROLES'
ROLE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:2.0:Role'
HEX64 = re.compile(r'^[a-f0-9]{64}$')


def require(condition, code):
    if not condition:
        raise Refuse(code)


def case_identifier():
    value = os.getenv('WSO2_CIAM_CASES_API_IDENTIFIER', '')
    # This precise URN is the existing BFF's verified API audience. Do not
    # generalize this exception to arbitrary URNs or change the running BFF.
    if value == 'urn:ciampoc:service-requests:v1':
        return value
    parsed = urllib.parse.urlsplit(value)
    require(value and len(value) <= 512 and value == value.strip() and
            parsed.scheme == 'https' and parsed.hostname and
            not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            'EXPLICIT_HTTPS_OR_PINNED_CASE_API_IDENTIFIER_REQUIRED')
    return value


def role_name(channel, kind):
    return f'CIAM v10 Cases {kind.title()} {channel.upper()}'


def path(brand, resource):
    return '/t/' + DOMAINS[brand] + resource


def read(client, p, auth):
    status, body, _ = client.call('GET', p, auth=auth)
    require(status == 200 and isinstance(body, (dict, list)), 'GET_FAILED_HTTP_' + str(status))
    return body


def list_items(body, *names):
    return resources.collection(body, names)


def exact_resource(client, brand, auth, identifier):
    root = path(brand, '/api/server/v1/api-resources')
    query = urllib.parse.urlencode({'filter': 'identifier eq ' + identifier, 'limit': '100'})
    doc = read(client, root + '?' + query, auth)
    rows = list_items(doc, 'APIResources', 'apiResources', 'resources', 'list')
    require(isinstance(doc, dict) and not (isinstance(doc.get('totalResults'), int) and doc['totalResults'] > len(rows))
            and not any(isinstance(link, dict) and link.get('rel') in ('next', 'after')
                            for link in doc.get('links', [])), 'UNSAFE_RESOURCE_PAGINATION')
    found = [x for x in rows if isinstance(x, dict) and x.get('identifier') == identifier]
    require(len(found) <= 1, 'DUPLICATE_CASE_RESOURCE')
    return found[0] if found else None


def exact_role(client, brand, auth, version, name):
    root = path(brand, f'/scim2/{version}/Roles')
    q = urllib.parse.urlencode({'filter': 'displayName eq "' + name + '"', 'count': '100', 'startIndex': '1'})
    doc = read(client, root + '?' + q, auth)
    rows = list_items(doc, 'Resources', 'resources')
    require(not (isinstance(doc, dict) and isinstance(doc.get('totalResults'), int) and doc['totalResults'] > len(rows)),
            'UNSAFE_ROLE_PAGINATION')
    found = [x for x in rows if isinstance(x, dict) and x.get('displayName') == name]
    require(len(found) <= 1, 'DUPLICATE_CASE_ROLE')
    return found[0] if found else None


def context():
    ts = resources.private_read(TENANT_FILE)
    oidc = resources.private_read(OIDC_FILE)
    authority = resources.private_read(AUTHORITY_FILE)
    identities = resources.private_read(IDENTITIES_FILE)
    seed = json.loads(SEED_FILE.read_text())
    require(ts.get('schema') == 'identity.wso2.ciam.v10.tenants' and ts.get('domains') == DOMAINS and
            ts.get('base') == resources.BASE, 'TENANT_JOURNAL_INVALID')
    require(oidc.get('schema') == 'identity.wso2.ciam.v10.oidc.v1', 'OIDC_JOURNAL_INVALID')
    require(authority.get('acceptance') == 'API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED',
            'PROFILE_AUTHORITY_NOT_VERIFIED')
    version = authority.get('roleApiVersion')
    require(version in ('v2', 'v3') and identities.get('roleApiVersion') == version,
            'ROLE_API_VERSION_NOT_JOURNAL_PINNED')
    require(identities.get('schema') == 'identity.wso2.ciam.v10.real-people.v1' and
            identities.get('seedHash') == hashlib.sha256(SEED_FILE.read_bytes()).hexdigest(),
            'IDENTITY_JOURNAL_OR_SEED_DRIFT')
    require(seed.get('implementedPermissionAssignments') == {'customer': ['ciam:profile:read']},
            'ORIGINAL_IDENTITY_SEED_CHANGED')
    for brand, domain in DOMAINS.items():
        t = ts['tenants'][brand]
        require(t.get('domain') == domain and t.get('status') == 'readback-verified' and
                t.get('owner', {}).get('username') == resources.OWNER and
                t.get('owner', {}).get('password'), 'TENANT_NOT_VERIFIED_' + brand)
        require(identities.get('tenants', {}).get(brand, {}).get('tenantId') == t['tenantId'] and
                oidc.get('tenants', {}).get(brand, {}).get('tenantId') == t['tenantId'],
                'TENANT_ID_DRIFT_' + brand)
        for channel in ('web', 'app'):
            app = oidc['tenants'][brand]['clients'][channel]
            require(app.get('state') == 'verified' and resources.ID.fullmatch(str(app.get('id', ''))),
                    'OIDC_APP_NOT_VERIFIED_' + brand + '_' + channel)
        for person in seed['people']:
            if brand in person['brands'] and person['type'] in ('customer', 'seller'):
                node = identities['tenants'][brand].get('users', {}).get(person['key'], {})
                require(node.get('state') == 'verified' and node.get('username') == person['username']
                        and resources.ID.fullmatch(str(node.get('id', ''))),
                        'EXPECTED_SCIM_USER_NOT_VERIFIED_' + person['key'])
    return ts, oidc, authority, identities, seed, version


def memberships(identities, seed, brand, kind):
    return sorted(identities['tenants'][brand]['users'][p['key']]['id'] for p in seed['people']
                  if brand in p['brands'] and p['type'] == kind)


def expected_journal(ts, oidc, version, identifier):
    return {'schema': 'identity.wso2.ciam.v10.cases-rbac.v1', 'base': resources.BASE,
            'apiIdentifier': identifier, 'roleApiVersion': version,
            'tenants': {b: {'domain': domain, 'tenantId': ts['tenants'][b]['tenantId'],
                            'apps': {c: oidc['tenants'][b]['clients'][c]['id'] for c in ('web', 'app')},
                            'resource': None, 'authorizations': {}, 'roles': {}}
                        for b, domain in DOMAINS.items()}}


def load_journal(expected):
    stored = resources.private_read(JOURNAL, False)
    if stored is None:
        return expected
    for key in ('schema', 'base', 'apiIdentifier', 'roleApiVersion'):
        require(stored.get(key) == expected[key], 'CASE_JOURNAL_CONTEXT_DRIFT_' + key)
    for brand in DOMAINS:
        for key in ('domain', 'tenantId', 'apps'):
            require(stored.get('tenants', {}).get(brand, {}).get(key) == expected['tenants'][brand][key],
                    'CASE_JOURNAL_TENANT_DRIFT_' + brand + '_' + key)
    return stored


def role_specs(oidc, identities, seed, brand):
    for channel in ('web', 'app'):
        appid = oidc['tenants'][brand]['clients'][channel]['id']
        for kind, perms in (('customer', CUSTOMER_SCOPES), ('seller', SELLER_SCOPES)):
            users = memberships(identities, seed, brand, kind)
            if not users:
                continue
            yield channel, kind, appid, role_name(channel, kind), users, tuple(perms)


def verify_resource(client, brand, auth, item, node, identifier):
    require(node and node.get('state') in ('verified', 'post-started') and
            re.fullmatch(r'ciam-v10-cases-[a-f0-9]{32}', node.get('ownerMarker', '')),
            'UNJOURNALED_CASE_RESOURCE_COLLISION_' + brand)
    rid = item.get('id')
    require(resources.ID.fullmatch(str(rid)), 'RESOURCE_ID_INVALID')
    detail = read(client, path(brand, '/api/server/v1/api-resources/' + rid), auth)
    scopes = read(client, path(brand, '/api/server/v1/api-resources/' + rid + '/scopes'), auth)
    names = set(x if isinstance(x, str) else x.get('name') for x in list_items(scopes, 'scopes'))
    require(detail.get('id') == rid and detail.get('identifier') == identifier and
            detail.get('name') == API_NAME and detail.get('description') == node['ownerMarker'] and
            detail.get('requiresAuthorization') is True and names == set(SCOPES) and
            (not node.get('id') or node['id'] == rid), 'CASE_RESOURCE_READBACK_DRIFT_' + brand)
    return rid


def verify_role(client, brand, auth, version, item, node, name, appid, users, perms):
    require(node and node.get('state') in ('verified', 'post-started'), 'UNJOURNALED_CASE_ROLE_COLLISION')
    rid = item.get('id')
    require(resources.ID.fullmatch(str(rid)), 'ROLE_ID_INVALID')
    detail = read(client, path(brand, '/scim2/' + version + '/Roles/' + rid), auth)
    actual_users = {v.get('value') for v in detail.get('users', []) if isinstance(v, dict)}
    actual_perms = {v.get('value') for v in detail.get('permissions', []) if isinstance(v, dict)}
    aud = detail.get('audience') or {}
    require(detail.get('id') == rid and detail.get('displayName') == name and
            aud.get('type') == 'application' and aud.get('value') == appid and
            actual_users == set(users) and actual_perms == set(perms) and
            (not node.get('id') or node['id'] == rid), 'CASE_ROLE_READBACK_DRIFT_' + name)
    return rid


def read_authorization(client, brand, auth, appid, rid):
    data = read(client, path(brand, '/api/server/v1/applications/' + appid + '/authorized-apis'), auth)
    rows = list_items(data, 'authorizedAPIs', 'authorizedApis', 'apis', 'resources', 'list')
    found = [x for x in rows if isinstance(x, dict) and x.get('id') == rid]
    require(len(found) <= 1, 'DUPLICATE_CASE_APP_AUTHORIZATION')
    return found[0] if found else None


def permission_list(row):
    return resources.scope_names(row)


def examine(client, context_data, journal, identifier):
    ts, oidc, authority, identities, seed, version = context_data
    actions = []
    counts = {}
    for brand in DOMAINS:
        auth = resources.basic(resources.OWNER + '@' + DOMAINS[brand],
                               ts['tenants'][brand]['owner']['password'])
        j = journal['tenants'][brand]
        item = exact_resource(client, brand, auth, identifier)
        node = j.get('resource')
        if item:
            rid = verify_resource(client, brand, auth, item, node, identifier)
            require(node['state'] == 'verified', 'CASE_RESOURCE_UNCERTAIN_RECONCILE_REQUIRED')
        else:
            require(not node or node.get('state') == 'prepared', 'CASE_RESOURCE_MISSING_AFTER_POST')
            rid = None
            actions.append([brand, 'create_api_resource'])
        for channel in ('web', 'app'):
            appid = oidc['tenants'][brand]['clients'][channel]['id']
            app = read(client, path(brand, '/api/server/v1/applications/' + appid), auth)
            require(app.get('id') == appid and
                    app.get('name') == oidc['tenants'][brand]['clients'][channel]['name'] and
                    (app.get('associatedRoles') or {}).get('allowedAudience') == 'APPLICATION',
                    'OIDC_APP_AUDIENCE_OR_ID_DRIFT_' + brand + '_' + channel)
            a = j.get('authorizations', {}).get(channel)
            if rid:
                found = read_authorization(client, brand, auth, appid, rid)
                if found:
                    require(a and a.get('state') == 'verified' and
                            permission_list(found) == set(SCOPES), 'CASE_APP_GRANT_COLLISION_OR_DRIFT')
                else:
                    require(not a or a.get('state') == 'prepared', 'CASE_APP_GRANT_MISSING_AFTER_POST')
                    actions.append([brand, channel, 'authorize_case_api'])
            else:
                require(not a or a.get('state') == 'prepared', 'CASE_APP_GRANT_BEFORE_API')
                actions.append([brand, channel, 'authorize_case_api'])
        for channel, kind, appid, name, users, perms in role_specs(oidc, identities, seed, brand):
            # Cross-check actual SCIM membership and deny missing/inactive identities.
            for uid in users:
                person = read(client, path(brand, '/scim2/Users/' + uid), auth)
                require(person.get('id') == uid and person.get('active') is not False,
                        'CASE_ROLE_USER_NOT_ACTIVE_' + brand)
            existing = exact_role(client, brand, auth, version, name)
            node = j.get('roles', {}).get(channel + ':' + kind)
            if existing:
                verify_role(client, brand, auth, version, existing, node, name, appid, users, perms)
                require(node['state'] == 'verified', 'CASE_ROLE_UNCERTAIN_RECONCILE_REQUIRED')
            else:
                require(not node or node.get('state') == 'prepared', 'CASE_ROLE_MISSING_AFTER_POST')
                actions.append([brand, channel, kind, 'create_app_role'])
        counts[brand] = {'channels': 2, 'customerUserCount': len(memberships(identities, seed, brand, 'customer')),
                         'sellerUserCount': len(memberships(identities, seed, brand, 'seller'))}
    return {'stage': 'CIAM_V10_CASES_RBAC_V1', 'remoteWrites': 0, 'roleApiVersion': version,
            'apiIdentifier': identifier, 'plannedActions': actions, 'perTenant': counts,
            'runtimeAuthentication': 'NOT_VERIFIED'}


def plan_hash(plan):
    # Exact authorized operations must be the same between plan and apply.
    payload = json.dumps(plan, sort_keys=True, separators=(',', ':')).encode('utf8')
    return hashlib.sha256(payload).hexdigest()


def save(state):
    resources.atomic_save(JOURNAL, state)


def create_with_readback(client, brand, auth, node, root, payload, checker):
    require(node.get('state') == 'prepared', 'UNCERTAIN_OR_ALREADY_ATTEMPTED_WRITE_NO_RETRY')
    node['state'] = 'post-started'; save(_JOURNAL_HOLDER[0])
    status, _, _ = client.call('POST', path(brand, root), auth=auth, data=payload)
    require(status in (200, 201), 'CASE_POST_UNCERTAIN_HTTP_' + str(status) + '_NO_RETRY')
    result = checker()
    require(result, 'CASE_POST_READBACK_UNCERTAIN_NO_RETRY')
    node['id'] = result
    node['state'] = 'verified'; save(_JOURNAL_HOLDER[0])
    return result

_JOURNAL_HOLDER = [None]


def apply(client, context_data, journal, identifier, before):
    ts, oidc, authority, identities, seed, version = context_data
    _JOURNAL_HOLDER[0] = journal
    for brand in DOMAINS:
        j = journal['tenants'][brand]
        auth = resources.basic(resources.OWNER + '@' + DOMAINS[brand],
                               ts['tenants'][brand]['owner']['password'])
        item = exact_resource(client, brand, auth, identifier)
        if not item:
            node = j.get('resource')
            if node is None:
                node = {'state': 'prepared', 'ownerMarker': 'ciam-v10-cases-' + secrets.token_hex(16)}
                j['resource'] = node; save(journal)
            def checked_resource():
                remote = exact_resource(client, brand, auth, identifier)
                return verify_resource(client, brand, auth, remote, node, identifier) if remote else None
            rid = create_with_readback(client, brand, auth, node, '/api/server/v1/api-resources',
                {'name': API_NAME, 'identifier': identifier, 'description': node['ownerMarker'],
                 'requiresAuthorization': True,
                 'scopes': [{'name': s, 'displayName': SCOPE_DESCRIPTIONS[s],
                             'description': SCOPE_DESCRIPTIONS[s]} for s in SCOPES]}, checked_resource)
        else:
            rid = verify_resource(client, brand, auth, item, j['resource'], identifier)
        for channel in ('web', 'app'):
            appid = oidc['tenants'][brand]['clients'][channel]['id']
            existing = read_authorization(client, brand, auth, appid, rid)
            if existing:
                require(permission_list(existing) == set(SCOPES), 'APP_GRANT_DRIFT')
                continue
            n = j.setdefault('authorizations', {}).setdefault(channel, {'state': 'prepared'})
            require(n['state'] == 'prepared', 'UNCERTAIN_APP_GRANT_NO_RETRY')
            n['state'] = 'post-started'; save(journal)
            status, _, _ = client.call('POST', path(brand, '/api/server/v1/applications/' + appid + '/authorized-apis'),
                                        auth=auth, data={'id': rid, 'policyIdentifier': 'RBAC', 'scopes': list(SCOPES)})
            require(status in (200, 201), 'CASE_AUTH_POST_UNCERTAIN_HTTP_' + str(status))
            confirmed = read_authorization(client, brand, auth, appid, rid)
            require(confirmed and permission_list(confirmed) == set(SCOPES), 'CASE_AUTH_READBACK_UNCERTAIN_NO_RETRY')
            n['state'] = 'verified'; save(journal)
        for channel, kind, appid, name, users, perms in role_specs(oidc, identities, seed, brand):
            existing = exact_role(client, brand, auth, version, name)
            if existing:
                verify_role(client, brand, auth, version, existing, j['roles'][channel+':'+kind],
                            name, appid, users, perms)
                continue
            n = j.setdefault('roles', {}).setdefault(channel+':'+kind, {'state': 'prepared', 'appId': appid, 'name': name})
            require(n.get('appId') == appid and n.get('name') == name, 'ROLE_JOURNAL_DRIFT')
            def checked_role():
                remote = exact_role(client, brand, auth, version, name)
                return verify_role(client, brand, auth, version, remote, n, name, appid, users, perms) if remote else None
            create_with_readback(client, brand, auth, n, '/scim2/' + version + '/Roles',
                {'schemas': [ROLE_SCHEMA], 'displayName': name,
                 'audience': {'value': appid, 'type': 'application'},
                 'permissions': [{'value': s} for s in perms],
                 'users': [{'value': u} for u in users]}, checked_role)
    # All readback conditions are rechecked without further writes.
    after = examine(client, context_data, journal, identifier)
    require(not after['plannedActions'], 'FINAL_RBAC_INCOMPLETE')
    return {'mode': 'APPLY', 'state': 'ALL_REMOTE_READBACKS_VERIFIED_NOT_BROWSER_VERIFIED', 'tenants': list(DOMAINS)}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['plan', 'apply', 'verify'])
    parser.add_argument('--plan-sha256', default='')
    args = parser.parse_args(argv)
    identifier = case_identifier()
    context_data = context()
    ts, oidc, authority, identities, seed, version = context_data
    expected = expected_journal(ts, oidc, version, identifier)
    journal = load_journal(expected)
    client = resources.HTTPS()
    plan = examine(client, context_data, journal, identifier)
    digest = plan_hash(plan)
    if args.mode == 'plan':
        print(json.dumps({**plan, 'planSha256': digest, 'mode': 'READ_ONLY'}, indent=2))
        return 0
    if args.mode == 'verify':
        require(not plan['plannedActions'], 'CASES_RBAC_NOT_FULLY_VERIFIED')
        print(json.dumps({'mode': 'VERIFY', 'status': 'READBACK_VERIFIED_NOT_BROWSER_TESTED',
                          'apiIdentifier': identifier, 'roleApiVersion': version}, indent=2))
        return 0
    require(os.getenv('WSO2_CIAM_CASES_CONFIRM') == CONFIRM_VALUE and
            HEX64.fullmatch(args.plan_sha256) and args.plan_sha256 == digest,
            'EXPLICIT_CONFIRMATION_AND_EXACT_PLAN_HASH_REQUIRED')
    if version == 'v2':
        require(os.getenv('WSO2_CIAM_V10_ROLE_V2_CONFIRM') ==
                'USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES',
                'V2_ROLE_API_NEEDS_SEPARATE_CONFIRMATION')
    fd = None
    try:
        require(not LOCK.exists() and not LOCK.is_symlink(), 'EXISTING_CASES_BOOTSTRAP_LOCK')
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, str(os.getpid()).encode())
        if not JOURNAL.exists():
            save(journal)
        print(json.dumps(apply(client, context_data, journal, identifier, plan), indent=2))
    finally:
        if fd is not None:
            os.close(fd)
            LOCK.unlink()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Refuse, OSError, ValueError, KeyError, TypeError) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        sys.exit(2)
