#!/usr/bin/env python3
"""WSO2 IS 7.3: role-only provisioning using pre-existing verified Cases APIs.

Does not adopt, create, update or delete API resources, applications, API
access grants, identities or profile roles. Role POST requires exact plan hash,
operator confirmation, private write-ahead journal, and journal-pinned Role API.
Uncertain POST outcomes block automatic retries. No live writes in plan/verify.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ciam_cases_existing_stage', HERE / 'bootstrap.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
Refuse = stage.Refuse

IDENTIFIER = 'urn:ciampoc:service-requests:v1'
# This is the observed name of the *existing* legacy API, not the different
# name the earlier create-resource stage was going to use.
RESOURCE_NAME = 'CIAM Service Requests API'
JOURNAL = stage.PRIVATE / 'bootstrap-cases-existing-roles-v10.private.json'
LOCK = stage.PRIVATE / 'bootstrap-cases-existing-roles-v10.lock'
SCHEMA = 'identity.wso2.ciam.v10.cases-existing-roles.v1'
CONFIRM = 'CREATE_ONLY_SIX_CASE_APPLICATION_ROLES_NO_RESOURCE_CHANGES'
ROLE_V2_CONFIRM = 'USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES'
ROLE_SCHEMA = stage.ROLE_SCHEMA


def require(condition, code):
    if not condition:
        raise Refuse(code)


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def check_identifier():
    require(os.environ.get('WSO2_CIAM_CASES_API_IDENTIFIER') == IDENTIFIER,
            'PINNED_EXISTING_CASES_IDENTIFIER_REQUIRED')
    return IDENTIFIER


class LimitedClient:
    """GET-only during inspection; apply additionally allows ONLY SCIM Roles POST."""
    def __init__(self, actual, role_version, allow_posts=False):
        self.actual = actual
        self.version = role_version
        self.allow_posts = allow_posts
        self.get_count = 0
        self.post_count = 0

    def call(self, method, path, *, auth, data=None, form=None):
        if method == 'GET' and data is None and form is None:
            self.get_count += 1
        elif (method == 'POST' and self.allow_posts and form is None and
              re.fullmatch(r'/t/(?:aurora\.identity\.test|brisa\.identity\.test)/scim2/' + self.version + r'/Roles', path) and
              isinstance(data, dict) and data.get('schemas') == [ROLE_SCHEMA] and
              isinstance(data.get('audience'), dict) and data['audience'].get('type') == 'application'):
            self.post_count += 1
        else:
            raise Refuse('ROLE_ONLY_STAGE_FORBIDS_NON_ROLE_MUTATION')
        return self.actual.call(method, path, auth=auth, data=data, form=form)


def load_existing():
    stored = stage.resources.private_read(JOURNAL, False)
    require(stored is None or isinstance(stored, dict), 'INVALID_ROLE_ONLY_JOURNAL')
    return stored


def expected_context(ctx, resource_ids):
    ts, oidc, authority, identities, seed, version = ctx
    return {'schema': SCHEMA, 'base': stage.resources.BASE,
            'apiIdentifier': IDENTIFIER, 'roleApiVersion': version,
            'tenants': {brand: {'domain': domain, 'tenantId': ts['tenants'][brand]['tenantId'],
                                'externalResourceId': resource_ids[brand],
                                'apps': {c: oidc['tenants'][brand]['clients'][c]['id'] for c in ('web', 'app')},
                                'roles': {}}
                        for brand, domain in stage.DOMAINS.items()}}


def validate_journal(stored, expected):
    if stored is None:
        return expected
    for k in ('schema', 'base', 'apiIdentifier', 'roleApiVersion'):
        require(stored.get(k) == expected[k], 'ROLE_ONLY_JOURNAL_DRIFT_' + k)
    require(set(stored.get('tenants', {})) == set(expected['tenants']), 'ROLE_ONLY_TENANT_SET_DRIFT')
    for brand in stage.DOMAINS:
        for k in ('domain', 'tenantId', 'externalResourceId', 'apps'):
            require(stored['tenants'][brand].get(k) == expected['tenants'][brand][k],
                    'ROLE_ONLY_JOURNAL_DRIFT_' + brand + '_' + k)
        require(isinstance(stored['tenants'][brand].get('roles'), dict), 'INVALID_ROLE_JOURNAL_ROLES')
        # Reject unexpected journal-owned role names, without relying on a
        # remote response to silently expand the stage's ownership.
        permitted = {'web:customer', 'web:seller', 'app:customer', 'app:seller'}
        require(set(stored['tenants'][brand]['roles']).issubset(permitted), 'UNEXPECTED_JOURNALED_ROLE_KEY')
    return stored


def verify_no_unowned_case_permission_roles(client, brand, auth, version, owned_roles):
    """Exhaustive role readback: existing grants outside our roles block writes.

    A missing intended role name does not mean another application/org role
    cannot already grant ciam:cases:*; check every role, not merely our six.
    """
    root = stage.path(brand, '/scim2/' + version + '/Roles')
    found_ids = set()
    start = 1
    total = None
    for _ in range(50):
        query = urllib.parse.urlencode({'startIndex': str(start), 'count': '100'})
        doc = stage.read(client, root + '?' + query, auth)
        require(isinstance(doc, dict) and isinstance(doc.get('totalResults'), int)
                and 0 <= doc['totalResults'] <= 5000, 'ROLE_LIST_TOTAL_NOT_ATTESTED')
        if total is None:
            total = doc['totalResults']
        require(total == doc['totalResults'], 'ROLE_LIST_CHANGED_DURING_SCAN')
        rows = stage.list_items(doc, 'Resources', 'resources')
        require(isinstance(rows, list) and len(rows) <= 100, 'ROLE_PAGE_INVALID')
        if len(found_ids) < total:
            require(rows, 'ROLE_PAGE_EMPTY_BEFORE_TOTAL')
        for row in rows:
            rid = row.get('id') if isinstance(row, dict) else None
            require(stage.resources.ID.fullmatch(str(rid)) and rid not in found_ids,
                    'ROLE_LIST_DUPLICATE_OR_BAD_ID')
            found_ids.add(rid)
            detail = stage.read(client, root + '/' + rid, auth)
            require(detail.get('id') == rid and isinstance(detail.get('permissions'), list),
                    'ROLE_PERMISSION_READBACK_INCOMPLETE')
            perms = {v.get('value') for v in detail['permissions'] if isinstance(v, dict)}
            if perms & set(stage.SCOPES):
                require(rid in owned_roles, 'UNOWNED_CASE_SCOPE_ROLE_PRESENT_' + brand)
        if len(found_ids) == total:
            return
        require(len(found_ids) < total, 'ROLE_LIST_COUNT_OVERFLOW')
        start = 1 + len(found_ids)
    raise Refuse('ROLE_LIST_PAGINATION_LIMIT')


def inventory(client, ctx, stored):
    """All GETs. Prove external dependencies without taking ownership."""
    ts, oidc, authority, identities, seed, version = ctx
    external_ids = {}
    verified_policy_fields = {}
    for brand in stage.DOMAINS:
        auth = stage.resources.basic(stage.resources.OWNER + '@' + stage.DOMAINS[brand],
                                     ts['tenants'][brand]['owner']['password'])
        row = stage.exact_resource(client, brand, auth, IDENTIFIER)
        require(row, 'EXTERNAL_CASES_RESOURCE_NOT_FOUND_' + brand)
        rid = row.get('id')
        require(stage.resources.ID.fullmatch(str(rid)), 'INVALID_EXISTING_CASES_RESOURCE_ID')
        detail = stage.read(client, stage.path(brand, '/api/server/v1/api-resources/' + rid), auth)
        scopes = stage.read(client, stage.path(brand, '/api/server/v1/api-resources/' + rid + '/scopes'), auth)
        scope_rows = stage.list_items(scopes, 'scopes')
        names = {v if isinstance(v, str) else v.get('name') for v in scope_rows}
        require(detail.get('id') == rid and detail.get('identifier') == IDENTIFIER and
                detail.get('name') == RESOURCE_NAME and detail.get('requiresAuthorization') is True and
                names == set(stage.SCOPES), 'EXTERNAL_CASES_RESOURCE_DRIFT_' + brand)
        external_ids[brand] = rid
        for c in ('web', 'app'):
            appid = oidc['tenants'][brand]['clients'][c]['id']
            app = stage.read(client, stage.path(brand, '/api/server/v1/applications/' + appid), auth)
            require(app.get('id') == appid and
                    app.get('name') == oidc['tenants'][brand]['clients'][c]['name'] and
                    (app.get('associatedRoles') or {}).get('allowedAudience') == 'APPLICATION',
                    'EXTERNAL_APP_AUDIENCE_DRIFT_' + brand + '_' + c)
            grant = stage.read_authorization(client, brand, auth, appid, rid)
            require(grant and stage.permission_list(grant) == set(stage.SCOPES),
                    'EXTERNAL_CASES_APP_GRANT_DRIFT_' + brand + '_' + c)
            # WSO2 7.3 GET authorized-apis documents "policyId"; the POST
            # payload uses "policyIdentifier". Accept either readback name
            # only when every present policy field explicitly says RBAC.
            policy_fields = ('policyId', 'policyIdentifier')
            observed_policies = [grant[k] for k in policy_fields if k in grant]
            require(observed_policies and all(type(v) is str and v == 'RBAC'
                                              for v in observed_policies),
                    'RBAC_POLICY_NOT_ATTESTED_' + brand + '_' + c)
            verified_policy_fields[brand + ':' + c] = [k for k in policy_fields if k in grant]
    expected = expected_context(ctx, external_ids)
    journal = validate_journal(stored, expected)
    # Validate all existing role grants, not just the expected six names.
    # An unmanaged role that already grants a case scope could bypass the
    # intended customer/seller separation despite our new role definitions.
    for brand in stage.DOMAINS:
        auth = stage.resources.basic(stage.resources.OWNER + '@' + stage.DOMAINS[brand],
                                     ts['tenants'][brand]['owner']['password'])
        owned_ids = {v.get('id') for v in journal['tenants'][brand]['roles'].values()
                     if isinstance(v, dict) and v.get('state') == 'verified' and v.get('id')}
        verify_no_unowned_case_permission_roles(client, brand, auth, version, owned_ids)
    actions = []
    role_counts = {}
    role_prerequisites = []
    for brand in stage.DOMAINS:
        auth = stage.resources.basic(stage.resources.OWNER + '@' + stage.DOMAINS[brand],
                                     ts['tenants'][brand]['owner']['password'])
        roles = journal['tenants'][brand]['roles']
        role_counts[brand] = {'customerRoles': 0, 'sellerRoles': 0}
        for channel, kind, appid, name, users, perms in stage.role_specs(oidc, identities, seed, brand):
            require(set(perms) == set(stage.CUSTOMER_SCOPES if kind == 'customer' else stage.SELLER_SCOPES),
                    'ROLE_PERMISSION_POLICY_DRIFT')
            for uid in users:
                person = stage.read(client, stage.path(brand, '/scim2/Users/' + uid), auth)
                require(person.get('id') == uid and person.get('active') is not False,
                        'ROLE_ONLY_USER_NOT_ACTIVE_' + brand)
            role_key = channel + ':' + kind
            node = roles.get(role_key)
            existing = stage.exact_role(client, brand, auth, version, name)
            if existing:
                require(node and node.get('state') == 'verified',
                        'UNOWNED_OR_UNCERTAIN_ROLE_COLLISION_' + brand + '_' + role_key)
                stage.verify_role(client, brand, auth, version, existing, node, name, appid, users, perms)
            else:
                require(node is None, 'JOURNALED_ROLE_MISSING_OR_UNCERTAIN_' + brand + '_' + role_key)
                actions.append([brand, channel, kind, 'create_app_role'])
            role_counts[brand][kind + 'Roles'] += 1
            role_prerequisites.append({'brand': brand, 'channel': channel, 'kind': kind,
                                       'appId': appid, 'permissions': sorted(perms),
                                       'userIds': sorted(users), 'roleName': name})
    plan = {'stage': 'CIAM_V10_EXISTING_CASES_ROLE_ONLY_V1', 'mode': 'READ_ONLY',
            'remoteWrites': 0, 'apiIdentifier': IDENTIFIER, 'roleApiVersion': version,
            'externalExistingResourcesPreserved': True,
            'resourceOrApplicationWritesPlanned': 0,
            'allFourClientCaseGrantsRbacVerified': True,
            'policyReadbackFields': verified_policy_fields,
            'unownedExistingCasePermissionRolesExcluded': True,
            'plannedActions': actions, 'perTenant': role_counts,
            'preconditionSha256': digest({'resources': external_ids,
                                         'expectedRoleBindings': role_prerequisites})}
    return plan, journal


def save(journal):
    stage.resources.atomic_save(JOURNAL, journal)


def create_one(client, brand, auth, version, journal, role, data):
    channel, kind, appid, name, users, perms = role
    key = channel + ':' + kind
    node = {'state': 'post-started', 'name': name, 'appId': appid}
    # Durable write-ahead marker: if HTTP request or readback is ambiguous,
    # the role must be manually reconciled; automatic retries are prohibited.
    journal['tenants'][brand]['roles'][key] = node
    save(journal)
    status, body, _ = client.call('POST', stage.path(brand, '/scim2/' + version + '/Roles'),
                                  auth=auth, data=data)
    require(status == 201, 'ROLE_POST_UNCERTAIN_NO_RETRY_HTTP_' + str(status))
    existing = stage.exact_role(client, brand, auth, version, name)
    require(existing, 'ROLE_POST_NO_READBACK_RETRY_FORBIDDEN')
    rid = stage.verify_role(client, brand, auth, version, existing, node, name, appid, users, perms)
    node['id'] = rid
    node['state'] = 'verified'
    save(journal)


def apply(client, ctx, journal, plan):
    ts, oidc, authority, identities, seed, version = ctx
    targets = {tuple(x[:3]) for x in plan['plannedActions']}
    for brand in stage.DOMAINS:
        auth = stage.resources.basic(stage.resources.OWNER + '@' + stage.DOMAINS[brand],
                                     ts['tenants'][brand]['owner']['password'])
        for role in stage.role_specs(oidc, identities, seed, brand):
            channel, kind, appid, name, users, perms = role
            if (brand, channel, kind) not in targets:
                continue
            # Reconfirm preconditions and role absence immediately before each
            # mutating operation. TOCTOU collisions fail on 409; never retry.
            inventory(LimitedClient(client.actual, version), ctx, journal)
            require(not stage.exact_role(client, brand, auth, version, name), 'ROLE_RACE_COLLISION')
            payload = {'schemas': [ROLE_SCHEMA], 'displayName': name,
                       'audience': {'type': 'application', 'value': appid},
                       'permissions': [{'value': v} for v in perms],
                       'users': [{'value': v} for v in users]}
            create_one(client, brand, auth, version, journal, role, payload)
    final, _ = inventory(LimitedClient(client.actual, version), ctx, journal)
    require(not final['plannedActions'], 'FINAL_ROLES_NOT_VERIFIED')
    return {'state': 'ROLE_ONLY_READBACK_VERIFIED_NOT_BUSINESS_ACCEPTANCE',
            'remoteRolePosts': client.post_count,
            'externalResourcesModified': False}


def main(argv=None):
    args_parser = argparse.ArgumentParser(description=__doc__)
    args_parser.add_argument('mode', choices=('plan', 'apply', 'verify'))
    args_parser.add_argument('--plan-sha256', default='')
    args = args_parser.parse_args(argv)
    check_identifier()
    ctx = stage.context()
    version = ctx[5]
    require(version == 'v2', 'JOURNAL_PINNED_ROLE_VERSION_CHANGED_REVIEW_REQUIRED')
    readclient = LimitedClient(stage.resources.HTTPS(), version)
    plan, journal = inventory(readclient, ctx, load_existing())
    ph = digest(plan)
    if args.mode == 'plan':
        print(json.dumps({**plan, 'planSha256': ph, 'getRequests': readclient.get_count}, indent=2))
        return 0
    if args.mode == 'verify':
        require(not plan['plannedActions'], 'ROLE_ONLY_STILL_INCOMPLETE')
        print(json.dumps({'stage': plan['stage'], 'status': 'ROLE_ONLY_READBACK_VERIFIED_NOT_BUSINESS_ACCEPTANCE',
                          'apiIdentifier': IDENTIFIER, 'remoteWrites': 0}, indent=2))
        return 0
    require(os.environ.get('WSO2_CIAM_CASES_EXISTING_ROLES_CONFIRM') == CONFIRM and
            os.environ.get('WSO2_CIAM_V10_ROLE_V2_CONFIRM') == ROLE_V2_CONFIRM and
            re.fullmatch(r'[0-9a-f]{64}', args.plan_sha256 or '') and args.plan_sha256 == ph,
            'EXPLICIT_CONFIRMATION_AND_MATCHING_LIVE_PLAN_REQUIRED')
    # A read-only plan with no operations must not initialize an ownership journal.
    require(plan['plannedActions'], 'NOTHING_TO_APPLY')
    fd = None
    try:
        require(not LOCK.exists() and not LOCK.is_symlink(), 'EXISTING_ROLE_ONLY_LOCK')
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, str(os.getpid()).encode())
        if not JOURNAL.exists():
            save(journal)
        writes = LimitedClient(stage.resources.HTTPS(), version, allow_posts=True)
        result = apply(writes, ctx, journal, plan)
        print(json.dumps({'stage': plan['stage'], **result}, indent=2))
    finally:
        if fd is not None:
            os.close(fd)
            LOCK.unlink()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Refuse, KeyError, TypeError, ValueError) as exc:
        # Known refusal codes should never include credentials or tokens.
        print('REFUSED: ' + str(exc), file=sys.stderr)
        sys.exit(2)
    except Exception:
        # Remote or filesystem failures may happen after a POST attempt. Do not
        # print raw transport exceptions (which may contain sensitive context).
        print('REFUSED: UNEXPECTED_OR_UNCERTAIN_IO_RECONCILE_PRIVATE_JOURNAL_NO_RETRY', file=sys.stderr)
        sys.exit(2)
