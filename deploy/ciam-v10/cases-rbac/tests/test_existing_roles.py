"""Offline tests. No WSO2 server or writes are used."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / 'existing_roles.py'
spec = importlib.util.spec_from_file_location('existing_cases_roles_under_test', FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def context():
    tenants = {'tenants': {brand: {'tenantId': 'tenant-' + brand,
                                   'owner': {'password': 'fixture-only'}}
                           for brand in m.stage.DOMAINS}}
    oidc = {'tenants': {brand: {'clients': {c: {'id': brand + '-' + c, 'name': brand + '-' + c}
                                           for c in ('web', 'app')}}
                        for brand in m.stage.DOMAINS}}
    people = [{'key': 'ana', 'type': 'customer', 'brands': ['aurora', 'brisa']},
              {'key': 'rafael', 'type': 'customer', 'brands': ['aurora']},
              {'key': 'marcos', 'type': 'seller', 'brands': ['aurora']}]
    identities = {'tenants': {brand: {'users': {p['key']: {'id': brand + '-' + p['key']}
                                               for p in people if brand in p['brands']}}
                              for brand in m.stage.DOMAINS}}
    return tenants, oidc, {}, identities, {'people': people}, 'v2'


class FakeWSO2:
    def __init__(self, ctx):
        self.ctx = ctx
        self.calls = []
        self.roles = {}
        self.policy = 'RBAC'
        self.policy_field = 'policyId'
        self.extra_policy_field = None
        self.extra_scope = False
        self.bad_name = False
        self.wrong_audience = False
        self.fail_after_post = False
        self.unowned_case_role = False

    def call(self, method, path, *, auth, data=None, form=None):
        self.calls.append((method, path, data))
        brand = 'aurora' if '/t/aurora.' in path else 'brisa'
        if method == 'POST':
            if self.fail_after_post:
                raise OSError('simulated request uncertainty')
            key = (brand, data['displayName'])
            self.roles[key] = {'id': brand + '-role-' + str(len(self.roles)+1),
                               'displayName': data['displayName'], 'audience': data['audience'],
                               'users': data['users'], 'permissions': data['permissions']}
            return 201, {}, None
        if method != 'GET':
            raise AssertionError('Unexpected write')
        rid = brand + '-existing-api'
        if '/api/server/v1/api-resources?' in path:
            return 200, {'APIResources': [{'id': rid, 'identifier': m.IDENTIFIER}], 'totalResults': 1}, None
        if '/api/server/v1/api-resources/' in path and path.endswith('/scopes'):
            scopes = list(m.stage.SCOPES)
            if self.extra_scope:
                scopes.append('ciam:cases:unsafe')
            return 200, {'scopes': [{'name': v} for v in scopes]}, None
        if '/api/server/v1/api-resources/' in path:
            return 200, {'id': rid, 'identifier': m.IDENTIFIER,
                         'name': 'WRONG' if self.bad_name else m.RESOURCE_NAME,
                         'requiresAuthorization': True}, None
        if '/authorized-apis' in path:
            return 200, {'authorizedAPIs': [{'id': rid, 'scopes': list(m.stage.SCOPES),
                                              **({self.policy_field: self.policy} if self.policy is not None else {}),
                                              **({'policyIdentifier': self.extra_policy_field} if self.extra_policy_field is not None else {})}]}, None
        if '/api/server/v1/applications/' in path:
            appid = path.rsplit('/', 1)[-1]
            channel = 'web' if appid.endswith('web') else 'app'
            return 200, {'id': appid,
                         'name': self.ctx[1]['tenants'][brand]['clients'][channel]['name'],
                         'associatedRoles': {'allowedAudience': 'ORGANIZATION' if self.wrong_audience else 'APPLICATION'}}, None
        if '/scim2/Users/' in path:
            uid = path.rsplit('/', 1)[-1]
            return 200, {'id': uid, 'active': True}, None
        if '/scim2/v2/Roles?' in path:
            import urllib.parse
            query = urllib.parse.parse_qs(path.split('?', 1)[1])
            if 'filter' not in query:
                rows = [{'id': r['id'], 'displayName': r['displayName']} for (b, _), r in self.roles.items() if b == brand]
                if self.unowned_case_role and brand == 'aurora':
                    rows.append({'id': 'legacy-case-role-id', 'displayName': 'Legacy Case Admin'})
                start = int(query['startIndex'][0]) - 1
                count = int(query['count'][0])
                return 200, {'Resources': rows[start:start+count], 'totalResults': len(rows)}, None
            name = query['filter'][0].split('"')[1]
            role = self.roles.get((brand, name))
            return 200, {'Resources': [{'id': role['id'], 'displayName': name}] if role else [],
                         'totalResults': 1 if role else 0}, None
        if '/scim2/v2/Roles/' in path:
            rid = path.rsplit('/', 1)[-1]
            if rid == 'legacy-case-role-id' and self.unowned_case_role:
                return 200, {'id': rid, 'displayName': 'Legacy Case Admin',
                             'permissions': [{'value':'ciam:cases:approve'}],
                             'audience':{'type':'application','value':'aurora-web'},
                             'users':[]}, None
            role = next((r for (b, _), r in self.roles.items() if b == brand and r['id'] == rid), None)
            if role:
                return 200, role, None
        raise AssertionError('Unexpected GET: ' + path)


class Safety(unittest.TestCase):
    def setUp(self):
        self.ctx = context()
        self.remote = FakeWSO2(self.ctx)
        self.reader = m.LimitedClient(self.remote, 'v2')

    def plan(self, stored=None):
        return m.inventory(self.reader, self.ctx, stored)

    def test_pinned_identifier_only(self):
        with patch.dict(os.environ, {'WSO2_CIAM_CASES_API_IDENTIFIER': m.IDENTIFIER}):
            self.assertEqual(m.check_identifier(), m.IDENTIFIER)
        for value in ('https://api.ciam-v10.test/cases','urn:ciampoc:service-requests:v2', ''):
            with patch.dict(os.environ, {'WSO2_CIAM_CASES_API_IDENTIFIER': value}):
                with self.assertRaises(m.Refuse): m.check_identifier()

    def test_existing_resources_are_never_created_or_adopted(self):
        plan, journal = self.plan()
        self.assertEqual(len(plan['plannedActions']), 6)
        self.assertTrue(plan['externalExistingResourcesPreserved'])
        self.assertEqual(plan['resourceOrApplicationWritesPlanned'], 0)
        self.assertEqual(self.reader.post_count, 0)
        self.assertEqual(journal['tenants']['aurora']['externalResourceId'], 'aurora-existing-api')
        self.assertTrue(all(x[0] == 'GET' for x in self.remote.calls))

    def test_expected_customer_and_seller_separation(self):
        self.assertEqual(set(m.stage.CUSTOMER_SCOPES), {'ciam:cases:create','ciam:cases:read'})
        self.assertEqual(set(m.stage.SELLER_SCOPES), {'ciam:cases:read','ciam:cases:review','ciam:cases:approve'})
        plan, _ = self.plan()
        self.assertFalse(any(x[0] == 'brisa' and x[2] == 'seller' for x in plan['plannedActions']))
        self.assertEqual(plan['perTenant']['aurora'], {'customerRoles': 2,'sellerRoles': 2})

    def test_missing_rbac_policy_denied(self):
        for value in (None, 'NONE', 'NO_POLICY'):
            with self.subTest(value=value):
                self.remote.policy = value
                with self.assertRaisesRegex(m.Refuse, 'RBAC_POLICY_NOT_ATTESTED'):
                    self.plan()

    def test_documented_get_policy_id_verified_for_all_four_clients(self):
        plan, _ = self.plan()
        self.assertTrue(plan['allFourClientCaseGrantsRbacVerified'])
        self.assertEqual(set(plan['policyReadbackFields']),
                         {'aurora:web', 'aurora:app', 'brisa:web', 'brisa:app'})
        self.assertTrue(all(fields == ['policyId']
                            for fields in plan['policyReadbackFields'].values()))

    def test_legacy_readback_policy_identifier_if_only_field(self):
        self.remote.policy_field = 'policyIdentifier'
        plan, _ = self.plan()
        self.assertTrue(all(fields == ['policyIdentifier']
                            for fields in plan['policyReadbackFields'].values()))

    def test_conflicting_policy_fields_fail_closed(self):
        self.remote.policy = 'RBAC'
        self.remote.extra_policy_field = 'NO_POLICY'
        with self.assertRaisesRegex(m.Refuse, 'RBAC_POLICY_NOT_ATTESTED'):
            self.plan()

    def test_two_rbac_policy_fields_are_consistent(self):
        self.remote.extra_policy_field = 'RBAC'
        plan, _ = self.plan()
        self.assertTrue(all(fields == ['policyId', 'policyIdentifier']
                            for fields in plan['policyReadbackFields'].values()))

    def test_policy_case_whitespace_and_empty_denied(self):
        for value in ('rbac', ' RBAC', 'RBAC ', '', 0, True):
            with self.subTest(value=value):
                self.remote.policy = value
                with self.assertRaisesRegex(m.Refuse, 'RBAC_POLICY_NOT_ATTESTED'):
                    self.plan()

    def test_resource_drift_denied(self):
        self.remote.extra_scope = True
        with self.assertRaisesRegex(m.Refuse,'EXTERNAL_CASES_RESOURCE_DRIFT'):
            self.plan()
        self.remote.extra_scope = False
        self.remote.bad_name = True
        with self.assertRaisesRegex(m.Refuse,'EXTERNAL_CASES_RESOURCE_DRIFT'):
            self.plan()

    def test_wrong_audience_denied(self):
        self.remote.wrong_audience = True
        with self.assertRaisesRegex(m.Refuse,'EXTERNAL_APP_AUDIENCE_DRIFT'):
            self.plan()

    def test_unowned_role_collision_denied(self):
        self.remote.roles[('aurora',m.stage.role_name('web','customer'))] = {
            'id':'test-collision','displayName':m.stage.role_name('web','customer'),
            'audience': {'type':'application','value':'aurora-web'},
            'users':[], 'permissions':[]}
        with self.assertRaisesRegex(m.Refuse,'UNOWNED_OR_UNCERTAIN_ROLE_COLLISION'):
            self.plan()

    def test_unowned_existing_role_permission_denied(self):
        self.remote.unowned_case_role = True
        with self.assertRaisesRegex(m.Refuse, 'UNOWNED_CASE_SCOPE_ROLE_PRESENT_aurora'):
            self.plan()

    def test_role_list_incomplete_refuses(self):
        class Incomplete(FakeWSO2):
            def call(self, method, path, *, auth, data=None, form=None):
                if method == 'GET' and '/scim2/v2/Roles?' in path and 'filter=' not in path:
                    return 200, {'Resources': [], 'totalResults': 1}, None
                return super().call(method, path, auth=auth, data=data, form=form)
        bad = m.LimitedClient(Incomplete(self.ctx),'v2')
        with self.assertRaisesRegex(m.Refuse, 'ROLE_PAGE_EMPTY_BEFORE_TOTAL'):
            m.inventory(bad,self.ctx,None)

    def test_role_only_client_denies_other_writes(self):
        writer = m.LimitedClient(self.remote,'v2', allow_posts=True)
        with self.assertRaisesRegex(m.Refuse,'ROLE_ONLY_STAGE_FORBIDS_NON_ROLE_MUTATION'):
            writer.call('POST','/t/aurora.identity.test/api/server/v1/api-resources',auth='test',data={'x':1})
        with self.assertRaisesRegex(m.Refuse,'ROLE_ONLY_STAGE_FORBIDS_NON_ROLE_MUTATION'):
            writer.call('PATCH','/t/aurora.identity.test/scim2/v2/Roles',auth='test',data={})
        self.assertFalse(self.remote.calls)

    def test_six_verified_role_creates_and_idempotent_plan(self):
        plan, journal = self.plan()
        writer = m.LimitedClient(self.remote,'v2',allow_posts=True)
        with patch.object(m,'save',lambda x:None):
            result = m.apply(writer,self.ctx,journal,plan)
        self.assertEqual(writer.post_count,6)
        self.assertEqual(result['remoteRolePosts'],6)
        self.assertEqual(len(self.remote.roles),6)
        after, _ = self.plan(journal)
        self.assertFalse(after['plannedActions'])
        self.assertEqual(writer.post_count,6)
        self.assertTrue(all(x[0] in ('GET','POST') for x in self.remote.calls))

    def test_uncertain_write_blocks_retry(self):
        plan, journal = self.plan()
        self.remote.fail_after_post = True
        writer = m.LimitedClient(self.remote,'v2',allow_posts=True)
        with patch.object(m,'save',lambda x:None):
            with self.assertRaises(OSError):
                m.apply(writer,self.ctx,journal,plan)
        self.assertEqual(writer.post_count,1)
        self.assertEqual(journal['tenants']['aurora']['roles']['web:customer']['state'],'post-started')
        with self.assertRaisesRegex(m.Refuse,'JOURNALED_ROLE_MISSING_OR_UNCERTAIN'):
            self.plan(journal)

    def test_journal_context_drift_denied(self):
        _, journal = self.plan()
        journal['tenants']['aurora']['externalResourceId'] = 'attacker-changed-id'
        with self.assertRaisesRegex(m.Refuse,'ROLE_ONLY_JOURNAL_DRIFT'):
            self.plan(journal)

    def test_plan_hash_binds_to_ops_and_resources(self):
        plan, _ = self.plan()
        changed = {**plan, 'plannedActions': []}
        self.assertNotEqual(m.digest(plan), m.digest(changed))
        changed2 = {**plan, 'preconditionSha256': '0' * 64}
        self.assertNotEqual(m.digest(plan), m.digest(changed2))

if __name__ == '__main__': unittest.main()
