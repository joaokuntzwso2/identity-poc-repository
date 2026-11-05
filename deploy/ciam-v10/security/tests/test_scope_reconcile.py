import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

# After installation this test is under deploy/ciam-v10/security/tests/.
# The optional override is for the isolated source-package testbed only.
REPO = pathlib.Path(os.environ.get('MAGALU_RECONCILE_TEST_ROOT',
             pathlib.Path(__file__).resolve().parents[4]))
if not (REPO / 'scripts/magalu-scope-reconcile.py').is_file():
    raise RuntimeError('install Magalu scope reconciler in repository root before testing')
sys.path.insert(0, str(REPO / 'deploy/ciam-v10/security'))
sys.path.insert(0, str(REPO / 'scripts'))
module = REPO / 'scripts/magalu-scope-reconcile.py'
spec = importlib.util.spec_from_file_location('magalu_reconcile', module)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReconcileTests(unittest.TestCase):
    def test_canonical_owner_binds_domain(self):
        self.assertEqual(m.canon_user('owner', 'aurora.identity.test'),
                         'owner@aurora.identity.test')
        self.assertEqual(m.canon_user('owner@brisa.identity.test', 'brisa.identity.test'),
                         'owner@brisa.identity.test')

    def test_cross_tenant_owner_denied(self):
        with self.assertRaises(m.Blocked):
            m.canon_user('owner@brisa.identity.test', 'aurora.identity.test')

    def test_bad_owner_formats_denied(self):
        for user in ('', 'name:bad', 'name\nother', 'a@b@aurora.identity.test'):
            with self.subTest(user=user), self.assertRaises(m.Blocked):
                m.canon_user(user, 'aurora.identity.test')

    def test_wsgi_documented_authorized_scopes(self):
        body = [{'id': 'api-resource-1', 'authorizedScopes': [
            {'name': 'internal_application_mgt_view'},
            {'name': 'other:scope'}]}]
        self.assertEqual(m.parse_auth_rows(body),
                         {'api-resource-1': {'internal_application_mgt_view', 'other:scope'}})

    def test_reject_ambiguous_authorization_rows(self):
        body = [{'id': 'api-1', 'authorizedScopes': []},
                {'id': 'api-1', 'authorizedScopes': []}]
        with self.assertRaises(m.Blocked): m.parse_auth_rows(body)

    def test_reject_authorized_scope_legacy_strings(self):
        with self.assertRaises(m.Blocked):
            m.parse_auth_rows([{'id': 'api-1', 'authorizedScopes': ['read']}])

    def test_cursor_is_bounded(self):
        doc = {'APIResources': [{'id': 'r'}], 'totalResults': 2,
               'links': [{'rel': 'after', 'href': '/api/server/v1/api-resources?after=Njox'}]}
        rows, total, cursor = m.parse_catalog_page(doc)
        self.assertEqual((len(rows), total, cursor), (1, 2, 'Njox'))

    def test_cursor_must_not_be_external(self):
        with self.assertRaises(m.Blocked):
            m.parse_catalog_page({'APIResources': [], 'links': [
                {'rel': 'after', 'href': 'https://evil.invalid/api-resources?after=abc'}]})

    def test_unique_scope_catalog_only_management(self):
        class API:
            def call(self, method, path):
                rid = path.rsplit('/', 1)[1]
                return {'id': rid, 'type': 'SYSTEM',
                        'scopes': [{'name': name} for name in sorted(m.TARGET)]}
        found = m.locate_scopes(API(), {'platform': {'type': 'SYSTEM', 'id': 'platform'},
                                      'business': {'type': 'BUSINESS', 'id': 'business'}})
        self.assertEqual(set(found), m.TARGET)
        self.assertTrue(all(rid == 'platform' for rid in found.values()))

    def test_missing_catalog_scope_blocks(self):
        class API:
            def call(self, method, path):
                return {'id': 'resource', 'type': 'SYSTEM',
                        'scopes': [{'name': 'internal_application_mgt_update'}]}
        with self.assertRaisesRegex(m.Blocked, 'REQUIRED_SCOPES_MISSING'):
            m.locate_scopes(API(), {'resource': {'type': 'SYSTEM'}})

    def test_duplicate_target_scope_blocks(self):
        class API:
            def call(self, method, path):
                rid = path.rsplit('/', 1)[1]
                return {'id': rid, 'type': 'SYSTEM',
                        'scopes': [{'name': 'internal_application_mgt_update'}]}
        with self.assertRaisesRegex(m.Blocked, 'TARGET_SCOPE_AMBIGUOUS'):
            m.locate_scopes(API(), {'one': {'type': 'SYSTEM'}, 'two': {'type': 'SYSTEM'}})

    def test_plan_adds_missing_only_and_keeps_existing(self):
        class API:
            def call(self, method, path):
                return [{'id': 'app-api', 'authorizedScopes': [
                    {'name': 'internal_application_mgt_view'}]}]
        scope_map = {'internal_application_mgt_view': 'app-api',
                     'internal_application_mgt_update': 'app-api',
                     'internal_governance_view': 'gov-api'}
        plan = m.plan_tenant(API(), 'manager-id', scope_map)
        self.assertEqual(plan['operations'], [
            {'api_resource_id': 'app-api', 'method': 'PATCH',
             'added_scopes': ['internal_application_mgt_update']},
            {'api_resource_id': 'gov-api', 'method': 'POST',
             'added_scopes': ['internal_governance_view']}])
        self.assertNotIn('removed_scopes', str(plan))

    def test_patch_schema_matches_documented_rest(self):
        class API:
            def __init__(self): self.calls=[]
            def call(self, method, path, body=None):
                self.calls.append((method, path, body))
                if method == 'GET':
                    return [{'id': 'resource-id', 'authorizedScopes': [
                        {'name': 'internal_governance_view'}]}]
                return {}
        api=API()
        m.patch_one(api, 'manager-id', {'api_resource_id':'resource-id',
                    'method':'PATCH','added_scopes':['internal_governance_view']})
        self.assertEqual(api.calls[0][0], 'PATCH')
        self.assertEqual(api.calls[0][2], {'addedScopes': ['internal_governance_view'], 'removedScopes': []})

    def test_post_schema_matches_documented_rest(self):
        class API:
            def __init__(self): self.calls=[]
            def call(self, method, path, body=None):
                self.calls.append((method, path, body))
                if method == 'GET':
                    return [{'id': 'resource-id', 'authorizedScopes': [
                        {'name': 'internal_governance_view'}]}]
                return {}
        api=API()
        m.patch_one(api, 'manager-id', {'api_resource_id':'resource-id',
                    'method':'POST','added_scopes':['internal_governance_view']})
        self.assertEqual(api.calls[0][0], 'POST')
        self.assertEqual(api.calls[0][2], {'id':'resource-id', 'policyIdentifier':'RBAC',
                                           'scopes':['internal_governance_view']})

    def test_missing_readback_prevents_success(self):
        api=MagicMock()
        api.call.return_value=[]
        with self.assertRaisesRegex(m.Blocked,'READBACK'):
            m.verified_readback(api, 'manager-id', [{'api_resource_id':'res','added_scopes':['internal_governance_view']}])

    def test_journal_is_0600_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / 'journal.json'
            m.write_private(path, {'digest':'test'})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertEqual(m.read_private(path), {'digest':'test'})
            with self.assertRaisesRegex(m.Blocked,'ALREADY_EXISTS'):
                m.write_private(path, {})

    def test_not_replay_grant_apply(self):
        self.assertIn('PREVIOUS_GRANT_APPLY_EXISTS_REFUSE_AUTOMATIC_RETRY', module.read_text())
        self.assertNotIn('os.system(', module.read_text())


if __name__ == '__main__': unittest.main()
