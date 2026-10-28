import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('scope_plan', ROOT / 'deploy/ciam-v10/oidc/management_scope_add_plan.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
# Import the known, pinned reader from the installed project when possible;
# tests are also runnable directly in this archive.
READER = ROOT / 'deploy/ciam-v10/oidc/management_authorization_readback.py'
if READER.is_file():
    RSPEC = importlib.util.spec_from_file_location('scope_reader', READER)
    R = importlib.util.module_from_spec(RSPEC)
    RSPEC.loader.exec_module(R)
else:
    # Offline tests are independent of private repo credentials and Docker.
    class R:
        @staticmethod
        def unwrap_authorizations(obj):
            if isinstance(obj, list):
                return obj
            if isinstance(obj, dict) and set(obj) == {'authorizedAPIs'}:
                return obj['authorizedAPIs']
            raise M.Refuse('UNRECOGNIZED_AUTHORIZATIONS')
        @staticmethod
        def parse_scope_names(items):
            if not isinstance(items, list):
                raise M.Refuse('SCOPES_NOT_LIST')
            names = [v.get('name') for v in items]
            if any(not isinstance(v, str) for v in names) or len(names) != len(set(names)):
                raise M.Refuse('SCOPES_INVALID')
            return set(names)

APP_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
RESOURCE_ID = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
MANAGEMENT = {'id': APP_ID, 'name': M.APP_NAME, 'domain': M.DOMAIN, 'state': 'verified'}
APP = {'id': APP_ID, 'name': M.APP_NAME, 'isManagementApp': True}
AUTH = {'id': RESOURCE_ID, 'identifier': M.APP_API, 'policyId': 'RBAC',
        'authorizedScopes': [{'name': name} for name in sorted(M.REQUIRED_BEFORE)]}

class ScopeAddPlanTests(unittest.TestCase):
    def run_plan(self, auth=None, app=None, management=None, resource_id=RESOURCE_ID):
        return M.evaluate(R, APP if app is None else app,
                          [AUTH] if auth is None else auth,
                          MANAGEMENT if management is None else management, resource_id)
    def test_exact_three_scope_baseline(self):
        p = self.run_plan()
        self.assertEqual(p['status'], 'VERIFIED_READBACK')
        self.assertEqual(p['proposedPatch'], {'addedScopes': [M.NEW_SCOPE], 'removedScopes': []})
        self.assertFalse(p['mutationImplementedHere'])
    def test_no_grant_without_separate_admin_approval(self):
        p = self.run_plan()
        self.assertFalse(p['adminAuthorizationVerified'])
        self.assertFalse(p['safeForAutomaticApply'])
        self.assertTrue(p['requiresExplicitSeparateAdminApproval'])
    def test_existing_scope_rejects(self):
        a = copy.deepcopy(AUTH)
        a['authorizedScopes'].append({'name': M.NEW_SCOPE})
        with self.assertRaises(M.Refuse): self.run_plan([a])
    def test_extra_scope_rejects(self):
        a = copy.deepcopy(AUTH)
        a['authorizedScopes'].append({'name': 'unexpected_scope'})
        with self.assertRaises(M.Refuse): self.run_plan([a])
    def test_missing_scope_rejects(self):
        a = copy.deepcopy(AUTH)
        a['authorizedScopes'].pop()
        with self.assertRaises(M.Refuse): self.run_plan([a])
    def test_duplicate_scope_rejects(self):
        a = copy.deepcopy(AUTH)
        a['authorizedScopes'].append(copy.deepcopy(a['authorizedScopes'][0]))
        with self.assertRaises(Exception): self.run_plan([a])
    def test_wrong_resource_identifier_rejects(self):
        a = dict(AUTH, identifier='/scim2/Users')
        with self.assertRaises(M.Refuse): self.run_plan([a])
    def test_wrong_resource_id_rejects(self):
        with self.assertRaises(M.Refuse): self.run_plan(resource_id='wrong-id')
    def test_wrong_rbac_policy_rejects(self):
        a = dict(AUTH, policyId='NO_AUTHORIZATION')
        with self.assertRaises(M.Refuse): self.run_plan([a])
    def test_wrong_api_type_rejects(self):
        a = dict(AUTH, type='BUSINESS')
        with self.assertRaises(M.Refuse): self.run_plan([a])
    def test_management_identity_rejects(self):
        with self.assertRaises(M.Refuse): self.run_plan(app=dict(APP, isManagementApp=False))
    def test_journal_identity_rejects(self):
        with self.assertRaises(M.Refuse): self.run_plan(management=dict(MANAGEMENT, domain='wrong'))
    def test_duplicate_resource_id_rejects(self):
        with self.assertRaises(M.Refuse): self.run_plan([AUTH, AUTH])
    def test_no_raw_identifiers_in_output(self):
        output = str(self.run_plan())
        self.assertNotIn(APP_ID, output)
        self.assertNotIn(RESOURCE_ID, output)
    def test_only_read_only_network_helpers(self):
        source = (ROOT / 'deploy/ciam-v10/oidc/management_scope_add_plan.py').read_text()
        self.assertNotIn("'PATCH',", source)
        self.assertNotIn("'PUT',", source)
        self.assertNotIn("'DELETE',", source)
        self.assertIn("'scope': 'internal_application_mgt_view'", source)

if __name__ == '__main__':
    unittest.main()
