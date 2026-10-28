import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / 'deploy/ciam-v10/oidc/management_authorization_readback.py'
spec = importlib.util.spec_from_file_location('management_auth_readback_tests', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

RESOURCE = 'f93bb5ee-38bf-4bf2-bb6d-4df4078af313'
BASE = {'id': RESOURCE, 'identifier': module.APP_API, 'policyId': 'RBAC',
        'authorizedScopes': [{'name': 'internal_application_mgt_view'},
                             {'name': 'internal_application_mgt_create'},
                             {'name': 'internal_application_mgt_client_secret_view'}]}

class ReadbackTests(unittest.TestCase):
    def classify(self, obj):
        return module.classify_authorization(obj, RESOURCE)

    def test_missing_update_matches_baseline(self):
        result = self.classify([BASE])
        self.assertEqual(result['condition'], 'UPDATE_NOT_AUTHORIZED_ON_EXISTING_MANAGEMENT_APP')
        self.assertFalse(result['updateScopeAuthorized'])

    def test_update_granted_changes_diagnosis(self):
        record = dict(BASE, authorizedScopes=BASE['authorizedScopes'] +
                      [{'name': module.UPDATE}])
        self.assertTrue(self.classify([record])['updateScopeAuthorized'])

    def test_wrapper_supported(self):
        for key in ('authorizedAPIs', 'authorizedApis', 'apis', 'resources'):
            with self.subTest(key=key):
                self.assertFalse(self.classify({key: [BASE]})['updateScopeAuthorized'])

    def test_unrecognized_wrapper_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify({'unexpected': [BASE]})

    def test_ambiguous_wrapper_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify({'authorizedAPIs': [BASE], 'apis': [BASE]})

    def test_missing_resource_id_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify([dict(BASE, id='different')])

    def test_duplicate_resource_id_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify([BASE, BASE])

    def test_identifier_drift_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify([dict(BASE, identifier='/scim2/Users')])

    def test_policy_drift_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify([dict(BASE, policyId='NO_AUTHORIZATION')])

    def test_duplicate_scopes_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify([dict(BASE, authorizedScopes=[{'name': module.UPDATE}, module.UPDATE])])

    def test_scope_not_leaked(self):
        item = dict(BASE, authorizedScopes=BASE['authorizedScopes'] + [{'name': 'custom:private:scope'}])
        result = self.classify([item])
        self.assertEqual(result['otherAuthorizedScopeCount'], 1)
        self.assertNotIn('custom:private:scope', str(result))

    def test_malformed_scope_refused(self):
        with self.assertRaises(module.Refuse):
            self.classify([dict(BASE, authorizedScopes=[{'displayName': 'Unknown'}])])

    def test_get_path_guard(self):
        with self.assertRaises(module.Refuse):
            module.only_get(None, '/t/aurora.identity.test/api/server/v1/applications/other',
                            'Bearer secret', '/t/aurora.identity.test/api/server/v1/applications/expected')

    def test_no_scope_output_for_raw_client_id(self):
        self.assertNotIn(RESOURCE, str(self.classify([BASE])))

if __name__ == '__main__':
    unittest.main()
