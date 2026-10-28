import copy
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = HERE / 'deploy/ciam-v10/oidc/management_authorized_api_type_probe_v3.py'
SPEC = importlib.util.spec_from_file_location('ciam_audit_v3', SCRIPT)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

class Reader:
    @staticmethod
    def unwrap_authorizations(data):
        if not isinstance(data, list):
            raise M.Refuse('AUTH_SHAPE_INVALID')
        return data

    @staticmethod
    def parse_scope_names(items):
        if not isinstance(items, list):
            raise M.Refuse('SCOPE_LIST_INVALID')
        scopes = [x.get('name') for x in items if isinstance(x, dict)]
        if len(scopes) != len(items) or not all(isinstance(x, str) for x in scopes):
            raise M.Refuse('SCOPE_INVALID')
        if len(set(scopes)) != len(scopes):
            raise M.Refuse('DUPLICATE_SCOPE')
        return set(scopes)

APPID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
APIID = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
APP = {'id': APPID, 'name': M.APP_NAME, 'isManagementApp': True}
MANAGEMENT = {'id': APPID, 'name': M.APP_NAME, 'domain': M.DOMAIN, 'state': 'verified'}
AUTH = {'id': APIID, 'identifier': M.APP_API, 'policyId': 'RBAC',
        'type': 'UNKNOWN_CUSTOM_ENUM',
        'authorizedScopes': [{'name': name} for name in sorted(M.REQUIRED_BEFORE)]}

class ProbeTests(unittest.TestCase):
    def evaluate(self, a=None, app=None, management=None, apiid=APIID):
        return M.evaluate(Reader, APP if app is None else app,
                          [AUTH] if a is None else a,
                          MANAGEMENT if management is None else management, apiid)

    def test_exact_metadata_observed_without_approval(self):
        p = self.evaluate()
        self.assertEqual(p['status'], 'VERIFIED_READBACK')
        self.assertEqual(p['observedAuthorizedApiType'], 'UNKNOWN_CUSTOM_ENUM')
        self.assertFalse(p['scopeAddPlanApproved'])
        self.assertIsNone(p['proposedPatch'])
        self.assertEqual(p['managementResourceWrites'], 0)

    def test_does_not_force_system(self):
        a = dict(AUTH, type='SYSTEM')
        p = self.evaluate([a])
        self.assertEqual(p['observedAuthorizedApiType'], 'SYSTEM')
        self.assertFalse(p['scopeAddPlanApproved'])

    def test_does_not_force_management(self):
        a = dict(AUTH, type='MANAGEMENT_API')
        self.assertEqual(self.evaluate([a])['observedAuthorizedApiType'], 'MANAGEMENT_API')

    def test_reject_raw_untrusted_type(self):
        a = dict(AUTH, type='PRIVATE\nACCESS_TOKEN=abc')
        with self.assertRaisesRegex(M.Refuse, '^AUTHORIZED_API_TYPE_FORMAT_UNEXPECTED$') as e:
            self.evaluate([a])
        self.assertNotIn('ACCESS_TOKEN', str(e.exception))

    def test_reject_malformed_type(self):
        for value in ('', 'a'*49, 77, None, {'type':'SYSTEM'}):
            with self.subTest(value=value), self.assertRaises(M.Refuse):
                self.evaluate([dict(AUTH, type=value)])

    def test_reject_missing_type(self):
        a = dict(AUTH)
        del a['type']
        with self.assertRaises(M.Refuse): self.evaluate([a])

    def test_reject_other_resource(self):
        with self.assertRaises(M.Refuse): self.evaluate(apiid='another-id')

    def test_reject_duplicate_resource(self):
        with self.assertRaises(M.Refuse): self.evaluate([AUTH, AUTH])

    def test_reject_identity_drift(self):
        with self.assertRaises(M.Refuse): self.evaluate(app=dict(APP, name='Another App'))

    def test_reject_policy_drift(self):
        with self.assertRaises(M.Refuse): self.evaluate([dict(AUTH, policyId='NO_AUTH')])

    def test_reject_identifier_drift(self):
        with self.assertRaises(M.Refuse): self.evaluate([dict(AUTH, identifier='/scim2/Users')])

    def test_reject_extra_scope(self):
        a = copy.deepcopy(AUTH)
        a['authorizedScopes'].append({'name':'unexpected'})
        with self.assertRaises(M.Refuse): self.evaluate([a])

    def test_reject_existing_update_scope(self):
        a = copy.deepcopy(AUTH)
        a['authorizedScopes'].append({'name':M.NEW_SCOPE})
        with self.assertRaises(M.Refuse): self.evaluate([a])

    def test_no_raw_private_ids(self):
        p = str(self.evaluate())
        self.assertNotIn(APPID, p)
        self.assertNotIn(APIID, p)

    def test_no_mutating_http_methods(self):
        source = SCRIPT.read_text()
        for token in ("'PATCH',", "'PUT',", "'DELETE',", "'POST', root"):
            self.assertNotIn(token, source)
        self.assertIn("'scope': 'internal_application_mgt_view'", source)

if __name__ == '__main__':
    unittest.main()
