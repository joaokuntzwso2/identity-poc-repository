import copy
import hashlib
import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / 'deploy/ciam-v10/oidc/management_scope_add_plan_v4.py'
spec = importlib.util.spec_from_file_location('scope_plan_v4', SRC)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

READER = ROOT / 'deploy/ciam-v10/oidc/management_authorization_readback.py'
if READER.exists():
    rspec = importlib.util.spec_from_file_location('reader', READER)
    R = importlib.util.module_from_spec(rspec)
    rspec.loader.exec_module(R)
else:
    class R:
        @staticmethod
        def unwrap_authorizations(data):
            return data if isinstance(data, list) else data['authorizedAPIs']
        @staticmethod
        def parse_scope_names(data):
            if not isinstance(data, list):
                raise ValueError('SCOPES_NOT_ARRAY')
            names = [s.get('name') for s in data]
            if any(not isinstance(s, str) for s in names) or len(names) != len(set(names)):
                raise ValueError('SCOPES_INVALID')
            return set(names)

APP_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
API_ID = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
APP = {'id': APP_ID, 'name': M.APP_NAME, 'isManagementApp': True}
MANAGEMENT = {'id': APP_ID, 'name': M.APP_NAME, 'domain': M.DOMAIN, 'state': 'verified'}
AUTH = {'id': API_ID, 'identifier': M.APP_API, 'policyId': 'RBAC', 'type': 'TENANT',
        'authorizedScopes': [{'name': s} for s in sorted(M.REQUIRED_BEFORE)]}

def digest(o):
    return hashlib.sha256(json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()

class PlanTests(unittest.TestCase):
    def run_plan(self, *, app=None, auths=None, management=None, resource_id=API_ID, pin=True):
        a = APP if app is None else app
        b = [AUTH] if auths is None else auths
        m = MANAGEMENT if management is None else management
        if pin:
            with patch.object(M, 'EXPECTED_APP_SHA', digest(a)), patch.object(M, 'EXPECTED_AUTH_LIST_SHA', digest(b)), patch.object(M, 'EXPECTED_TARGET_AUTH_SHA', digest(b[0])):
                return M.evaluate(R, a, b, m, resource_id)
        return M.evaluate(R, a, b, m, resource_id)

    def test_live_fingerprints_pinned(self):
        self.assertEqual(M.EXPECTED_APP_SHA, '2b0121de738802c643d30f84d3b123a2f3b4e22b8874a34950a5fc148a22f756')
        self.assertEqual(M.EXPECTED_AUTH_LIST_SHA, '69ed9885664735f171c4d2327987fde5f7b2fd8e277ff025e6686aac92bb756f')
        self.assertEqual(M.EXPECTED_TARGET_AUTH_SHA, 'd7c89a7cbc4f1bb85b9404a83d5610121147b0c8da0108d47b320cdb91d69972')
    def test_tenant_type_expected_with_exact_identity(self):
        p = self.run_plan()
        self.assertEqual(p['status'], 'VERIFIED_READBACK')
        self.assertEqual(p['observedAuthorizedApiType'], 'TENANT')
        self.assertEqual(p['proposedPatch'], {'addedScopes': [M.NEW_SCOPE], 'removedScopes': []})
        self.assertEqual(p['managementResourceWrites'], 0)
        self.assertFalse(p['adminAuthorizationVerified'])
        self.assertFalse(p['safeForAutomaticApply'])
        self.assertTrue(p['requiresExplicitSeparateAdminApproval'])
    def test_system_refused(self):
        with self.assertRaisesRegex(M.Refuse, 'TYPE_NOT_OBSERVED_TENANT'):
            self.run_plan(auths=[dict(AUTH, type='SYSTEM')])
    def test_business_refused(self):
        with self.assertRaises(M.Refuse):
            self.run_plan(auths=[dict(AUTH, type='BUSINESS')])
    def test_unknown_refused_without_echo(self):
        with self.assertRaisesRegex(M.Refuse, 'TYPE_NOT_OBSERVED_TENANT') as e:
            self.run_plan(auths=[dict(AUTH, type='UNSAFE\nsecret')])
        self.assertNotIn('secret', str(e.exception))
    def test_missing_type_refused(self):
        a = dict(AUTH); a.pop('type')
        with self.assertRaises(M.Refuse): self.run_plan(auths=[a])
    def test_wrong_app_id(self):
        with self.assertRaises(M.Refuse): self.run_plan(app=dict(APP, id='other'))
    def test_wrong_app_name(self):
        with self.assertRaises(M.Refuse): self.run_plan(app=dict(APP, name='other'))
    def test_wrong_tenant(self):
        with self.assertRaises(M.Refuse): self.run_plan(management=dict(MANAGEMENT, domain='other'))
    def test_wrong_api_id(self):
        with self.assertRaises(M.Refuse): self.run_plan(resource_id='other')
    def test_wrong_api_path(self):
        with self.assertRaises(M.Refuse): self.run_plan(auths=[dict(AUTH, identifier='/wrong')])
    def test_wrong_policy(self):
        with self.assertRaises(M.Refuse): self.run_plan(auths=[dict(AUTH, policyId='NO_AUTHORIZATION')])
    def test_duplicate_api_id(self):
        with self.assertRaises(M.Refuse): self.run_plan(auths=[AUTH, AUTH])
    def test_update_already_present(self):
        a = copy.deepcopy(AUTH); a['authorizedScopes'].append({'name': M.NEW_SCOPE})
        with self.assertRaises(M.Refuse): self.run_plan(auths=[a])
    def test_extra_scope_refused(self):
        a = copy.deepcopy(AUTH); a['authorizedScopes'].append({'name': 'extra'})
        with self.assertRaises(M.Refuse): self.run_plan(auths=[a])
    def test_duplicate_scope_refused(self):
        a = copy.deepcopy(AUTH); a['authorizedScopes'].append(a['authorizedScopes'][0])
        with self.assertRaises(Exception): self.run_plan(auths=[a])
    def test_missing_scope_refused(self):
        a = copy.deepcopy(AUTH); a['authorizedScopes'].pop()
        with self.assertRaises(M.Refuse): self.run_plan(auths=[a])
    def test_drift_from_pinned_snapshot_refused(self):
        with self.assertRaisesRegex(M.Refuse, 'FINGERPRINT_CHANGED'):
            self.run_plan(pin=False)
    def test_pinned_target_drift_refused(self):
        with patch.object(M, 'EXPECTED_TARGET_AUTH_SHA', '0'*64):
            with patch.object(M, 'EXPECTED_APP_SHA', digest(APP)), patch.object(M, 'EXPECTED_AUTH_LIST_SHA', digest([AUTH])):
                with self.assertRaisesRegex(M.Refuse, 'TARGET_API_FINGERPRINT_CHANGED'):
                    M.evaluate(R, APP, [AUTH], MANAGEMENT, API_ID)
    def test_output_has_no_private_ids(self):
        p = str(self.run_plan())
        self.assertNotIn(APP_ID, p)
        self.assertNotIn(API_ID, p)
    def test_no_mutating_api_calls(self):
        s = SRC.read_text()
        for method in ("'PATCH'", "'PUT'", "'DELETE'"):
            self.assertNotIn(method, s)
        self.assertIn("'scope': 'internal_application_mgt_view'", s)

if __name__ == '__main__':
    unittest.main()
