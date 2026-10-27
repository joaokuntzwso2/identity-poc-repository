import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIR))
def module(name, fname):
    s = importlib.util.spec_from_file_location(name, DIR/fname)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m

P = module('introspection_policy','introspection_policy.py')
M = module('introspection_maintenance','introspection_maintenance.py')

class IntrospectionConfigTests(unittest.TestCase):
    def test_fresh_config_has_pinned_scope_and_handler(self):
        text = P.ensure_introspection_policy('[server]\nbase_path = "https://localhost:9444"\n')
        self.assertEqual(text.count('BasicClientAuthentication'),1)
        self.assertIn('scopes = ["internal_oauth2_introspect"]', text)
        self.assertEqual(P.ensure_introspection_policy(text), text)
    def test_no_weakening_existing_introspection_scopes(self):
        with self.assertRaises(P.PolicyRefused):
            P.ensure_introspection_policy('[resource_access_control.introspect]\nscopes = []\n')
    def test_cross_tenant_introspection_must_remain_disabled(self):
        with self.assertRaises(P.PolicyRefused):
            P.ensure_introspection_policy('[oauth.introspect]\nallow_cross_tenant=true\n')
        with self.assertRaises(P.PolicyRefused):
            P.ensure_introspection_policy('[oauth.introspect]\nallow_cross_sub_org=true\n')
    def test_no_broader_scope_set(self):
        with self.assertRaises(P.PolicyRefused):
            P.ensure_introspection_policy('[resource_access_control.introspect]\nscopes=["internal_oauth2_introspect","other"]\n')
    def test_no_conflicting_handlers(self):
        with self.assertRaises(P.PolicyRefused):
            P.ensure_introspection_policy('[[resource.access_control]]\ncontext="/oauth2/introspect"\nallowed_auth_handlers="all"\n')
    def test_no_duplicate_handler(self):
        text = P.HANDLER + '\n' + P.HANDLER
        with self.assertRaises(P.PolicyRefused):P.ensure_introspection_policy(text)
    def test_nonintrospection_rule_preserved(self):
        text = '''[[resource.access_control]]
context="/api/identity/"
http_method="get"
secure=true
allowed_auth_handlers="BasicAuthentication"
'''
        new = P.ensure_introspection_policy(text)
        self.assertIn(text, new)
    def test_no_writes_without_stage_confirmation(self):
        with mock.patch.dict('os.environ', {}, clear=True):
            with self.assertRaisesRegex(M.Refuse,'CONFIRMATION'):
                M.cmd_stage()
    def test_no_restart_without_separate_confirmation(self):
        with mock.patch.dict('os.environ', {}, clear=True):
            with self.assertRaisesRegex(M.Refuse,'CONFIRMATION'):
                M.cmd_restart()
    def test_private_file_modes_enforced(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/'deployment.toml'
            p.write_text('secret')
            p.chmod(0o644)
            with self.assertRaises(M.Refuse):M.private_file(p)
            p.chmod(0o600)
            self.assertEqual(M.private_file(p),b'secret')
    def test_stage_refuses_uncertain_previous_journal(self):
        with tempfile.TemporaryDirectory() as t:
            journal=Path(t)/'journal';journal.write_text('pending')
            backup=Path(t)/'backup'
            with (mock.patch.dict('os.environ', {'WSO2_CIAM_V10_INTROSPECTION_CONFIG_CONFIRM':M.STAGE_CONFIRM}),
                  mock.patch.object(M,'plan', return_value=({'current': b'x'},b'y')),
                  mock.patch.object(M,'JOURNAL',journal),mock.patch.object(M,'BACKUP',backup)):
                with self.assertRaisesRegex(M.Refuse,'PREVIOUS_STAGING'):
                    M.cmd_stage()
    def test_existing_rules_do_not_grant_privileges(self):
        text=P.ensure_introspection_policy('[server]\nhostname="localhost"\n')
        self.assertNotIn('scopes = []',text)
        self.assertNotIn('consent_mgt',text)

if __name__=='__main__': unittest.main()
