"""Fail-closed BFF startup preflight regression checks; no network or writes."""
import ast
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

OIDC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OIDC))
spec = importlib.util.spec_from_file_location('v10_oidc_bootstrap_preflight_v5', OIDC / 'bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class PreflightBeforePublishing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.authority = {'WSO2_AUTHORITY_OIDC_SCOPE': 'ciam:profile:read',
                          'WSO2_BUSINESS_API_AUDIENCE': 'https://api.ciam-v10.test/profile'}

    def test_cases_policy_conflict_rejected_before_private_manifest(self):
        from bff_runtime_config import RuntimeConfigurationError
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(bootstrap, 'verified_authority_env', return_value=self.authority), \
             mock.patch('bff_runtime_config.build_cases_runtime_env',
                        side_effect=RuntimeConfigurationError('BFF_RUNTIME_CONFLICT_WSO2_CASES_SCOPES_ENABLED')), \
             mock.patch.object(bootstrap, 'publish_bff', side_effect=AssertionError('manifest write')):
            with self.assertRaisesRegex(bootstrap.Refuse, 'BFF_RUNTIME_CONFLICT'):
                bootstrap.start_bff({}, self.repo)

    def test_busy_port_refused_before_private_manifest(self):
        fake_socket = mock.Mock()
        fake_socket.connect_ex.return_value = 0
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(bootstrap, 'verified_authority_env', return_value=self.authority), \
             mock.patch('bff_runtime_config.build_cases_runtime_env', return_value={}), \
             mock.patch('socket.socket', return_value=fake_socket), \
             mock.patch.object(bootstrap, 'publish_bff', side_effect=AssertionError('manifest write')):
            with self.assertRaisesRegex(bootstrap.Refuse, 'PORT_4400_IN_USE_REFUSED'):
                bootstrap.start_bff({}, self.repo)
            fake_socket.close.assert_called_once()

    def test_production_mode_is_not_silently_overridden_to_development(self):
        with mock.patch.dict(os.environ, {'NODE_ENV': 'production'}, clear=True), \
             mock.patch.object(bootstrap, 'verified_authority_env',
                               side_effect=AssertionError('must refuse before journal read')), \
             mock.patch.object(bootstrap, 'publish_bff',
                               side_effect=AssertionError('manifest write')):
            with self.assertRaisesRegex(bootstrap.Refuse, 'NOT_FOR_PRODUCTION'):
                bootstrap.start_bff({}, self.repo)

    def test_preflights_run_in_order_before_private_manifest(self):
        tree = ast.parse((OIDC / 'bootstrap.py').read_text())
        fn = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == 'start_bff')
        calls = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name) and n.func.id in ('verified_authority_env', 'build_cases_runtime_env', 'publish_bff'):
                    calls[n.func.id] = n.lineno
                if isinstance(n.func, ast.Attribute) and n.func.attr in ('connect_ex', 'Popen'):
                    calls[n.func.attr] = n.lineno
        self.assertLess(calls['verified_authority_env'], calls['build_cases_runtime_env'])
        self.assertLess(calls['build_cases_runtime_env'], calls['connect_ex'])
        self.assertLess(calls['connect_ex'], calls['publish_bff'])
        self.assertLess(calls['publish_bff'], calls['Popen'])


if __name__ == '__main__':
    unittest.main()
