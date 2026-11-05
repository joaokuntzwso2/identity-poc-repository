"""Offline regression checks for safe BFF PID/log preflight before manifest writes."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

OIDC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OIDC))
spec = importlib.util.spec_from_file_location('ciam_oidc_v6_process_preflight', OIDC / 'bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)

class ProcessFilesBeforePublishing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name)
        self.pid = self.private / 'bff-v10.pid'
        self.log = self.private / 'bff-v10.log'
        self.authority = {
            'WSO2_AUTHORITY_OIDC_SCOPE': 'ciam:profile:read',
            'WSO2_BUSINESS_API_AUDIENCE': 'https://api.ciam-v10.test/profile',
        }

    def launch(self, publisher):
        socket = mock.Mock()
        socket.connect_ex.return_value = 1
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(bootstrap, 'PRIVATE', self.private), \
             mock.patch.object(bootstrap, 'verified_authority_env', return_value=self.authority), \
             mock.patch('bff_runtime_config.build_cases_runtime_env', return_value={}), \
             mock.patch('socket.socket', return_value=socket), \
             mock.patch.object(bootstrap, 'publish_bff', side_effect=publisher):
            return bootstrap.start_bff({}, self.private)

    def test_existing_pid_refused_before_manifest_publish(self):
        self.pid.write_text('4242\n')
        self.pid.chmod(0o600)
        with self.assertRaisesRegex(bootstrap.Refuse, 'PIDFILE_EXISTS_REFUSED'):
            self.launch(AssertionError('private manifest was published'))
        self.assertEqual(self.pid.read_text(), '4242\n')
        self.assertFalse(self.log.exists())

    def test_pid_symlink_refused_before_manifest_publish(self):
        outside = self.private / 'unrelated.txt'
        outside.write_text('not a pid')
        self.pid.symlink_to(outside)
        with self.assertRaisesRegex(bootstrap.Refuse, 'PIDFILE_EXISTS_REFUSED'):
            self.launch(AssertionError('private manifest was published'))
        self.assertEqual(outside.read_text(), 'not a pid')

    def test_log_symlink_refused_before_manifest_publish(self):
        outside = self.private / 'unrelated.txt'
        outside.write_text('do not overwrite')
        self.log.symlink_to(outside)
        with self.assertRaisesRegex(bootstrap.Refuse, 'BFF_LOGFILE_SYMLINK_REFUSED'):
            self.launch(AssertionError('private manifest was published'))
        self.assertEqual(outside.read_text(), 'do not overwrite')
        self.assertFalse(self.pid.exists())

    def test_insecure_existing_log_refused_without_chmod(self):
        self.log.write_text('old bytes')
        self.log.chmod(0o644)
        with self.assertRaisesRegex(bootstrap.Refuse, 'BFF_LOGFILE_UNSAFE_REFUSED'):
            self.launch(AssertionError('private manifest was published'))
        self.assertEqual(stat.S_IMODE(self.log.stat().st_mode), 0o644)
        self.assertEqual(self.log.read_text(), 'old bytes')

    def test_safe_existing_log_allows_guarded_launch(self):
        self.log.write_text('old bytes')
        self.log.chmod(0o600)
        with mock.patch.object(bootstrap.subprocess, 'Popen', return_value=mock.Mock(pid=12345)) as popen:
            output = self.launch(lambda *a, **k: {'bffManifest': 'TEST_ONLY'})
        self.assertTrue(output['pidRecorded'])
        self.assertEqual(self.pid.read_text(), '12345\n')
        self.assertEqual(self.log.read_text(), 'old bytes')
        self.assertEqual(stat.S_IMODE(self.log.stat().st_mode), 0o600)
        popen.assert_called_once()

if __name__ == '__main__':
    unittest.main()
