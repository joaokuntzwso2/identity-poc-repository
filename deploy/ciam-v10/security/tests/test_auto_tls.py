"""No live WSO2 calls; TLS bootstrap must not silently disable verification."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import trusted_tls as t


class TlsResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        (self.home / 'private').mkdir()
        t._CACHE.clear()

    def test_keystore_public_cert_uses_stdin_not_cli_secret(self):
        (self.home / 'private/deployment.toml').write_text(
            '[keystore.tls]\nfile_name = "wso2carbon.jks"\n'
            'alias = "wso2carbon"\npassword = "secret-storepass"\n')
        result = Mock(returncode=0, stdout='-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----')
        with patch.object(t.subprocess, 'run', return_value=result) as call:
            pem = t._keystore_pubcert(self.home, lambda p: {
                'is_id': 'pinned-v10-id', 'carbon_home': '/opt/ga'})
        args = call.call_args.args[0]
        self.assertIn('docker', args)
        self.assertIn('pinned-v10-id', args)
        self.assertNotIn('secret-storepass', str(args))
        self.assertEqual(call.call_args.kwargs['input'], 'secret-storepass\n')
        self.assertTrue(pem.startswith('-----BEGIN CERTIFICATE-----'))

    def test_no_public_keystore_password_refuses(self):
        (self.home / 'private/deployment.toml').write_text(
            '[keystore.tls]\nfile_name = "wso2carbon.jks"\n'
            'alias = "wso2carbon"\npassword = "${SOME_ENV}"\n')
        with self.assertRaises(t.TlsBootstrapError):
            t._keystore_pubcert(self.home, lambda p: {})

    def test_default_system_context_without_override(self):
        mock_ctx = Mock()
        with patch.dict(os.environ, {'CIAM_V10_CA_CERT': ''}), \
             patch.object(t.ssl, 'create_default_context', return_value=mock_ctx) as mk, \
             patch.object(t, '_verify_peer', return_value=mock_ctx) as verify:
            actual = t.trusted_context(self.home, lambda _: {})
        self.assertIs(actual, mock_ctx)
        mk.assert_called_once_with()
        verify.assert_called_once_with(mock_ctx)

    def test_ca_override_preserves_peer_verification(self):
        mock_ctx = Mock()
        with patch.dict(os.environ, {'CIAM_V10_CA_CERT': '/known/ca.pem'}), \
             patch.object(t.ssl, 'create_default_context', return_value=mock_ctx) as mk, \
             patch.object(t, '_verify_peer', return_value=mock_ctx):
            actual = t.trusted_context(self.home, lambda _: {})
        self.assertIs(actual, mock_ctx)
        mk.assert_called_once_with(cafile='/known/ca.pem')


if __name__ == '__main__':
    unittest.main()
