"""Offline fail-closed tests; ZERO Docker/WSO2 connections or external writes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SRC = Path(__file__).resolve().parents[1] / 'deploy/ciam-v10/oidc/audience_apply.py'
spec = importlib.util.spec_from_file_location('v10_audience_apply_tests', SRC)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.node = {'id':'aud_v10_safe_1234', 'name':'Identity Lab v10 Aurora Web',
                     'clientId':'actual-client-id',
                     'clientSecret':'SECRET_HAS_NO_REAL_VALUE_1234567890',
                     'callback':'http://127.0.0.1:4400/auth/aurora-web/callback'}
        self.oidc = {
            'clientId':self.node['clientId'],
            'clientSecret':self.node['clientSecret'],
            'grantTypes':['authorization_code', 'refresh_token'],
            'callbackURLs':[self.node['callback']],
            'publicClient':False,
            'pkce':{'mandatory':True, 'supportPlainTransformAlgorithm':False},
            'accessToken':{'type':'JWT','userAccessTokenExpiryInSeconds':1800},
            'idToken':{'audience':[], 'expiryInSeconds':3600},
            'subject':{'subjectType':'pairwise'},
            'clientAuthentication':{'tokenEndpointAuthMethod':'client_secret_basic'},
            'allowedOrigins':[]
        }
        self.app = {'id':self.node['id'], 'name':self.node['name']}

    def test_normal_payload_is_full_document_with_exact_delta(self):
        candidate = a.prepare_payload(self.oidc, self.node)
        self.assertEqual(candidate['clientSecret'], self.node['clientSecret'])
        self.assertEqual(candidate['idToken']['audience'], [a.AUDIENCE])
        self.assertEqual(candidate['callbackURLs'], self.oidc['callbackURLs'])
        self.assertTrue(a.is_only_audience_delta(a.without_secret(self.oidc),
                                                 a.without_secret(candidate)))
        self.assertEqual(self.oidc['idToken']['audience'], [])

    def test_read_only_client_secret_expiry_removed_from_put(self):
        self.oidc['clientSecretExpiresAt'] = 0
        payload = a.prepare_payload(self.oidc, self.node)
        self.assertNotIn('clientSecretExpiresAt', payload)

    def test_unexpected_field_fail_closed(self):
        self.oidc['newCriticalSetting'] = True
        with self.assertRaisesRegex(a.Refuse, 'OIDC_UNDOCUMENTED_GET_FIELDS'):
            a.prepare_payload(self.oidc, self.node)

    def test_secret_mismatch_fail_closed(self):
        self.oidc['clientSecret'] = 'OTHER_SECRET_DO_NOT_USE_123456789'
        with self.assertRaisesRegex(a.Refuse, 'CLIENT_SECRET_JOURNAL_MISMATCH'):
            a.prepare_payload(self.oidc, self.node)

    def test_masked_secret_fail_closed(self):
        self.oidc['clientSecret'] = '*'*32
        with self.assertRaisesRegex(a.Refuse, 'CLIENT_SECRET_UNAVAILABLE_OR_MASKED'):
            a.prepare_payload(self.oidc, self.node)

    def test_malformed_audience_fail_closed(self):
        self.oidc['idToken']['audience'] = ['another-api']
        with self.assertRaisesRegex(a.Refuse, 'AUDIENCE_ALREADY_CHANGED'):
            a.prepare_payload(self.oidc, self.node)

    def test_changed_callback_fail_closed(self):
        self.oidc['callbackURLs'] = ['http://localhost:4400/other']
        with self.assertRaisesRegex(a.Refuse, 'CALLBACK_CHANGED'):
            a.prepare_payload(self.oidc, self.node)

    def test_full_fidelity_readback(self):
        before_public = a.without_secret(self.oidc)
        after = copy.deepcopy(self.oidc)
        after['idToken']['audience'] = [a.AUDIENCE]
        self.assertTrue(a.verify_after(self.app, before_public, self.app,
                                       a.without_secret(after), after, self.node))

    def test_extra_scope_or_expiry_change_fails_readback(self):
        after = copy.deepcopy(self.oidc)
        after['idToken']['audience'] = [a.AUDIENCE]
        after['accessToken']['userAccessTokenExpiryInSeconds'] = 500
        with self.assertRaisesRegex(a.Refuse, 'OIDC_READBACK_CHANGED_OTHER_FIELDS'):
            a.verify_after(self.app, a.without_secret(self.oidc), self.app,
                           a.without_secret(after), after, self.node)

    def test_app_metadata_drift_fails_readback(self):
        after = copy.deepcopy(self.oidc)
        after['idToken']['audience'] = [a.AUDIENCE]
        with self.assertRaisesRegex(a.Refuse, 'APPLICATION_GET_CHANGED'):
            a.verify_after(self.app, a.without_secret(self.oidc),
                           {**self.app,'modified':True}, a.without_secret(after), after, self.node)

    def test_no_wrong_path_can_put(self):
        with self.assertRaisesRegex(a.Refuse, 'UNSAFE_MUTATING_URL'):
            a.request_put(None, '/t/brisa.identity.test/api/server/v1/applications/abcdEF123/inbound-protocols/oidc', 'token', {})
        with self.assertRaisesRegex(a.Refuse, 'UNSAFE_MUTATING_URL'):
            a.request_put(None, '/t/aurora.identity.test/api/server/v1/applications/abcdEF123/inbound-protocols/oidc?x=1', 'token', {})

    def test_put_once_uses_only_expected_endpoint(self):
        path='/t/aurora.identity.test/api/server/v1/applications/abcdEF123/inbound-protocols/oidc'
        conn = MagicMock()
        conn.getresponse.return_value.status = 204
        conn.getresponse.return_value.read.return_value = b''
        with patch.object(a.http.client, 'HTTPSConnection', return_value=conn):
            a.request_put(None, path, 'Bearer placeholder', a.prepare_payload(self.oidc, self.node))
        conn.request.assert_called_once()
        args, kwargs = conn.request.call_args
        self.assertEqual(args[:2], ('PUT', path))
        self.assertEqual(json.loads(kwargs['body'])['idToken']['audience'], [a.AUDIENCE])
        self.assertEqual(conn.close.call_count, 1)

    def test_durable_backup_exclusive_and_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td) / 'backup.json'
            a.exclusive_json(p, {'secret':'DO_NOT_PRINT'})
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertEqual(a.read_private_json(p)['secret'], 'DO_NOT_PRINT')
            with self.assertRaises(FileExistsError):
                a.exclusive_json(p, {'something':'else'})

    def test_private_dir_refuses_group_readable_parent(self):
        with tempfile.TemporaryDirectory() as td:
            private=Path(td)/'private'; private.mkdir(mode=0o755)
            with self.assertRaisesRegex(a.Refuse, 'PRIVATE_DIRECTORY_NOT_OWNER_ONLY'):
                a.safe_private_dir(Path(td))

    def test_unknown_after_write_does_not_mutate(self):
        before = copy.deepcopy(self.oidc)
        after = copy.deepcopy(before)
        after['idToken']['audience'] = [a.AUDIENCE]
        after['subject']['subjectType'] = 'public'
        with self.assertRaises(a.Refuse):
            a.verify_after(self.app, a.without_secret(before), self.app,
                           a.without_secret(after), after, self.node)

if __name__=='__main__': unittest.main()
