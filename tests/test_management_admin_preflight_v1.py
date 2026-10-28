import hashlib
import importlib.util
import json
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'deploy/ciam-v10/oidc/management_admin_preflight_v1.py'
spec = importlib.util.spec_from_file_location('ciam_preflight_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def valid_token(scope=None):
    return {'access_token': 'do-not-log-token', 'token_type': 'Bearer',
            'scope': scope or ' '.join(sorted(m.REQUIRED_SCOPES))}


class TokenTests(unittest.TestCase):
    def test_three_required_scopes_granted(self):
        token, names = m.validate_token_response(valid_token())
        self.assertEqual(token, 'do-not-log-token')
        self.assertEqual(names, sorted(m.REQUIRED_SCOPES))

    def test_missing_update_scope_refuses(self):
        with self.assertRaises(m.Refuse) as ctx:
            m.validate_token_response(valid_token('internal_application_mgt_view internal_application_internal_api_update'))
        self.assertEqual(ctx.exception.reason, 'ADMIN_REQUIRED_SCOPES_NOT_GRANTED')
        self.assertEqual(ctx.exception.missing, ('internal_application_mgt_update',))

    def test_missing_internal_api_scope_refuses(self):
        with self.assertRaises(m.Refuse) as ctx:
            m.validate_token_response(valid_token('internal_application_mgt_view internal_application_mgt_update'))
        self.assertEqual(ctx.exception.missing, ('internal_application_internal_api_update',))

    def test_missing_view_scope_refuses(self):
        with self.assertRaises(m.Refuse) as ctx:
            m.validate_token_response(valid_token('internal_application_mgt_update internal_application_internal_api_update'))
        self.assertEqual(ctx.exception.missing, ('internal_application_mgt_view',))

    def test_invalid_token_refuses(self):
        for value in ({'access_token': '', 'scope': 'a', 'token_type': 'Bearer'},
                      {'access_token': 'secret', 'scope': 'a', 'token_type': 'mac'},
                      {'scope': 'a', 'token_type': 'Bearer'}, 'anything'):
            with self.subTest(value=value), self.assertRaises(m.Refuse):
                m.validate_token_response(value)

    def test_malformed_scopes_refuse(self):
        for value in (None, ['internal_application_mgt_update'], 12):
            response = valid_token()
            response['scope'] = value
            with self.subTest(value=value), self.assertRaises(m.Refuse):
                m.validate_token_response(response)

    def test_duplicate_scopes_refuse(self):
        response = valid_token()
        response['scope'] += ' internal_application_mgt_view'
        with self.assertRaises(m.Refuse):
            m.validate_token_response(response)

    def test_extra_scopes_do_not_obscure_required(self):
        response = valid_token()
        response['scope'] += ' extra_scope'
        self.assertEqual(m.validate_token_response(response)[1], sorted(m.REQUIRED_SCOPES))


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.home = Path(self.d.name)
        self.root = self.home / 'wso2-ciam-v10' / 'private'
        self.root.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        self.f = self.root / 'existing-admin.json'
        self.value = {'tenant': m.TENANT, 'clientId': 'separate-client', 'clientSecret': 'not-a-real-secret'}
        self.f.write_text(json.dumps(self.value), encoding='utf-8')
        self.f.chmod(0o600)
        self.p = mock.patch.object(m.Path, 'home', return_value=self.home)
        self.p.start()
        self.addCleanup(self.p.stop)

    def test_owner_only_credential_file(self):
        self.assertEqual(m.read_existing_admin_credentials(self.f), self.value)

    def test_reject_world_readable_file(self):
        self.f.chmod(0o644)
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(self.f)

    def test_reject_group_readable_private_directory(self):
        self.root.chmod(0o750)
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(self.f)

    def test_reject_symlink(self):
        link = self.root / 'link.json'
        link.symlink_to(self.f)
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(link)

    def test_reject_dotdot_escape(self):
        outside = self.home / 'wso2-ciam-v10' / 'other.json'
        outside.write_text(json.dumps(self.value))
        outside.chmod(0o600)
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(self.root / '..' / 'other.json')

    def test_reject_outside_private_home(self):
        other = self.home / 'other.json'
        other.write_text(json.dumps(self.value))
        other.chmod(0o600)
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(other)

    def test_reject_wrong_tenant(self):
        self.value['tenant'] = 'brisa.identity.test'
        self.f.write_text(json.dumps(self.value))
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(self.f)

    def test_reject_unknown_field(self):
        self.value['password'] = 'never'
        self.f.write_text(json.dumps(self.value))
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(self.f)

    def test_reject_empty_or_control_char_secrets(self):
        for value in ('', ' hi\nthere', ' x '):
            self.value['clientSecret'] = value
            self.f.write_text(json.dumps(self.value))
            with self.subTest(value=value), self.assertRaises(m.Refuse):
                m.read_existing_admin_credentials(self.f)

    def test_reject_symlinked_parent(self):
        actual = self.root / 'nested'
        actual.mkdir(mode=0o700)
        actual_file = actual / 'cred.json'
        actual_file.write_text(json.dumps(self.value))
        actual_file.chmod(0o600)
        link = self.root / 'alias'
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(m.Refuse):
            m.read_existing_admin_credentials(link / 'cred.json')


class IntegrationContractTests(unittest.TestCase):
    def test_pinned_v4_digest(self):
        base = Path(__file__).resolve().parents[1]
        p = base / 'deploy/ciam-v10/oidc/management_scope_add_plan_v4.py'
        # This file is separately installed in the user's checkout, not bundled here.
        self.assertEqual(len(m.V4_SHA), 64)
        if p.exists():
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), m.V4_SHA)

    def test_no_apply_mode_or_direct_write_transport(self):
        source = SCRIPT.read_text()
        self.assertNotIn("conn.request('PATCH'", source)
        self.assertNotIn("conn.request('PUT'", source)
        self.assertNotIn('subprocess.run([\'docker\', \'restart\'', source)
        self.assertNotIn("'apply'", source)

    def test_v4_exact_fingerprints_and_scope_only_patch(self):
        class V4:
            @staticmethod
            def evaluate(reader, app, auth, management, resource_id):
                return {'status': 'VERIFIED_READBACK',
                        'observedAuthorizedApiType': 'TENANT',
                        'proposedPatch': {'addedScopes': ['internal_application_mgt_update'],
                                          'removedScopes': []},
                        'applicationReadbackSha256': 'a',
                        'authorizedApiReadbackSha256': 'b',
                        'targetApiAuthorizationSha256': 'c'}
        self.assertEqual(m.evaluate(V4, None, {}, {}, {}, 'resource')['proposedPatch']['removedScopes'], [])

    def test_unexpected_patch_refuses(self):
        class V4:
            @staticmethod
            def evaluate(*args):
                return {'status':'VERIFIED_READBACK',
                        'proposedPatch': {'addedScopes': ['admin'], 'removedScopes': []}}
        with self.assertRaises(m.Refuse):
            m.evaluate(V4, None, {}, {}, {}, 'resource')


if __name__ == '__main__':
    unittest.main()
