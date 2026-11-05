import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

SEC = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SEC))

# Exact helper will be installed next to bootstrap.py by the overlay patch.
import management_oauth as m


class FakeResponse:
    def __init__(self, data, status=200):
        self.data = json.dumps(data).encode() if not isinstance(data, bytes) else data
        self.status = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getcode(self): return self.status
    def read(self, size): return self.data[:size]


class FakeOpener:
    def __init__(self, scopes):
        self.scopes = scopes
        self.calls = []
    def open(self, request, timeout):
        self.calls.append((request.full_url, request.get_method(), request.headers, request.data))
        if request.full_url.endswith('/oauth2/token'):
            form = __import__('urllib.parse', fromlist=['parse_qs']).parse_qs(request.data.decode())
            requested = form['scope'][0]
            scope = requested if self.scopes == 'match' else self.scopes
            return FakeResponse({'token_type': 'Bearer', 'access_token': 'a'*32, 'scope': scope})
        return FakeResponse({'applications': []})


class ManagementOAuthTests(unittest.TestCase):
    def test_exact_two_tenant_allowlist(self):
        self.assertEqual(set(m.DOMAINS), {'aurora.identity.test', 'brisa.identity.test'})
        with self.assertRaisesRegex(m.OAuthBlocked, 'UNSUPPORTED_TENANT'):
            m.management_request('/tmp', 'carbon.super', '/api/server/v1/applications', context=None)

    def test_only_known_management_api_families(self):
        self.assertEqual(m._api_scopes('/api/server/v1/applications?limit=100', 'GET'), m.APPLICATION_VIEW)
        self.assertEqual(m._api_scopes('/api/server/v1/applications/x', 'PATCH'), m.APPLICATION_WRITE)
        self.assertEqual(m._api_scopes('/api/server/v1/identity-governance/', 'GET'), m.GOVERNANCE_VIEW)
        self.assertEqual(m._api_scopes('/api/server/v1/identity-governance/id/connectors/one', 'PATCH'), m.GOVERNANCE_WRITE)
        for path in ['/api/server/v1/tenants', '/oauth2/token', '/api/server/v1/../users', '/api/server/v1/applicationsEvil']:
            with self.subTest(path=path):
                with self.assertRaises(m.OAuthBlocked): m._api_scopes(path, 'GET')

    def test_credential_source_existing_resource_journal_only(self):
        with tempfile.TemporaryDirectory() as t:
            p = pathlib.Path(t)
            prv = p / 'private'; prv.mkdir()
            journal = prv / 'bootstrap-resources-v10.private.json'
            journal.write_text(json.dumps({'tenants': {'aurora': {
                'domain': 'aurora.identity.test',
                'management': {'clientId': 'client-a', 'clientSecret': 'secret-a'}
            }, 'brisa': {
                'domain': 'brisa.identity.test',
                'management': {'clientId': 'client-b', 'clientSecret': 'secret-b'}
            }}}))
            journal.chmod(0o600)
            prv.chmod(0o700)
            self.assertEqual(m._management(p, 'aurora.identity.test'), ('client-a', 'secret-a'))
            self.assertEqual(m._management(p, 'brisa.identity.test'), ('client-b', 'secret-b'))
            prv.chmod(0o777)
            with self.assertRaisesRegex(m.OAuthBlocked, 'DIRECTORY_UNSAFE'):
                m._management(p, 'aurora.identity.test')
            prv.chmod(0o700)
            journal.chmod(0o644)
            with self.assertRaisesRegex(m.OAuthBlocked, 'UNSAFE'):
                m._management(p, 'aurora.identity.test')

    def test_mismatched_tenant_binding_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            private = pathlib.Path(t) / 'private'
            private.mkdir(mode=0o700)
            with patch.object(m, '_secure_load', return_value={'tenants': {'aurora': {
                'domain': 'brisa.identity.test', 'management': {'clientId':'aaa','clientSecret':'bbb'}}}}):
                with self.assertRaisesRegex(m.OAuthBlocked, 'DOMAIN_MISMATCH'):
                    m._management(t, 'aurora.identity.test')

    def test_read_only_bearer_request_and_scope_validation(self):
        fake=FakeOpener('match')
        with patch.object(m, '_opener', return_value=fake), patch.object(m, '_management', return_value=('id-a','secret-a')):
            result=m.management_request('/tmp', 'aurora.identity.test', '/api/server/v1/applications?limit=1', context=None)
        self.assertEqual(result, {'applications': []})
        self.assertEqual([x[1] for x in fake.calls], ['POST','GET'])
        self.assertIn('scope=internal_application_mgt_view', fake.calls[0][3].decode())
        self.assertTrue(fake.calls[1][2]['Authorization'].startswith('Bearer '))
        self.assertNotIn('secret-a', str(fake.calls[1]))
        self.assertNotIn('id-a', str(fake.calls[1]))

    def test_missing_scope_rejected_before_api_request(self):
        fake=FakeOpener('internal_application_mgt_create')
        with patch.object(m, '_opener', return_value=fake), patch.object(m, '_management', return_value=('id-a','secret-a')):
            with self.assertRaisesRegex(m.OAuthBlocked, 'SCOPE_OR_TOKEN'):
                m.management_request('/tmp','aurora.identity.test','/api/server/v1/applications',context=None)
        self.assertEqual(len(fake.calls), 1)

    def test_preflight_requests_both_write_scope_sets_without_patch(self):
        fake=FakeOpener('match')
        with patch.object(m, '_opener', return_value=fake), patch.object(m, '_management', return_value=('id-a','secret-a')):
            m.preflight_write_scopes('/tmp','brisa.identity.test',context=None)
        self.assertEqual([x[1] for x in fake.calls], ['POST', 'POST'])
        self.assertTrue(all('/oauth2/token' in x[0] for x in fake.calls))
        self.assertIn('internal_governance_update', fake.calls[1][3].decode())
        self.assertIn('internal_application_script_update', fake.calls[0][3].decode())

    def test_no_proxy_and_no_redirects(self):
        with patch('urllib.request.build_opener') as b:
            m._opener(None)
        self.assertTrue(any(isinstance(x, __import__('urllib.request', fromlist=['ProxyHandler']).ProxyHandler)
                            and x.proxies == {} for x in b.call_args.args))
        self.assertTrue(any(isinstance(x, m._NoRedirect) for x in b.call_args.args))

    def test_http_error_sanitized(self):
        from urllib.error import HTTPError
        class Refusing:
            def open(self, request, timeout):
                raise HTTPError(request.full_url, 403, 'sensitive body', {}, io.BytesIO(b'PRIVATE'))
        with self.assertRaisesRegex(m.OAuthBlocked, 'HTTP_403') as ctx:
            m._call(Refusing(), __import__('urllib.request', fromlist=['Request']).Request('https://localhost:9444/'))
        self.assertNotIn('PRIVATE', str(ctx.exception))

if __name__ == '__main__': unittest.main()
