"""No-slash WSO2 7.3 GA endpoint regressions; no network calls."""
import pathlib
import sys
import unittest
from unittest.mock import patch

SEC = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SEC))
import governance as g
import management_oauth as oauth

CANONICAL = '/api/server/v1/identity-governance'


class CanonicalGovernanceTests(unittest.TestCase):
    def test_scope_classifier_reaches_supported_collection_without_slash(self):
        self.assertEqual(oauth._api_scopes(CANONICAL, 'GET'), oauth.GOVERNANCE_VIEW)
        self.assertEqual(oauth._api_scopes(CANONICAL + '/cat/connectors/x', 'PATCH'),
                         oauth.GOVERNANCE_WRITE)
        for name in ('/api/server/v1/identity-governance-rogue',
                     '/t/brisa.identity.test' + CANONICAL):
            with self.subTest(name=name), self.assertRaises(oauth.OAuthBlocked):
                oauth._api_scopes(name, 'GET')

    def test_collector_uses_only_canonical_no_slash_root(self):
        tenant = 'aurora.identity.test'
        calls = []
        props = [{'name': key, 'value': value} for key, value in g.DESIRED[tenant].items()]

        def fake_get(t, path):
            self.assertEqual(t, tenant)
            calls.append(path)
            if path == CANONICAL:
                return [{'id': 'cat'}]
            if path == CANONICAL + '/cat/connectors':
                return [{'id': 'connector', 'properties': props}]
            raise AssertionError('unexpected or redirected endpoint: ' + path)

        actual = g.discovered(tenant, fake_get)
        self.assertEqual(set(actual), set(g.DESIRED[tenant]))
        self.assertEqual(calls[0], CANONICAL)
        self.assertEqual(len(calls), 2)

    def test_auth_check_uses_canonical_governance_path(self):
        body = (SEC / 'bootstrap.py').read_text()
        start = body.index('def do_auth_check():')
        end = body.index('def do_inventory():', start)
        check = body[start:end]
        self.assertIn("('governance_view', '/api/server/v1/identity-governance'),", check)
        self.assertNotIn("('governance_view', '/api/server/v1/identity-governance/'),", check)

    def test_management_client_still_refuses_redirects(self):
        guard = oauth._NoRedirect()
        with self.assertRaisesRegex(oauth.OAuthBlocked, 'UNEXPECTED_HTTP_REDIRECT'):
            guard.redirect_request(None, None, 302, 'redirect', {},
                                   'https://localhost:9444/console')


if __name__ == '__main__':
    unittest.main()
