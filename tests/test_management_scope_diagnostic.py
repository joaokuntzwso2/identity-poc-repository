import importlib.util
from pathlib import Path
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/ciam-v10/oidc/management_scope_diagnostic.py'
spec = importlib.util.spec_from_file_location('scope_probe_under_test', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
S = module.SCOPES

class Classifier(unittest.TestCase):
    def test_full_grant(self):
        value = {'access_token':'TOP_SECRET','token_type':'Bearer','scope':' '.join(S)}
        import json
        res = module.classify_response(200,json.dumps(value).encode(),S)
        self.assertEqual(res['missing'], [])
        self.assertNotIn('TOP_SECRET', str(res))
    def test_partial_grant(self):
        res = module.classify_response(200,b'{"access_token":"SECRET","token_type":"Bearer","scope":"internal_application_mgt_view"}',S)
        self.assertEqual(res['granted'], [S[0]])
        self.assertEqual(res['missing'], list(S[1:]))
        self.assertNotIn('SECRET',str(res))
    def test_http_invalid_scope(self):
        res = module.classify_response(400,b'{"error":"SECRET"}',S)
        self.assertEqual(res['outcome'],'TOKEN_HTTP_400')
        self.assertNotIn('SECRET',str(res))
    def test_malformed_json(self):
        self.assertEqual(module.classify_response(200,b'bad',S)['outcome'],'INVALID_TOKEN_RESPONSE')
    def test_missing_token(self):
        self.assertEqual(module.classify_response(200,b'{"scope":"internal_application_mgt_view"}',S)['outcome'],'TOKEN_RESPONSE_UNUSABLE')
    def test_rejects_non_string_scope(self):
        self.assertEqual(module.classify_response(200,b'{"access_token":"x","token_type":"bearer","scope":["foo"]}',S)['outcome'],'TOKEN_RESPONSE_UNUSABLE')
    def test_unknown_scope_ignored(self):
        res=module.classify_response(200,b'{"access_token":"SECRET","token_type":"bearer","scope":"unexpected_string"}',S)
        self.assertEqual(res['granted'], [])
        self.assertNotIn('unexpected_string',str(res))
    def test_all_grants_single_request(self):
        p=mock.Mock(return_value={'outcome':'TOKEN_ISSUED','granted':list(S),'missing':[]})
        res=module.diagnostic(p)
        self.assertEqual(res['tokenRequests'], 1)
        p.assert_called_once_with(S)
    def test_missing_scopes_individually(self):
        p=mock.Mock(side_effect=[
            {'outcome':'TOKEN_ISSUED','granted':[S[0]],'missing':list(S[1:])},
            {'outcome':'TOKEN_ISSUED','granted':[S[0]],'missing':[]},
            {'outcome':'TOKEN_HTTP_400','granted':[],'missing':[S[1]]},
            {'outcome':'TOKEN_ISSUED','granted':[S[2]],'missing':[]},
        ])
        res=module.diagnostic(p)
        self.assertEqual(res['tokenRequests'],4)
        self.assertEqual(set(res['individual']),set(S))
    def test_no_unapproved_scope_allowed(self):
        with self.assertRaises(module.ProbeRefusal):
            module.token_probe(None, {'clientId':'x','clientSecret':'y'}, lambda *args:'Basic x',('internal_user_mgt_create',))

if __name__ == '__main__':
    unittest.main()
