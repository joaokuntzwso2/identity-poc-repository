import ast
import importlib.util
import json
from pathlib import Path
import types
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'deploy/ciam-v10/oidc/audience_oidc_schema_probe_v1.py'
spec = importlib.util.spec_from_file_location('ciam_schema_probe_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

V2 = types.SimpleNamespace(
    UPDATE_MEMBERS=frozenset({'clientId', 'idToken', 'hybridFlow'}),
    READ_ONLY_MEMBERS=frozenset({'state', 'clientSecretExpiresAt'}),
    without_secret=lambda d: {k: v for k, v in d.items()
                              if k not in {'clientSecret', 'clientSecretExpiresAt'}})

class SchemaTests(unittest.TestCase):
    def test_pinned_v2_hash_valid(self):
        self.assertEqual(len(m.EXPECTED_V2_SHA), 64)
        int(m.EXPECTED_V2_SHA, 16)
    def test_unknown_field_reported_without_value(self):
        out = m.render_field_names({'clientId': 'SECRET', 'unknownSecureField': 'VALUE'}, V2)
        self.assertEqual(out['unrecognizedFieldNames'], ['unknownSecureField'])
        self.assertNotIn('SECRET', json.dumps(out))
        self.assertNotIn('VALUE', json.dumps(out))
    def test_known_meta_reported_without_value(self):
        out = m.render_field_names({'state': 'ACTIVE'}, V2)
        self.assertEqual(out['knownGetOnlyFieldNames'], ['state'])
        self.assertNotIn('ACTIVE', json.dumps(out))
    def test_no_unknown(self):
        self.assertEqual(m.render_field_names({'idToken': {}}, V2)['unrecognizedFieldCount'], 0)
    def test_reject_many_unknown(self):
        with self.assertRaisesRegex(m.Refuse, 'TOO_MANY'):
            m.render_field_names({f'x{i}':i for i in range(33)}, V2)
    def test_reject_untrusted_key(self):
        with self.assertRaisesRegex(m.Refuse, 'UNSAFE_FIELD_NAME'):
            m.render_field_names({'private-token=abc': 1}, V2)
    def test_reject_long_key(self):
        with self.assertRaisesRegex(m.Refuse, 'UNSAFE_FIELD_NAME'):
            m.render_field_names({'x' * 65: 1}, V2)
    def test_reject_not_dict(self):
        with self.assertRaisesRegex(m.Refuse, 'OIDC_RESPONSE'):
            m.render_field_names([], V2)
    def test_same_unknown_sets_ok(self):
        result = m.schema_diff({'idToken':{},'newField':1,'clientSecret':'masked'},
                               {'idToken':{},'newField':1,'clientSecret':'real'}, V2)
        self.assertTrue(result['unknownFieldSetsMatch'])
    def test_differing_view_raises(self):
        with self.assertRaisesRegex(m.Refuse, 'VIEW_AND_PRIVILEGED'):
            m.schema_diff({'idToken':{}, 'other':'A'}, {'idToken':{},'other':'B'}, V2)
    def test_no_apply_entrypoint_no_mutating_network(self):
        tree = ast.parse(SCRIPT.read_text())
        self.assertNotIn('request_put(', SCRIPT.read_text())
        self.assertNotIn('request_patch(', SCRIPT.read_text())
        self.assertNotIn('atomic_journal(', SCRIPT.read_text())
        self.assertNotIn('exclusive_json(', SCRIPT.read_text())
        self.assertFalse(any(isinstance(n, ast.FunctionDef) and n.name == 'apply' for n in ast.walk(tree)))
    def test_v2_pin_is_correct(self):
        import hashlib
        real = SCRIPT.with_name('audience_apply_v2.py')
        if real.exists():
            self.assertEqual(hashlib.sha256(real.read_bytes()).hexdigest(), m.EXPECTED_V2_SHA)

if __name__ == '__main__':
    unittest.main()
