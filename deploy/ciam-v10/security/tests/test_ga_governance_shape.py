import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('governance_ga', ROOT / 'governance.py')
gov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gov)


class GACatalogTests(unittest.TestCase):
    def get(self, t, url):
        self.assertEqual(t, 'aurora.identity.test')
        if url == '/api/server/v1/identity-governance':
            return [{'id': 'category-1', 'connectors': [{'id': 'connector-1'}]}]
        if url.endswith('/connectors'):
            return [{'id': 'connector-1'}]  # This GA list does not have values.
        if url.endswith('/connectors/connector-1'):
            return {'id': 'connector-1', 'properties': [
                {'name': k, 'value': 'false' if k.endswith('enable') else '5'}
                for k in gov.DESIRED[t]
            ]}
        raise AssertionError(url)

    def test_fetch_connector_details_when_listing_has_no_properties(self):
        found = gov.discovered('aurora.identity.test', self.get)
        self.assertEqual(set(found), set(gov.DESIRED['aurora.identity.test']))
        self.assertTrue(all('/connectors/connector-1' in x['path'] for x in found.values()))

    def test_malformed_category_rejected(self):
        with self.assertRaises(gov.GovernanceMismatch):
            gov.discovered('aurora.identity.test', lambda t, p: {'unexpected': []})

    def test_mismatch_in_detail_id_rejected(self):
        def changed(t, p):
            v = self.get(t, p)
            if p.endswith('/connectors/connector-1'):
                v['id'] = 'something-else'
            return v
        with self.assertRaisesRegex(gov.GovernanceMismatch, 'DETAIL_ID_MISMATCH'):
            gov.discovered('aurora.identity.test', changed)

    def test_duplicate_key_rejected(self):
        def duplicate(t, p):
            v = self.get(t, p)
            if p.endswith('/connectors/connector-1'):
                v['properties'].append(dict(v['properties'][0]))
            return v
        with self.assertRaisesRegex(gov.GovernanceMismatch, 'AMBIGUOUS'):
            gov.discovered('aurora.identity.test', duplicate)

    def test_bounded_categories(self):
        with self.assertRaisesRegex(gov.GovernanceMismatch, 'INVALID_CATEGORY'):
            gov.discovered('aurora.identity.test', lambda t, p: [{'id': str(i)} for i in range(31)])

    def test_other_tenant_not_accepted(self):
        with self.assertRaises(gov.GovernanceMismatch):
            gov.discovered('carbon.super', lambda *a: [])


if __name__ == '__main__':
    unittest.main()
