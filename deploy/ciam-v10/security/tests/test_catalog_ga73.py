"""WSO2 7.3 GA live-observed apiResources schema + bounded cursor handling."""
import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[4]
source = root / 'scripts' / 'magalu-scope-reconcile.py'
spec = importlib.util.spec_from_file_location('magalu_scope_reconcile_ga73', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CatalogGA73Test(unittest.TestCase):
    def test_live_lowercase_field(self):
        page = {'apiResources': [{'id': 'resource-1', 'name': 'API',
                 'identifier': 'api', 'type': 'SYSTEM',
                 'requiresAuthorization': True, 'self': '/api/server/v1/api-resources/resource-1'}],
                'links': [], 'totalResults': 1}
        items, total, after = m.parse_catalog_page(page)
        self.assertEqual([r['id'] for r in items], ['resource-1'])
        self.assertEqual(total, 1)
        self.assertIsNone(after)

    def test_legacy_uppercase_example(self):
        items, total, after = m.parse_catalog_page(
            {'APIResources': [{'id': 'r1'}], 'totalResults': 1, 'links': []})
        self.assertEqual((len(items), total, after), (1, 1, None))

    def test_reject_ambiguous_dual_key(self):
        with self.assertRaisesRegex(m.Blocked, 'CATALOG_FORMAT_CHANGED'):
            m.parse_catalog_page({'apiResources': [], 'APIResources': []})

    def test_cursor_pagination_with_lowercase_pages(self):
        class API:
            def __init__(self):
                self.paths = []
            def call(self, method, path):
                self.paths.append((method, path))
                if path == '/api/server/v1/api-resources?limit=100':
                    return {'apiResources': [{'id': 'r1', 'type': 'SYSTEM'}],
                            'totalResults': 2,
                            'links': [{'rel': 'before', 'href':
                                      '/api/server/v1/api-resources?after=MQ=='}]}
                if path == '/api/server/v1/api-resources?limit=100&after=MQ%3D%3D':
                    return {'apiResources': [{'id': 'r2', 'type': 'SYSTEM'}],
                            'totalResults': 2, 'links': []}
                raise AssertionError('unexpected endpoint')
        api = API()
        self.assertEqual(set(m.catalog(api)), {'r1', 'r2'})
        self.assertEqual(len(api.paths), 2)
        self.assertTrue(all(method == 'GET' for method, _ in api.paths))


if __name__ == '__main__':
    unittest.main()
