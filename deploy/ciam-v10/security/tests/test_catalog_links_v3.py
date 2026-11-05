"""No-network regression tests: WSO2 7.3 absolute + relative catalog links."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / 'scripts' / 'magalu-scope-reconcile.py'
spec = importlib.util.spec_from_file_location('magalu_scope_reconcile_v3', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
A = 'aurora.identity.test'
B = 'brisa.identity.test'


def page(href, rel='next', total=2):
    return {'apiResources': [{'id':'first'}], 'totalResults':total,
            'links':[{'rel': rel, 'href': href}]}


class CatalogLinksV3(unittest.TestCase):
    def test_accept_ga_absolute_loopback_9444(self):
        href='https://localhost:9444/t/'+A+'/api/server/v1/api-resources?limit=100&after=Mg%3D%3D'
        self.assertEqual(m.parse_catalog_page(page(href), A)[2], 'Mg==')

    def test_accept_container_port_9443_without_following_it(self):
        href='https://localhost:9443/t/'+A+'/api/server/v1/api-resources?after=Ng%3D%3D'
        self.assertEqual(m.parse_catalog_page(page(href), A)[2], 'Ng==')

    def test_accept_short_relative_cursor(self):
        self.assertEqual(m.parse_catalog_page(page('?after=MQ=='), A)[2], 'MQ==')

    def test_accept_absolute_offset_and_reconstruct_safe_get(self):
        href='https://127.0.0.1:9444/t/'+A+'/api/server/v1/api-resources?limit=100&offset=100'
        self.assertEqual(m.parse_catalog_page(page(href), A)[2], ('offset', 100))

    def test_ignore_previous_link_if_only_previous(self):
        self.assertIsNone(m.parse_catalog_page(page('https://evil.invalid/', rel='previous', total=1), A)[2])

    def test_refuse_offorigin_cross_tenant_and_unsafe_links(self):
        bad = [
            'https://evil.invalid/t/'+A+'/api/server/v1/api-resources?after=MQ==',
            'https://localhost:9444/t/'+B+'/api/server/v1/api-resources?after=MQ==',
            'https://localhost:9444@evil.invalid/t/'+A+'/api/server/v1/api-resources?after=MQ==',
            'https://u:p@localhost:9444/t/'+A+'/api/server/v1/api-resources?after=MQ==',
            'http://localhost:9444/t/'+A+'/api/server/v1/api-resources?after=MQ==',
            'https://localhost:9445/t/'+A+'/api/server/v1/api-resources?after=MQ==',
            'https://localhost:9444/t/'+A+'/api/server/v1/other?after=MQ==',
            '/t/'+A+'/api/server/v1/../applications?after=MQ==',
            '/api/server/v1/api-resources?after=MQ==#fragment',
            '/api/server/v1/api-resources?limit=100&after=MQ==&admin=1',
            '/api/server/v1/api-resources?limit=100&after=MQ==&after=Mg==',
            '/api/server/v1/api-resources?after=',
            '/api/server/v1/api-resources?offset=-1',
        ]
        for href in bad:
            with self.subTest(href=href), self.assertRaises(m.Blocked):
                m.parse_catalog_page(page(href), A)

    def test_reject_ambiguous_next_links(self):
        p=page('/api/server/v1/api-resources?after=MQ==')
        p['links'].append({'rel':'next','href':'/api/server/v1/api-resources?after=Mg=='})
        with self.assertRaisesRegex(m.Blocked, 'DUPLICATE_NEXT_LINK'):
            m.parse_catalog_page(p, A)

    def test_two_page_absolute_cursor_no_cross_origin_follow(self):
        class C:
            tenant = A
            def __init__(self): self.calls=[]
            def call(self, method, path):
                self.calls.append((method,path))
                if len(self.calls)==1:
                    return {'apiResources':[{'id':'r1'}], 'totalResults':2,
                            'links':[{'rel':'next','href':'https://localhost:9443/t/'+A+'/api/server/v1/api-resources?after=MQ%3D%3D&limit=100'}]}
                return {'apiResources':[{'id':'r2'}], 'totalResults':2, 'links':[]}
        c=C()
        self.assertEqual(set(m.catalog(c)), {'r1','r2'})
        self.assertEqual(c.calls, [('GET','/api/server/v1/api-resources?limit=100'),
                                   ('GET','/api/server/v1/api-resources?limit=100&after=MQ%3D%3D')])

    def test_offset_two_pages_reconstructed(self):
        class C:
            tenant = B
            def __init__(self): self.calls=[]
            def call(self, method, path):
                self.calls.append((method,path))
                if len(self.calls)==1:
                    return {'apiResources':[{'id':'r1'}], 'totalResults':2,
                            'links':[{'rel':'next','href':'/t/'+B+'/api/server/v1/api-resources?offset=100&limit=100'}]}
                return {'apiResources':[{'id':'r2'}], 'totalResults':2, 'links':[]}
        c=C()
        self.assertEqual(set(m.catalog(c)), {'r1','r2'})
        self.assertEqual(c.calls[1][1], '/api/server/v1/api-resources?limit=100&offset=100')

    def test_repeated_cursor_rejected(self):
        class C:
            tenant = A
            def call(self, method, path):
                return {'apiResources':[{'id':'r'+str(len(path))}], 'totalResults':3,
                        'links':[{'rel':'next','href':'/api/server/v1/api-resources?after=MQ=='}]}
        with self.assertRaises(m.Blocked): m.catalog(C())

if __name__=='__main__': unittest.main()
