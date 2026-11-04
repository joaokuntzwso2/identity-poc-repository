"""WSO2 IS 7.3 GA pagination: real doc shapes + denial of hostile references."""
import importlib.util
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

SCRIPT=next((p for p in (Path(__file__).resolve().parents[1]/'p2-bootstrap-authority.py',
                          Path(__file__).resolve().parents[1]/'scripts/p2-bootstrap-authority.py') if p.is_file()), None)
if SCRIPT is None:raise RuntimeError('P2 authority script not found')
spec=importlib.util.spec_from_file_location('p224_pagination_bridge',SCRIPT)
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class Pages:
    def __init__(self, url, payloads):
        self.url=url; self.payloads=list(payloads);self.calls=[]
    def call(self,method,path,*,auth):
        assert method=='GET' and auth=='Basic approved'
        assert path.startswith(self.url+'?'),path
        self.calls.append(path)
        if not self.payloads:raise AssertionError('Unexpected additional HTTP read')
        return 200,self.payloads.pop(0),None

class PaginationTests(unittest.TestCase):
    def test_catalog_relative_href(self):
        page1={'APIResources':[{'id':'id01'}], 'links':[{'rel':'next','href':'api-resources?after=Mg%3D%3D&limit=10'}]}
        page2={'APIResources':[{'id':'id02'}], 'totalResults':2}
        w=Pages(a.CATALOG,[page1,page2]); result=a.listing(w,a.CATALOG,'Basic approved',('APIResources',))
        self.assertEqual(len(result),2)
        self.assertEqual(parse_qs(urlsplit(w.calls[1]).query)['after'],['Mg=='])
        self.assertTrue(all(x.startswith('/t/aurora.identity.test/') for x in w.calls))
    def test_cursor_bare_root_and_absolute_pinned_links(self):
        for prefix in ('/api/server/v1/api-resources',
                       '/t/aurora.identity.test/api/server/v1/api-resources',
                       'https://localhost:9444/t/aurora.identity.test/api/server/v1/api-resources',
                       '?after=Mg%3D%3D&limit=10',
                       './api-resources'):
            with self.subTest(prefix=prefix):
                href=prefix if prefix.startswith('?') else prefix+'?after=Mg%3D%3D&limit=10'
                w=Pages(a.CATALOG,[{'APIResources':[{'id':'1'}], 'links':[{'rel':'next','href':href}]},
                                     {'APIResources':[{'id':'2'}], 'totalResults':2}])
                self.assertEqual(len(a.listing(w,a.CATALOG,'Basic approved',('APIResources',))),2)
    def test_documented_application_offset_pages(self):
        pages=[{'applications':[{'id':'1'},{'id':'2'}],
                'links':[{'rel':'next','href':'applications?offset=2&limit=2'}]},
               {'applications':[{'id':'3'}], 'totalResults':3}]
        w=Pages(a.APP_PREFIX,pages)
        self.assertEqual([x['id'] for x in a.listing(w,a.APP_PREFIX,'Basic approved',('applications',))],['1','2','3'])
        second=parse_qs(urlsplit(w.calls[1]).query)
        self.assertEqual(second['offset'],['2'])
        self.assertNotIn('after',second)
    def test_next_href_never_becomes_network_url(self):
        w=Pages(a.CATALOG,[{'APIResources':[{'id':'1'}],
                              'links':[{'rel':'next','href':'https://localhost:9444/api/server/v1/api-resources?after=Mw%3D%3D'}]},
                             {'APIResources':[{'id':'2'}], 'totalResults':2}])
        a.listing(w,a.CATALOG,'Basic approved',('APIResources',))
        self.assertTrue(all(x.startswith(a.CATALOG+'?') for x in w.calls))
    def test_foreign_origin_brisa_other_ports_credentials_and_fragment_blocked(self):
        bad=[
            'https://evil.example/api/server/v1/api-resources?after=Ng%3D%3D',
            'https://localhost.evil.example:9444/api/server/v1/api-resources?after=Ng%3D%3D',
            'https://localhost:9443/api/server/v1/api-resources?after=Ng%3D%3D',
            'http://localhost:9444/api/server/v1/api-resources?after=Ng%3D%3D',
            'https://user:pass@localhost:9444/api/server/v1/api-resources?after=Ng%3D%3D',
            '/t/brisa.identity.test/api/server/v1/api-resources?after=Ng%3D%3D',
            '/api/server/v1/organizations?after=Ng%3D%3D',
            '../api-resources?after=Ng%3D%3D',
            'api-resources?after=Ng%3D%3D#fragment',
        ]
        for href in bad:
            with self.subTest(href=href):
                w=Pages(a.CATALOG,[{'APIResources':[{'id':'1'}],'links':[{'rel':'next','href':href}]}])
                with self.assertRaises(a.Stop):a.listing(w,a.CATALOG,'Basic approved',('APIResources',))
                self.assertEqual(len(w.calls),1)
    def test_duplicate_unknown_and_missing_cursor_parameters_blocked(self):
        for query in ('after=Ng%3D%3D&after=Nw%3D%3D','before=Ng%3D%3D',
                      'after=','after=Ng%3D%3D&x=1','after=Ng%3D%3D&limit=0',
                      'after=Ng%3D%3D&bad'):
            with self.subTest(query=query):
                w=Pages(a.CATALOG,[{'APIResources':[{'id':'1'}],
                                    'links':[{'rel':'next','href':'api-resources?'+query}]}])
                with self.assertRaises(a.Stop):a.listing(w,a.CATALOG,'Basic approved',('APIResources',))
                self.assertEqual(len(w.calls),1)
    def test_cursor_loop_blocked(self):
        href='api-resources?after=MTA%3D'
        w=Pages(a.CATALOG,[{'APIResources':[{'id':'1'}], 'links':[{'rel':'next','href':href}]},
                           {'APIResources':[{'id':'2'}], 'links':[{'rel':'next','href':href}]}])
        with self.assertRaisesRegex(a.Stop,'PAGINATION_CURSOR_LOOP'):
            a.listing(w,a.CATALOG,'Basic approved',('APIResources',))
        self.assertEqual(len(w.calls),2)
    def test_offset_gaps_and_overlap_blocked(self):
        for offset in (1,3,100):
            w=Pages(a.APP_PREFIX,[{'applications':[{'id':'1'},{'id':'2'}],
                                  'links':[{'rel':'next','href':f'applications?offset={offset}&limit=2'}]}])
            with self.assertRaisesRegex(a.Stop,'PAGINATION_OFFSET_GAP_OR_OVERLAP'):
                a.listing(w,a.APP_PREFIX,'Basic approved',('applications',))
            self.assertEqual(len(w.calls),1)
    def test_empty_next_page_and_partial_results_blocked(self):
        w=Pages(a.CATALOG,[{'APIResources':[],'links':[{'rel':'next','href':'api-resources?after=Mg%3D%3D'}]}])
        with self.assertRaisesRegex(a.Stop,'EMPTY_PAGE_WITH_NEXT_LINK'):
            a.listing(w,a.CATALOG,'Basic approved',('APIResources',))
        w=Pages(a.CATALOG,[{'APIResources':[{'id':'1'}], 'totalResults':2}])
        with self.assertRaisesRegex(a.Stop,'PARTIAL_LIST_PAGINATION'):
            a.listing(w,a.CATALOG,'Basic approved',('APIResources',))
    def test_unattested_full_page_without_link_blocked(self):
        w=Pages(a.CATALOG,[{'APIResources':[{'id':'1'},{'id':'2'}]}])
        with self.assertRaisesRegex(a.Stop,'PAGINATION_COMPLETENESS_NOT_ATTESTED'):
            a.listing(w,a.CATALOG,'Basic approved',('APIResources',),limit=2)

if __name__=='__main__':unittest.main()
