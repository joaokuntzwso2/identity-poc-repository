"""Offline negative and positive contract cases for P2.24 API resource query."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('p2_api_ga_v5_test',ROOT/'scripts/p2/m2m_bootstrap.py')
m=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

API='abcdef01-1111-4222-8333-abcdefabcdef'
ADMIN=('admin@aurora.identity.test','fixture-only-not-real')

class Fake:
    def __init__(self, *, key='apiResources', bad=None, total=None,
                 links=None, scopes=True, mismatch=False, double=False,
                 first_has_scope=True):
        self.key=key;self.bad=bad;self.total=total;self.links=links
        self.scopes=scopes;self.mismatch=mismatch;self.double=double
        self.first_has_scope=first_has_scope
        self.calls=[]
    def call(self, method, path, *, basic=None, **kwargs):
        self.calls.append((method,path))
        assert method=='GET' and path.startswith(m.API_ROOT), (method,path)
        if '/api-resources?' in path:
            identifier=parse_qs(urlsplit(path).query)['filter'][0].removeprefix('identifier eq ')
            rows=[] if identifier=='/o/api/server/v1/organizations' else [{'id':API,'identifier':identifier}]
            if self.bad=='invalid_id': rows[0]['id']='../../bad'
            if self.bad=='wrong_identifier': rows[0]['identifier']='/api/server/v1/applications'
            d={'totalResults':len(rows) if self.total is None else self.total,
               'links':[] if self.links is None else self.links}
            if self.key is not None:d[self.key]=rows
            if self.double:
                d['APIResources']=rows
                d['apiResources']=rows
            return (200,d,'')
        if path==m.API_ROOT+'/'+API:
            identifier='/api/server/v1/organizations'
            scopes=[{'name':m.SCOPE}] if self.scopes else [{'name':'internal_org_organization_create'}]
            if not self.first_has_scope: scopes=[]
            return (200,{'id':API, 'identifier':('different' if self.mismatch else identifier),'scopes':scopes},'')
        raise AssertionError(('unexpected_url',path))

class APIGATests(unittest.TestCase):
    def test_ga_lowercase_list_is_verified_via_detail(self):
        f=Fake(key='apiResources')
        r=m.pick_org_api(f,ADMIN)
        self.assertEqual(r['id'],API)
        self.assertEqual(len(f.calls),3)
        self.assertTrue(all(x=='GET' for x,_ in f.calls))
    def test_legacy_uppercase_is_accepted_for_compatibility(self):
        self.assertEqual(m.pick_org_api(Fake(key='APIResources'),ADMIN)['id'],API)
    def test_missing_collection_refused(self):
        with self.assertRaisesRegex(m.Block,'COLLECTION_MISSING_OR_AMBIGUOUS'):
            m.pick_org_api(Fake(key=None),ADMIN)
    def test_both_collection_variants_refused(self):
        with self.assertRaisesRegex(m.Block,'COLLECTION_MISSING_OR_AMBIGUOUS'):
            m.pick_org_api(Fake(double=True),ADMIN)
    def test_truncated_filtered_page_refused(self):
        with self.assertRaisesRegex(m.Block,'QUERY_INCOMPLETE'):
            m.pick_org_api(Fake(total=2),ADMIN)
    def test_cursor_next_on_exact_filter_refused(self):
        with self.assertRaisesRegex(m.Block,'CURSOR_INCOMPLETE'):
            m.pick_org_api(Fake(links=[{'rel':'next','href':'/anything'}]),ADMIN)
    def test_cursor_after_refused(self):
        with self.assertRaisesRegex(m.Block,'CURSOR_INCOMPLETE'):
            m.pick_org_api(Fake(links=[{'rel':'after','href':'/anything'}]),ADMIN)
    def test_malformed_links_refused(self):
        with self.assertRaisesRegex(m.Block,'LINKS_UNVERIFIED'):
            m.pick_org_api(Fake(links=[{'href':'x'}]),ADMIN)
    def test_wrong_identifier_refused(self):
        with self.assertRaisesRegex(m.Block,'LIST_ITEM_INVALID'):
            m.pick_org_api(Fake(bad='wrong_identifier'),ADMIN)
    def test_unsafe_id_refused(self):
        with self.assertRaisesRegex(m.Block,'LIST_ITEM_INVALID'):
            m.pick_org_api(Fake(bad='invalid_id'),ADMIN)
    def test_unverified_detail_refused(self):
        with self.assertRaisesRegex(m.Block,'DETAIL_UNVERIFIED'):
            m.pick_org_api(Fake(mismatch=True),ADMIN)
    def test_missing_view_scope_refused(self):
        with self.assertRaisesRegex(m.Block,'RESOURCE_NOT_UNAMBIGUOUS'):
            m.pick_org_api(Fake(scopes=False),ADMIN)
    def test_type_bool_total_refused(self):
        with self.assertRaisesRegex(m.Block,'QUERY_INCOMPLETE'):
            m._complete_filtered_api_resource_page({'apiResources':[],'totalResults':False,'links':[]})
    def test_missing_collection_does_not_imply_empty(self):
        with self.assertRaisesRegex(m.Block,'COLLECTION_MISSING_OR_AMBIGUOUS'):
            m._complete_filtered_api_resource_page({'totalResults':0,'links':[]})
    def test_unfiltered_multipart_catalog_cannot_be_mistaken_complete(self):
        with self.assertRaisesRegex(m.Block,'QUERY_INCOMPLETE'):
            m._complete_filtered_api_resource_page({'apiResources':[{'id':'x'}],
                     'totalResults':184,'links':[{'rel':'next','href':'/api'}]})
    def test_plan_does_not_write_journal_or_post(self):
        class F(Fake):
            def call(self,method,path,**kw):
                if path.startswith(m.APP_ROOT+'?'):
                    return (200,{'applications':[],'totalResults':0},'')
                return super().call(method,path,**kw)
        with tempfile.TemporaryDirectory(prefix='p2-ga-no-write-') as folder:
            d=Path(folder)
            f=F()
            result=m.bootstrap(f,d,ADMIN,'plan')
            self.assertEqual(result['remoteManagementWrites'],0)
            self.assertEqual(list(d.iterdir()),[])
            self.assertTrue(all(method=='GET' for method,_ in f.calls))

if __name__=='__main__': unittest.main()
