from __future__ import annotations
import importlib.util
import pathlib
import re
import unittest

p=pathlib.Path(__file__).resolve().parents[2]/'scripts/p2/partner_access_v14.py'
s=importlib.util.spec_from_file_location('partner_access_v14_tests',p)
v=importlib.util.module_from_spec(s);s.loader.exec_module(v)
A='10000000-0000-4000-8000-000000000001'
B='10000000-0000-4000-8000-000000000002'
C='10000000-0000-4000-8000-000000000003'
class M:
    UUID=re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',re.I)

class Http:
    def __init__(self,responses): self.responses=responses;self.calls=[]
    def call(self,method,path,basic=None):
        self.calls.append((method,path,basic))
        data=self.responses[len(self.calls)-1]
        return 200,data,''

class Access(unittest.TestCase):
    def test_no_share_is_not_authorization(self):
        self.assertEqual(v.interpret_shares([],None,B,A),'NOT_SHARED')
    def test_selected_share_with_roles_is_still_not_business_auth(self):
        r={'id':B,'parentId':A,'status':'ACTIVE','sharingMode':{'policy':'SELECTED_ORG_ONLY',
           'roleSharing':{'mode':'SELECTED','roles':[{'displayName':'Partner Viewer',
                                                     'audience':{'type':'application','display':'Partner Portal'}}]}}}
        self.assertEqual(v.interpret_shares([r],None,B,A),
          'TARGETED_APP_SHARE_POLICY_OBSERVED_BUSINESS_AUTH_UNTESTED')
    def test_global_share_is_not_approved(self):
        r={'id':B,'sharingMode':{'policy':'SELECTED_ORG_ONLY','roleSharing':{'mode':'SELECTED','roles':[{'displayName':'x','audience':{}}]}}}
        self.assertEqual(v.interpret_shares([r],{'policy':'ALL_EXISTING_AND_FUTURE_ORGS'},B,A),
            'BROAD_OR_GLOBAL_SHARING_REVIEW')
    def test_missing_policy_cannot_prove(self):
        self.assertEqual(v.interpret_shares([{'id':B}],None,B,A),'PRESENT_POLICY_UNVERIFIED')
    def test_wrong_parent_fails(self):
        with self.assertRaisesRegex(v.Block,'PARENT_DRIFT'):
            v.interpret_shares([{'id':B,'parentId':C}],None,B,A)
    def test_duplicate_share_fails(self):
        with self.assertRaisesRegex(v.Block,'DUPLICATE'):
            v.interpret_shares([{'id':B},{'id':B}],None,B,A)
    def test_empty_collection_explicit(self):
        http=Http([{'organizations':[], 'links':[]}]);out,mode=v.read_shares(M,http,("admin@aurora.identity.test",'hidden'),A)
        self.assertEqual(out,[]);self.assertIsNone(mode)
        self.assertEqual(len(http.calls),1)
    def test_missing_collection_with_zero(self):
        http=Http([{'totalResults':0,'links':[]}]);out,_=v.read_shares(M,http,('admin@aurora.identity.test','hidden'),A)
        self.assertEqual(out,[])
    def test_omitted_collection_without_total_fails(self):
        with self.assertRaisesRegex(v.Block,'COLLECTION_OMITTED'):
            v.read_shares(M,Http([{'links':[]}]),('admin@aurora.identity.test','hidden'),A)
    def test_incomplete_total_fails(self):
        with self.assertRaisesRegex(v.Block,'INCOMPLETE_TOTAL'):
            v.read_shares(M,Http([{'organizations':[],'totalResults':1,'links':[]}]),('admin@aurora.identity.test','hidden'),A)
    def test_paged(self):
        href=f'/api/server/v1/applications/{A}/share?limit=100&recursive=false&after=MTA%3D'
        one={'organizations':[{'id':B}],'totalResults':2,'links':[{'rel':'next','href':href}]}
        two={'organizations':[{'id':C}],'totalResults':2,'links':[]}
        http=Http([one,two]);out,_=v.read_shares(M,http,('admin@aurora.identity.test','hidden'),A)
        self.assertEqual([x['id'] for x in out],[B,C]);self.assertEqual(len(http.calls),2)
        self.assertIn('/t/aurora.identity.test/',http.calls[1][1])
    def test_next_foreign_tenant_fails(self):
        with self.assertRaisesRegex(v.Block,'FOREIGN_PATH'):
            v.next_page_href(f'/t/brisa.identity.test/api/server/v1/applications/{A}/share?next=AA',A,set())
    def test_next_foreign_host_fails(self):
        with self.assertRaisesRegex(v.Block,'FOREIGN_ORIGIN'):
            v.next_page_href(f'https://evil.test/api/server/v1/applications/{A}/share?next=AA',A,set())
    def test_cursor_loop_fails(self):
        u=f'/api/server/v1/applications/{A}/share?next=ABC'
        self.assertIn('next=ABC',v.next_page_href(u,A,set()))
        with self.assertRaisesRegex(v.Block,'CURSOR_LOOP'):
            v.next_page_href(u,A,{'ABC'})
    def test_duplicate_paged_id_fails(self):
        href=f'/api/server/v1/applications/{A}/share?next=XYZ'
        with self.assertRaisesRegex(v.Block,'DUPLICATE'):
            v.read_shares(M,Http([{'organizations':[{'id':B}],'totalResults':2,'links':[{'rel':'next','href':href}]},
                                  {'organizations':[{'id':B}],'totalResults':2,'links':[]}]),('admin@aurora.identity.test','hidden'),A)
    def test_no_write_interface(self):
        source=p.read_text()
        self.assertNotIn("http.call('POST'",source)
        self.assertNotIn('authorized-apis',source)

if __name__=='__main__': unittest.main()
