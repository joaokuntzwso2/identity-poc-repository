import importlib.util, json, re, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
P=(HERE/'overlay/scripts/p2/partner_share_ga_probe_v17_1.py' if (HERE/'overlay').is_dir() else HERE.parents[1]/'scripts/p2/partner_share_ga_probe_v17_1.py')
spec=importlib.util.spec_from_file_location('v171probe',P)
x=importlib.util.module_from_spec(spec);spec.loader.exec_module(x)
APP='11111111-1111-4111-8111-111111111111'
PARTNER='22222222-2222-4222-8222-222222222222'
FOREIGN='33333333-3333-4333-8333-333333333333'
class Http:
    def __init__(self,docs):self.docs=docs;self.calls=[]
    def call(self,method,path,basic=None):
        self.calls.append((method,path,basic))
        d=self.docs.get(path)
        if isinstance(d,Exception):raise d
        return (200,{} if d is None else d,{})

class TestProbe(unittest.TestCase):
    def test_empty_omitted_unverified(self):
        d=x.summarize('share',{},PARTNER,APP)
        self.assertEqual(d['collectionPresence'],'OMITTED')
        self.assertNotIn('collection',d)
    def test_empty_explicit_is_distinct(self):
        d=x.summarize('share',{'organizations':[]},PARTNER,APP)
        self.assertEqual(d['collectionPresence'],'PRESENT')
        self.assertEqual(d['collection']['count'],0)
    def test_null_is_distinct(self):
        self.assertEqual(x.summarize('shared-apps',{'sharedApplications':None},PARTNER,APP)['collectionPresence'],'NULL')
    def test_explicit_total_zero_is_reported_but_not_certified(self):
        d=x.summarize('share',{'totalResults':0},PARTNER,APP)
        self.assertEqual(d['totalResults'],0)
        self.assertEqual(d['collectionPresence'],'OMITTED')
    def test_broad_policy_disclosed_as_label_only(self):
        d=x.summarize('share',{'sharingMode':{'policy':'ALL_EXISTING_AND_FUTURE_ORGS','roleSharing':{'mode':'ALL'}}},PARTNER,APP)
        self.assertEqual(d['globalPolicy'],'OTHER_POLICY')
        self.assertEqual(d['globalRoleMode'],'ALL')
    def test_no_role_label(self):
        d=x.summarize('share',{'organizations':[{'id':PARTNER,'sharingMode':{'policy':'SELECTED_ORG_ONLY','roleSharing':{'mode':'NONE'}}}]},PARTNER,APP)
        self.assertEqual(d['collection']['targetMatches'],1)
        self.assertEqual(d['collection']['explicitNoRolesCount'],1)
    def test_foreign_names_and_ids_never_print(self):
        secret='VERY_PRIVATE_SUBJECT_1234567890'
        raw={'organizations':[{'id':FOREIGN,'name':secret,'metadata':{'token':secret}}],'secretKey':secret}
        out=json.dumps(x.summarize('share',raw,PARTNER,APP))
        self.assertNotIn(FOREIGN,out)
        self.assertNotIn(secret,out)
        self.assertEqual(json.loads(out)['unrecognizedFieldCount'],1)
    def test_shared_app_foreign_is_count_only(self):
        d=x.summarize('shared-apps',{'sharedApplications':[{'applicationId':APP,'organizationId':FOREIGN}]},PARTNER,APP)
        self.assertEqual(d['collection']['otherOrgReferences'],1)
        self.assertNotIn(FOREIGN,json.dumps(d))
    def test_untrusted_total_not_published(self):
        d=x.summarize('share',{'totalResults':'99886644'},PARTNER,APP)
        self.assertEqual(d['totalResults'],'UNTRUSTED')
    def test_untrusted_links_never_followed(self):
        d=x.summarize('share',{'links':[{'rel':'next','href':'https://evil.example/?token=x'}]},PARTNER,APP)
        self.assertEqual(d['pagination']['nextLinkCount'],1)
        self.assertNotIn('evil.example',json.dumps(d))
    def test_non_obj_is_not_assumed_empty(self):
        self.assertEqual(x.summarize('share',None,PARTNER,APP)['responseShape'],'NON_OBJECT')
    def test_call_get_only(self):
        http=Http({})
        output=x.snapshot(http,('admin@aurora.identity.test','testnotprinted'),APP,PARTNER)
        self.assertEqual(len(http.calls),5)
        self.assertTrue(all(t[0]=='GET' for t in http.calls))
        self.assertTrue(all(t[1].startswith(x.BASE+'/'+APP) for t in http.calls))
        self.assertEqual(output['shareDefault']['collectionPresence'],'OMITTED')
        self.assertNotIn('testnotprinted',json.dumps(output))
    def test_tenant_foreign_ids_block(self):
        http=Http({})
        with self.assertRaisesRegex(x.Refuse,'V17_1_INVALID_PINNED_ID'):
            x.snapshot(http,('admin','pwd'),'../../../other',PARTNER)
        self.assertFalse(http.calls)
    def test_http_readback_errors_sanitized(self):
        http=Http({x.BASE+'/'+APP:Exception('WSO2_GET_HTTP_403')})
        d=x.call_inspect(http,x.BASE+'/'+APP,'application',('a','b'),PARTNER,APP)
        self.assertEqual(d['httpStatus'],403)
    def test_non_http_error_not_reflected(self):
        http=Http({x.BASE+'/'+APP:Exception('SECRET:abcdefg')})
        d=x.call_inspect(http,x.BASE+'/'+APP,'application',('a','b'),PARTNER,APP)
        self.assertNotIn('SECRET',json.dumps(d))
    def test_invalid_readback_does_not_print_body(self):
        d=x.summarize('share',{'organizations':['supersecret']},PARTNER,APP)
        self.assertEqual(d['collection']['shape'],'INVALID_ITEM')
        self.assertNotIn('supersecret',json.dumps(d))
    def test_script_is_get_only(self):
        src=P.read_text()
        self.assertNotIn("http.call('POST'",src)
        self.assertNotIn('urllib.request.Request(',src)
    def test_pinned_v17_hash_is_correct(self):
        source=(HERE/'reference/partner_share_v17.py' if (HERE/'reference').is_dir() else HERE.parents[1]/'scripts/p2/partner_share_v17.py')
        import hashlib
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),x.SOURCE_SHA)
if __name__=='__main__':unittest.main()
