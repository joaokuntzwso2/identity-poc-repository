"""WSO2 7.3 GA observed empty JSON sharing envelopes; never infer shared access."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

SRC = next((p/'scripts/p2-bootstrap-share.py' for p in Path(__file__).resolve().parents if (p/'scripts/p2-bootstrap-share.py').is_file()),None)
if SRC is None: raise RuntimeError('P224_SHARE_SOURCE_NOT_FOUND')
spec=importlib.util.spec_from_file_location('p224_ga_empty_share',SRC)
share=importlib.util.module_from_spec(spec);spec.loader.exec_module(share)
PARTNER='629e590a-9072-406d-95a8-71f0cfc52cbe'
ROOT='5252717e-1024-40f0-89ee-016b513d36f3'
APP='1b4be256-ee33-4e76-ada6-6cb3ac62fdac'
PRIOR='existing_v10_owner_app'

class Wire:
    def __init__(self, *, share_after_post='array', initial_shared=False, switch_http=400,
                 switch_wrong_tenant=False, secondary_override=None):
        self.share_after_post=share_after_post
        self.initial_shared=initial_shared
        self.switch_http=switch_http
        self.switch_wrong_tenant=switch_wrong_tenant
        self.secondary_override=secondary_override
        self.calls=[];self.share_posts=0
    def call(self,method,path,*,auth,payload=None,form=None):
        self.calls.append((method,path,payload,form))
        if method=='GET' and path.endswith('/shared-apps'):
            return 200, self.secondary_override if self.secondary_override is not None else {},None
        if method=='GET' and path.endswith('/share'):
            if self.initial_shared or (self.share_posts and self.share_after_post=='array'):
                return 200,{'organizations':[{'id':PARTNER}]},None
            return 200,{},None
        if method=='POST' and path.endswith('/share'):
            assert payload=={'shareWithAllChildren':False,'sharedOrganizations':[PARTNER]}
            self.share_posts+=1
            return 200,{},None
        if method=='POST' and path.endswith('/oauth2/token'):
            assert form and form['grant_type']=='organization_switch'
            assert form['switching_organization']==PARTNER
            if self.switch_http==200 or (self.share_posts and self.share_after_post=='switch'):
                return 200,{'token_type':'Bearer','access_token':'s'*40,
                    'scope':' '.join(share.PARTNER_SCOPES)},None
            return self.switch_http,{'error':'invalid_grant'},None
        if method=='GET' and path.endswith('/organizations/self'):
            assert auth.startswith('Bearer ')
            return 200,{'id':ROOT if self.switch_wrong_tenant else PARTNER,
                       'parent':{'id':ROOT},'status':'ACTIVE'},None
        raise AssertionError((method,path))

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.private=Path(self.tmp.name)
        share.authority.private_write(self.private/'p2-bootstrap-authority.private.json',{
            'schema':'identity.wso2.p224.authority.v1','state':'verified',
            'domain':share.DOMAIN,'sourceAppId':PRIOR,'appId':APP,
            'rootOrganizationId':ROOT,'marker':'p2-bootstrap-'+'a'*32})
        self.p1=patch.object(share.authority,'verify_app',return_value={
            'clientId':'c'*24,'clientSecret':'s'*24})
        self.p2=patch.object(share,'read_partner',return_value='r'*40)
        self.p1.start();self.addCleanup(self.p1.stop)
        self.p2.start();self.addCleanup(self.p2.stop)
    def invoke(self,w,write=False):
        return share.reconcile(w,self.private,'Basic tenant-owner',PRIOR,PARTNER,write,sleep=lambda _:None)
    def journal(self):
        return share.authority.private_read(self.private/'p2-bootstrap-share.private.json',optional=True)
    def test_both_empty_is_unverified_without_writes(self):
        w=Wire()
        r=self.invoke(w)
        self.assertEqual(r['state'],'EMPTY_UNVERIFIED')
        self.assertEqual(r['readbackMode'],'EMPTY_HTTP_200_NOT_PROOF')
        self.assertEqual(r['remoteWrites'],0)
        self.assertEqual(w.share_posts,0)
        self.assertIsNone(self.journal())
        self.assertEqual(sum(path.endswith('/share') for method,path,_,_ in w.calls if method=='GET'),2)
    def test_one_explicit_bounded_post_then_positive_share_readback(self):
        w=Wire(share_after_post='array')
        r=self.invoke(w,True)
        self.assertEqual(r['state'],'VERIFIED')
        self.assertEqual(r['readbackMode'],'APPLICATION_SHARING_API')
        self.assertEqual(w.share_posts,1)
        self.assertEqual(self.journal()['state'],'verified')
        self.assertEqual(self.invoke(w,True)['remoteWrites'],0)
        self.assertEqual(w.share_posts,1)
    def test_previously_shared_switch_token_is_positive_readback_without_post(self):
        w=Wire(switch_http=200)
        r=self.invoke(w,True)
        self.assertEqual(r['state'],'VERIFIED')
        self.assertEqual(r['readbackMode'],'ORGANIZATION_SWITCH_CONTEXT')
        self.assertEqual(r['remoteWrites'],0)
        self.assertEqual(w.share_posts,0)
    def test_post_then_empty_api_envelopes_can_be_verified_by_switched_context(self):
        w=Wire(share_after_post='switch')
        r=self.invoke(w,True)
        self.assertEqual(r['state'],'VERIFIED')
        self.assertEqual(r['readbackMode'],'ORGANIZATION_SWITCH_CONTEXT')
        self.assertEqual(w.share_posts,1)
    def test_post_without_any_positive_readback_never_reports_success_or_retries(self):
        w=Wire(share_after_post='nothing')
        with self.assertRaisesRegex(share.Stop,'NOT_YET_READBACK_VERIFIED_NO_RETRY'):
            self.invoke(w,True)
        self.assertEqual(w.share_posts,1)
        self.assertEqual(self.journal()['state'],'post-started')
        with self.assertRaisesRegex(share.Stop,'PRIOR_POST_OUTCOME_UNCERTAIN_NO_RETRY'):
            self.invoke(w,True)
        self.assertEqual(w.share_posts,1)
    def test_journaled_uncertain_post_can_be_adopted_if_switch_later_succeeds(self):
        w=Wire(share_after_post='nothing')
        with self.assertRaises(share.Stop): self.invoke(w,True)
        w.switch_http=200
        r=self.invoke(w,True)
        self.assertEqual(r['remoteWrites'],0)
        self.assertEqual(self.journal()['state'],'verified')
        self.assertEqual(w.share_posts,1)
    def test_switched_root_or_other_org_denied(self):
        w=Wire(switch_http=200,switch_wrong_tenant=True)
        with self.assertRaisesRegex(share.Stop,'SWITCH_CONTEXT_NOT_PARTNER'):
            self.invoke(w,True)
        self.assertEqual(w.share_posts,0)
        self.assertIsNone(self.journal())
    def test_unknown_secondary_metadata_does_not_trigger_write(self):
        w=Wire(secondary_override={'unexpected':'field'})
        with self.assertRaisesRegex(share.Stop,'SECONDARY_COLLECTION_MISSING'):
            self.invoke(w,True)
        self.assertEqual(w.share_posts,0)
    def test_http_401_in_switch_probe_denied_without_write(self):
        w=Wire(switch_http=401)
        with self.assertRaisesRegex(share.Stop,'SWITCH_PROBE_HTTP_401'):
            self.invoke(w,True)
        self.assertEqual(w.share_posts,0)
    def test_global_sharing_policy_still_blocked(self):
        class GlobalWire(Wire):
            def call(self,method,path,*,auth,payload=None,form=None):
                if method=='GET' and path.endswith('/share'):
                    return 200,{'sharingMode':{'policy':'ALL_EXISTING_AND_FUTURE_ORGS'}},None
                return super().call(method,path,auth=auth,payload=payload,form=form)
        with self.assertRaisesRegex(share.Stop,'ALL_ORGS'):
            self.invoke(GlobalWire(),True)
    def test_invalid_switched_token_cannot_verify(self):
        class WeakTokenWire(Wire):
            def call(self,method,path,*,auth,payload=None,form=None):
                if method=='POST' and path.endswith('/oauth2/token'):
                    return 200,{'token_type':'Bearer','access_token':'s'*40,'scope':'internal_org_organization_view'},None
                return super().call(method,path,auth=auth,payload=payload,form=form)
        with self.assertRaisesRegex(share.Stop,'SWITCH_TOKEN_UNVERIFIED'):
            self.invoke(WeakTokenWire(),True)
    def test_zero_credentials_never_emitted_in_json(self):
        w=Wire()
        serialized=str(self.invoke(w,False))
        self.assertNotIn('r'*40,serialized)
        self.assertNotIn('s'*24,serialized)

if __name__=='__main__': unittest.main()
