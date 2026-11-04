import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve()
roots=(HERE.parents[2],HERE.parents[1])
ROOTDIR=next((base for base in roots if (base/'scripts/p2-bootstrap-share.py').is_file()),None)
if ROOTDIR is None:raise RuntimeError('P2_SHARE_SOURCE_NOT_INSTALLED')
SRC=ROOTDIR/'scripts/p2-bootstrap-share.py'
spec=importlib.util.spec_from_file_location('share_under_test',SRC)
share=importlib.util.module_from_spec(spec)
spec.loader.exec_module(share)

ROOT='11111111-1111-4111-8111-111111111111'
PARTNER='22222222-2222-4222-8222-222222222222'
APP='appid_01234567890'
MARKER='p2-bootstrap-'+'a'*32

class FakeWire:
    def __init__(self, shared=False, *, foreign=False, next_link=False, post_status=200):
        self.shared=shared
        self.foreign=foreign
        self.next_link=next_link
        self.post_status=post_status
        self.calls=[]
    def call(self, method, path, *, auth, payload=None, form=None):
        self.calls.append((method,path,payload))
        if method=='GET' and path.endswith('/share'):
            orgs=([{'id':PARTNER}] if self.shared else [])
            if self.foreign:orgs=[{'id':'33333333-3333-4333-8333-333333333333'}]
            links=[{'href':'?after=x','rel':'next'}] if self.next_link else []
            return 200,{'organizations':orgs,'links':links},None
        if method=='POST' and path.endswith('/share'):
            if self.post_status in (200,202):self.shared=True
            return self.post_status,{},None
        raise AssertionError((method,path))

class ShareBehavior(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.private=Path(self.temp.name)
        share.authority.private_write(self.private/'p2-bootstrap-authority.private.json',{
            'schema':'identity.wso2.p224.authority.v1','state':'verified',
            'domain':share.DOMAIN,'sourceAppId':'legacyid_012345',
            'appId':APP,'rootOrganizationId':ROOT,'marker':MARKER
        })
        self.patch1=patch.object(share.authority,'verify_app',return_value={'clientId':'client-id','clientSecret':'client-secret'})
        self.patch2=patch.object(share,'read_partner',return_value=None)
        self.patch1.start();self.patch2.start()
    def tearDown(self):
        self.patch2.stop();self.patch1.stop();self.temp.cleanup()
    def invoke(self,wire,write):
        return share.reconcile(wire,self.private,'Basic private','legacyid_012345',PARTNER,write,sleep=lambda _:None)
    def test_readonly_missing_does_not_write(self):
        wire=FakeWire()
        result=self.invoke(wire,False)
        self.assertEqual(result['state'],'MISSING')
        self.assertEqual([x[0] for x in wire.calls],['GET'])
        self.assertFalse((self.private/'p2-bootstrap-share.private.json').exists())
    def test_write_only_exact_app_partner_with_readback(self):
        wire=FakeWire()
        result=self.invoke(wire,True)
        self.assertEqual(result['state'],'VERIFIED')
        self.assertEqual(result['remoteWrites'],1)
        posts=[x for x in wire.calls if x[0]=='POST']
        self.assertEqual(len(posts),1)
        self.assertEqual(posts[0][2],{'shareWithAllChildren':False,'sharedOrganizations':[PARTNER]})
        journal=share.authority.private_read(self.private/'p2-bootstrap-share.private.json')
        self.assertEqual(journal['state'],'verified')
        wire.calls.clear()
        self.assertEqual(self.invoke(wire,True)['remoteWrites'],0)
        self.assertTrue(all(x[0]=='GET' for x in wire.calls))
    def test_verified_remote_share_idempotent_without_journal(self):
        wire=FakeWire(shared=True)
        self.assertEqual(self.invoke(wire,True)['remoteWrites'],0)
        self.assertTrue(all(x[0]=='GET' for x in wire.calls))
    def test_foreign_sharing_blocked(self):
        wire=FakeWire(foreign=True)
        with self.assertRaisesRegex(share.Stop,'FOREIGN_ORGANIZATION'):
            self.invoke(wire,True)
        self.assertTrue(all(x[0]=='GET' for x in wire.calls))
    def test_pagination_blocks_incomplete_share(self):
        wire=FakeWire(next_link=True)
        with self.assertRaisesRegex(share.Stop,'INVENTORY_INCOMPLETE'):
            self.invoke(wire,True)
        self.assertTrue(all(x[0]=='GET' for x in wire.calls))
    def test_unknown_post_stays_uncertain_and_never_retries(self):
        wire=FakeWire(post_status=400)
        with self.assertRaisesRegex(share.Stop,'WRITE_OUTCOME_UNCERTAIN'):
            self.invoke(wire,True)
        self.assertEqual(sum(x[0]=='POST' for x in wire.calls),1)
        wire.calls.clear()
        with self.assertRaisesRegex(share.Stop,'PRIOR_POST_OUTCOME_UNCERTAIN'):
            self.invoke(wire,True)
        self.assertTrue(all(x[0]=='GET' for x in wire.calls))
    def test_previous_post_adopted_only_after_remote_readback(self):
        wire=FakeWire(post_status=400)
        with self.assertRaises(share.Stop):self.invoke(wire,True)
        wire.shared=True;wire.calls.clear()
        result=self.invoke(wire,True)
        self.assertEqual(result['state'],'VERIFIED')
        self.assertTrue(all(x[0]=='GET' for x in wire.calls))
    def test_journal_context_tamper_denied(self):
        p=self.private/'p2-bootstrap-authority.private.json'
        journal=share.authority.private_read(p)
        journal['domain']='brisa.identity.test'
        share.authority.private_write(p,journal)
        with self.assertRaisesRegex(share.Stop,'AUTHORITY_JOURNAL_DRIFT'):
            self.invoke(FakeWire(),True)
    def test_wrong_partner_id_shape_denied(self):
        with self.assertRaisesRegex(share.Stop,'PARTNER_ID_INVALID'):
            share.check_partner_id('brisa')
    def test_global_share_denied(self):
        class GlobalWire(FakeWire):
            def call(self,method,path,*,auth,payload=None,form=None):
                if method=='GET':return 200,{'organizations':[], 'sharingMode':{'policy':'ALL_EXISTING_AND_FUTURE_ORGS'}},None
                return super().call(method,path,auth=auth,payload=payload,form=form)
        with self.assertRaisesRegex(share.Stop,'ALL_ORGS'):
            self.invoke(GlobalWire(),True)

if __name__=='__main__':unittest.main()

@unittest.skipIf(share is None,'share implementation missing')
class PartnerScopeReadback(unittest.TestCase):
    def test_partner_parent_mismatch_never_authorizes_sharing(self):
        class Wire:
            def call(self,method,path,*,auth,payload=None,form=None):
                if path.endswith('/oauth2/token'):
                    return 200,{'access_token':'a'*40,'scope':' '.join(share.authority.ROOT_SCOPES)},None
                if path.endswith('/organizations/self'):
                    return 200,{'id':ROOT},None
                if path.endswith('/organizations/'+PARTNER):
                    return 200,{'id':PARTNER,'name':share.PARTNER_NAME,
                      'orgHandle':share.PARTNER_HANDLE,'status':'ACTIVE',
                      'parent':{'id':'44444444-4444-4444-8444-444444444444'}},None
                raise AssertionError(path)
        with self.assertRaisesRegex(share.Stop,'PARTNER_CONTEXT_INVALID'):
            share.read_partner(Wire(),'Basic owner',{'clientId':'c'*20,'clientSecret':'s'*20},PARTNER,ROOT)

    def test_root_identity_mismatch_denied_before_partner(self):
        calls=[]
        class Wire:
            def call(self,method,path,*,auth,payload=None,form=None):
                calls.append(path)
                if path.endswith('/oauth2/token'):
                    return 200,{'access_token':'a'*40,'scope':' '.join(share.authority.ROOT_SCOPES)},None
                if path.endswith('/organizations/self'):
                    return 200,{'id':'44444444-4444-4444-8444-444444444444'},None
                raise AssertionError('unexpected partner API request')
        with self.assertRaisesRegex(share.Stop,'ROOT_CONTEXT_DRIFT'):
            share.read_partner(Wire(),'Basic owner',{'clientId':'c'*20,'clientSecret':'s'*20},PARTNER,ROOT)
        self.assertFalse(any('/organizations/'+PARTNER in x for x in calls))
