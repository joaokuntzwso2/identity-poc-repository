from __future__ import annotations
import importlib.util,json,re,tempfile,unittest,uuid
from pathlib import Path

def dynamic(path,key):
    s=importlib.util.spec_from_file_location(key,path)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
REPO=Path(__file__).resolve().parents[2]
v=dynamic(REPO/'scripts/p2/partner_portal_v16_3.py','test_v163')
old=dynamic(REPO/'scripts/p2/partner_portal_v16.py','test_old_v16')
SOURCE_URI='http://localhost:4000/auth/aurora-web/callback'
TARGET_URI='http://localhost:4000/auth/aurora-partner-web/callback'

class Store:
    UUID=re.compile(r'[a-f0-9-]{36}')
    def __init__(self):self.records={}
    def exclusive_json(self,path,value):
        assert path not in self.records
        self.records[path]=value
    def replace_json(self,path,value):self.records[path]=value
    def hash_id(self,ident):return 'fingerprint'
    def inventory(self,http,path,collection,admin):return http.apps

class HTTP:
    def __init__(self):
        self.posts=[];self.apps=[];self.created=str(uuid.uuid4());self.bad=False;self.unknown=False
    def call(self,method,path,**kwargs):
        if method=='POST':
            self.posts.append((path,kwargs['data']))
            if self.unknown:raise OSError('post timed out')
            self.apps.append({'id':self.created,'name':old.NAME})
            return 201,{'id':self.created},None
        if path==old.BASE+'/'+self.created:
            return 200,{'id':self.created,'name':old.NAME,'description':old.DESCRIPTION,
                        'isManagementApp':False,'applicationEnabled':True},None
        if path==old.BASE+'/'+self.created+'/inbound-protocols/oidc':
            return 200,{'clientId':'new-partner-client','grantTypes':['authorization_code'],
                        'callbackURLs':[TARGET_URI],'publicClient':False,
                        'pkce':{'mandatory':not self.bad,'supportPlainTransformAlgorithm':False}},None
        if path==old.BASE+'/'+self.created+'/authorized-apis':return 200,[],None
        raise AssertionError((method,path))

class V163Test(unittest.TestCase):
    def test_exact_distinct_callback(self):
        self.assertEqual(v.derive_callback(old,SOURCE_URI),TARGET_URI)
        self.assertNotEqual(TARGET_URI,SOURCE_URI)
    def test_source_must_be_aurora_web_not_mobile_or_foreign(self):
        for url in ('http://localhost:4000/auth/aurora-app/callback',
                    'https://attacker.test/auth/aurora-web/callback',
                    'http://localhost:4000/auth/brisa-web/callback'):
            with self.subTest(url=url),self.assertRaises((old.Stop,v.Halt)):v.derive_callback(old,url)
    def test_full_handler_is_wired(self):
        self.assertEqual(v.route_proof(REPO),v.sha(v.ROUTE))
    def test_incorrect_route_fails(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);p=r/'services/identity-bff/src';p.mkdir(parents=True)
            (p/'server.js').write_text('no callback')
            (p/'partner-portal-route.js').write_text('not a handler')
            with self.assertRaisesRegex(v.Halt,'ROUTE_UNPROVEN'):v.route_proof(r)
    def test_no_manual_command_or_surprise_approval(self):
        # Commands are fixed; startup only invokes bootstrap with prior user approval.
        self.assertEqual(v.APPROVAL,old.APPROVAL)
        self.assertEqual(v.NAME,old.NAME)
        self.assertNotIn('share',old.BASE)
    def test_journal_verifier_requires_new_schema(self):
        m=Store();record=self.record()
        v.verify_journal(old,m,record,TARGET_URI,'source-app')
        for mutate in (dict(schema=old.SCHEMA),dict(tenant='brisa.identity.test'),
                       dict(callbackFingerprint='bad'),dict(state='UNEXPECTED'),
                       dict(sourceApplicationId='other'),dict(partnerFingerprint='foreign')):
            rec={**record,**mutate}
            with self.subTest(mutate=mutate),self.assertRaisesRegex(v.Halt,'JOURNAL_OR_APPROVAL_DRIFT'):
                v.verify_journal(old,m,rec,TARGET_URI,'source-app')
    def record(self):
        return dict(schema=v.SCHEMA,state='INTENT',tenant=v.TENANT,name=v.NAME,
                    partnerFingerprint=old.PARTNER_FP,rootFingerprint=old.ROOT_FP,
                    sourceApplicationId='source-app',callbackFingerprint=v.sha(TARGET_URI),
                    callbackPathFingerprint=v.sha(v.ROUTE),specFingerprint=v.journal_spec(old,TARGET_URI),
                    baselineIds=[])
    def test_one_create_post_and_verified_journal(self):
        http=HTTP();m=Store()
        with tempfile.TemporaryDirectory() as d:
            out=v.create_once(old,m,http,'admin',Path(d),[], 'source-app',TARGET_URI)
            self.assertEqual(out['status'],'VERIFIED');self.assertEqual(out['managementWrites'],1)
            self.assertEqual(len(http.posts),1);self.assertEqual(http.posts[0][0],old.BASE)
            self.assertEqual(http.posts[0][1]['inboundProtocolConfiguration']['oidc']['callbackURLs'],[TARGET_URI])
            self.assertEqual(m.records[Path(d)/old.JOURNAL]['state'],'VERIFIED')
            self.assertEqual(m.records[Path(d)/old.JOURNAL]['sharingVerified'],False)
    def test_unknown_post_does_not_retry_and_keeps_intent(self):
        http=HTTP();http.unknown=True;m=Store()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(v.Halt,'UNKNOWN_NO_RETRY'):
                v.create_once(old,m,http,'admin',Path(d),[], 'source-app',TARGET_URI)
            self.assertEqual(len(http.posts),1)
            self.assertEqual(m.records[Path(d)/old.JOURNAL]['state'],'INTENT')
    def test_failed_remote_readback_keeps_intent(self):
        http=HTTP();http.bad=True;m=Store()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(old.Stop):
                v.create_once(old,m,http,'admin',Path(d),[], 'source-app',TARGET_URI)
            self.assertEqual(m.records[Path(d)/old.JOURNAL]['state'],'INTENT')
            self.assertEqual(len(http.posts),1)
    def test_intent_reconcile_never_post(self):
        http=HTTP();m=Store();rec=self.record()
        answer=v.find_verified(old,m,http,'admin',[],[],rec,TARGET_URI)
        self.assertEqual(answer['status'],'RECONCILIATION_ONLY')
        self.assertEqual(len(http.posts),0)
    def test_intent_can_be_readback_candidate_without_automatic_adoption(self):
        http=HTTP();m=Store();rec=self.record()
        result=v.find_verified(old,m,http,'admin',[{'id':http.created,'name':old.NAME}],
                                [http.created],rec,TARGET_URI)
        self.assertEqual(result['status'],'RECONCILIATION_ONLY')
        self.assertEqual(result['code'],'V16_3_EXACT_REMOTE_CREATE_READBACK_FINISH_AVAILABLE')
        self.assertEqual(http.posts,[])
    def test_verification_requires_unique_name(self):
        http=HTTP();m=Store();rec=self.record();rec['state']='VERIFIED';rec['applicationId']=http.created
        with self.assertRaisesRegex(v.Halt,'REMOTE_APP_DRIFT'):
            v.find_verified(old,m,http,'admin',[],[],rec,TARGET_URI)
    def test_no_business_grants_or_shares_in_spec(self):
        s=old.spec_for(TARGET_URI)
        self.assertEqual(s['inboundProtocolConfiguration']['oidc']['grantTypes'],['authorization_code'])
        self.assertNotIn('authorizedAPIs',s)
        self.assertNotIn('share',json.dumps(s).lower())

if __name__=='__main__':unittest.main()
