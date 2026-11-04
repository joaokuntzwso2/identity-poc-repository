from __future__ import annotations
import importlib.util,json,re,tempfile,unittest,uuid
from pathlib import Path
from unittest import mock
SOURCE=Path(__file__).resolve().parents[2]/'scripts/p2/partner_portal_v16.py'
spec=importlib.util.spec_from_file_location('v16_portal',SOURCE)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
ORIGINAL='http://localhost:4000/api/identity/aurora/callback'
class FakeM:
    UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    def __init__(self,http):self.http=http
    def inventory(self,http,root,field,admin):
        assert field=='applications' and root==v.BASE
        return [dict(id=k,name=x['name']) for k,x in self.http.docs.items()]
    def exclusive_json(self,p,obj):
        with open(p,'x') as f:json.dump(obj,f)
    def replace_json(self,p,obj):p.write_text(json.dumps(obj))
    def read_json_private(self,p):return json.loads(p.read_text())
    def hash_id(self,s):return v.fp(s)
class FakeHTTP:
    def __init__(self):
        self.source=str(uuid.uuid4());self.created=str(uuid.uuid4());self.posts=[]
        self.docs={self.source:dict(id=self.source,name='Aurora Web',description='Existing',isManagementApp=False)}
        self.oidc={self.source:dict(grantTypes=['authorization_code'],callbackURLs=[ORIGINAL])}
        self.auth={self.source:[]};self.fail_post=False;self.bad_pkce=False
    def call(self,method,path,*,basic=None,data=None):
        if method=='POST':
            self.posts.append((path,data))
            assert path==v.BASE
            if self.fail_post:raise OSError('unknown outcome')
            self.docs[self.created]=dict(id=self.created,name=v.NAME,description=v.DESCRIPTION,
                                          isManagementApp=False,applicationEnabled=True)
            self.oidc[self.created]=dict(grantTypes=['authorization_code'],
                        callbackURLs=[ORIGINAL],publicClient=False,clientId='client-xyz',
                        pkce=dict(mandatory=True,supportPlainTransformAlgorithm=self.bad_pkce))
            self.auth[self.created]=[]
            return 201,dict(id=self.created),''
        assert method=='GET'
        assert path.startswith(v.BASE+'/')
        tail=path[len(v.BASE)+1:].split('/')
        app=tail[0]
        if len(tail)==1:return 200,self.docs[app],''
        if tail[1]=='inbound-protocols':return 200,self.oidc[app],''
        if tail[1]=='authorized-apis':return 200,self.auth[app],''
        raise AssertionError(path)
class PortalTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.repo=self.root/'repo';(self.repo/'scripts/p2').mkdir(parents=True)
        (self.repo/'scripts/p2/partner_business_plan_v15.py').write_text('#fixture')
        (self.repo/'scripts/ciam-v10.sh').write_text('#fixture')
        self.private=self.root/'private';self.private.mkdir(mode=0o700)
        self.http=FakeHTTP();self.m=FakeM(self.http)
        self.uri=ORIGINAL
        self.evidence=lambda repo,private:(self.m,self.http,'admin',*v.strict_app_inventory(self.m,self.http,'admin'),self.http.source,self.uri,v.fp('/api/identity/aurora/callback'))
        self.oldcwd=Path.cwd()
        self.cwd=mock.patch('pathlib.Path.cwd',return_value=self.repo)
        self.getenv=mock.patch.dict('os.environ',{'P2_PRIVATE_DIR':str(self.private)})
        self.check=mock.patch.object(v,'evidence',side_effect=self.evidence)
        self.cwd.start();self.getenv.start();self.check.start()
    def tearDown(self):
        self.check.stop();self.getenv.stop();self.cwd.stop();self.tmp.cleanup()
    def run_command(self,*args):return v.main(list(args))
    def create(self):return self.run_command('ensure','--approve='+v.APPROVAL)
    def test_first_start_posts_once_then_readback(self):
        out=self.create()
        self.assertEqual(out['code'],'V16_PORTAL_CREATED_ONCE_AND_READBACK_VERIFIED')
        self.assertEqual(out['managementWrites'],1)
        self.assertFalse(out['sharingPerformed'])
        self.assertEqual(len(self.http.posts),1)
        self.assertEqual(self.http.posts[0][1]['inboundProtocolConfiguration']['oidc']['pkce'],
                         {'mandatory':True,'supportPlainTransformAlgorithm':False})
        record=self.m.read_json_private(self.private/v.JOURNAL)
        self.assertEqual(record['state'],'VERIFIED')
        self.assertEqual(record['managementWriteIntentCount'],1)
        self.assertNotIn('clientSecret',json.dumps(record))
    def test_restart_is_get_only(self):
        self.create()
        again=self.create()
        self.assertEqual(again['code'],'V16_PORTAL_ALREADY_REGISTERED_AND_REVERIFIED')
        self.assertEqual(again['managementWrites'],0)
        self.assertEqual(len(self.http.posts),1)
    def test_plan_is_readonly(self):
        out=self.run_command('status')
        self.assertEqual(out['status'],'PLAN_ONLY');self.assertEqual(self.http.posts,[])
        self.assertFalse((self.private/v.JOURNAL).exists())
    def test_reconcile_absent_no_post(self):
        self.assertEqual(self.run_command('reconcile')['status'],'PLAN_ONLY')
        self.assertEqual(len(self.http.posts),0)
    def test_unknown_post_leaves_intent_and_does_not_retry(self):
        self.http.fail_post=True
        with self.assertRaisesRegex(v.Stop,'UNKNOWN_NO_RETRY'):self.create()
        self.assertEqual(self.m.read_json_private(self.private/v.JOURNAL)['state'],'INTENT')
        self.http.fail_post=False
        with self.assertRaisesRegex(v.Stop,'INTENT_EXISTS_RECONCILE'):self.create()
        self.assertEqual(len(self.http.posts),1)
    def test_reconcile_after_lost_response_does_not_grant_or_post(self):
        self.http.fail_post=True
        with self.assertRaises(v.Stop):self.create()
        self.http.fail_post=False
        out=self.run_command('reconcile')
        self.assertEqual(out['code'],'V16_CREATE_OUTCOME_UNRESOLVED_NO_RETRY')
        self.assertEqual(len(self.http.posts),1)
    def test_reconcile_then_get_only_finish(self):
        self.http.fail_post=True
        with self.assertRaises(v.Stop):self.create()
        self.http.fail_post=False
        self.http.docs[self.http.created]=dict(id=self.http.created,name=v.NAME,description=v.DESCRIPTION,
                                             isManagementApp=False,applicationEnabled=True)
        self.http.oidc[self.http.created]=dict(grantTypes=['authorization_code'],callbackURLs=[ORIGINAL],
                                             publicClient=False,clientId='test-client',
                                             pkce=dict(mandatory=True,supportPlainTransformAlgorithm=False))
        self.http.auth[self.http.created]=[]
        out=self.run_command('reconcile')
        self.assertEqual(out['code'],'V16_EXACT_NEW_APP_OBSERVED_GET_ONLY_FINISH_AVAILABLE')
        done=self.run_command('finish','--readback-only')
        self.assertEqual(done['code'],'V16_GET_ONLY_FINALIZATION_COMPLETE')
        self.assertEqual(done['managementWrites'],0)
        self.assertEqual(len(self.http.posts),1)
    def test_bad_pkce_rejected_after_one_post_with_intent_preserved(self):
        self.http.bad_pkce=True
        with self.assertRaisesRegex(v.Stop,'OIDC_CONFIGURATION_NOT_EXACT'):self.create()
        self.assertEqual(len(self.http.posts),1)
        self.assertEqual(self.m.read_json_private(self.private/v.JOURNAL)['state'],'INTENT')
    def test_owned_name_collision_before_post(self):
        other=str(uuid.uuid4());self.http.docs[other]=dict(id=other,name=v.NAME)
        with self.assertRaisesRegex(v.Stop,'UNOWNED_NAME_COLLISION'):self.create()
        self.assertEqual(len(self.http.posts),0)
    def test_intent_tamper_fails_closed(self):
        self.create();p=self.private/v.JOURNAL;rec=json.loads(p.read_text());rec['tenant']='brisa.identity.test';p.write_text(json.dumps(rec))
        with self.assertRaisesRegex(v.Stop,'JOURNAL_UNTRUSTED'):self.create()
        self.assertEqual(len(self.http.posts),1)
    def test_extra_authorized_api_rejected(self):
        self.create();self.http.auth[self.http.created]=[dict(id='bad')]
        with self.assertRaisesRegex(v.Stop,'UNEXPECTED_API_AUTHORIZATION'):self.create()
    def test_callback_bad_origins_rejected(self):
        for uri in ('https://evil.test/callback','https://localhost:9444/t/brisa.identity.test/callback',
                    'http://localhost:4000/a?cb=1','regexp=(http://localhost:4000/callback)',
                    'http://localhost:4000/callback/*', 'https://localhost:4000/callback#x'):
            with self.subTest(uri=uri),self.assertRaises(v.Stop):v.secure_callback(uri)
    def test_callback_project_source_anchored(self):
        src=self.repo/'services/identity-bff/src/server.js';src.parent.mkdir(parents=True)
        src.write_text("const route='/api/identity/aurora/callback';")
        self.assertEqual(v.callback_in_project(self.repo,ORIGINAL),v.fp('/api/identity/aurora/callback'))
        src.write_text("const route='/api/identity/other/callback';")
        with self.assertRaisesRegex(v.Stop,'NOT_IMPLEMENTED'):v.callback_in_project(self.repo,ORIGINAL)
    def test_response_location_rejects_foreign_origin(self):
        with self.assertRaisesRegex(v.Stop,'LOCATION_FOREIGN'):
            v.parse_id(self.m,{},'https://evil.test'+v.BASE+'/'+self.http.created)
    def test_no_start_without_exact_approval(self):
        with self.assertRaisesRegex(v.Stop,'USE_STATUS_ENSURE'):self.run_command('ensure')
        self.assertEqual(len(self.http.posts),0)
    def test_no_manual_finish_without_intent(self):
        with self.assertRaisesRegex(v.Stop,'NO_JOURNAL_TO_FINISH'):self.run_command('finish','--readback-only')
    def test_post_does_not_authorize_or_share(self):
        self.create()
        self.assertTrue(all(path==v.BASE for path,_ in self.http.posts))
        self.assertFalse(any('/share' in path or '/authorized-apis' in path for path,_ in self.http.posts))
if __name__=='__main__':unittest.main()
