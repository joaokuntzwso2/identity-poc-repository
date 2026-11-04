"""V12 offline safety tests: no WSO2 network, no real client credentials."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SRC=Path(__file__).resolve().parents[2]/'scripts/p2/creator_m2m_v12.py'
if not SRC.exists():
    SRC=Path(__file__).resolve().parents[2]/'overlay/scripts/p2/creator_m2m_v12.py'
spec=importlib.util.spec_from_file_location('creator_v12',SRC)
v=importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
UUID=re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
VIEW='11111111-1111-4111-8111-111111111111'
CREATOR='22222222-2222-4222-8222-222222222222'
OTHER=['%08x-3333-4333-8333-333333333333'%i for i in range(1,7)]
RID='AuroraOrgApiOnly'
ORG_IDENTIFIER='/o/api/server/v1/organizations'

class FakeHttp:
    def __init__(self):
        self.posts=[];self.calls=[];self.created=False;self.authorized=False
        self.location='https://localhost:9444'+v.APP_ROOT+'/'+CREATOR
        self.body={};self.create_status=201;self.auth_status=201
        self.extra_new=False;self.extra_scopes=False;self.missing_auth=False
        self.client_secret='secret_for_offline_fixture_do_not_use'
    def call(self,method,path,*,basic=None,bearer=None,data=None):
        self.calls.append((method,path))
        if method=='POST':
            self.posts.append((path,data))
            if path==v.APP_ROOT:
                assert data=={'name':v.APP_NAME,'description':v.DESCRIPTION,'isManagementApp':True,
                              'inboundProtocolConfiguration':{'oidc':{'grantTypes':['client_credentials'],
                                                                    'publicClient':False}}}
                if self.create_status==201:self.created=True
                return self.create_status,self.body,self.location
            if path==v.APP_ROOT+'/'+CREATOR+'/authorized-apis':
                assert data=={'id':RID,'policyIdentifier':'RBAC','scopes':[v.SCOPE]}
                self.authorized=True
                return self.auth_status,{},''
            raise AssertionError('UNAUTHORIZED_POST: '+path)
        assert method=='GET'
        if path==v.APP_ROOT+'?limit=100&offset=0':
            items=[{'id':VIEW,'name':'P2 Aurora Organization View M2M'}]
            items += [{'id':i,'name':'Unrelated'} for i in OTHER]
            if self.created:items.append({'id':CREATOR,'name':v.APP_NAME})
            if self.extra_new:items.append({'id':'44444444-4444-4444-8444-444444444444','name':'Unknown'})
            return 200,{'applications':items,'totalResults':len(items)},''
        if path.startswith(v.API_ROOT+'?'):
            import urllib.parse
            qs=urllib.parse.parse_qs(path.split('?',1)[1]); filt=qs['filter'][0]
            if filt=='identifier eq '+ORG_IDENTIFIER:
                return 200,{'apiResources':[{'id':RID,'identifier':ORG_IDENTIFIER}],
                            'totalResults':1,'links':[]},''
            return 200,{'apiResources':[],'totalResults':0,'links':[]},''
        if path==v.API_ROOT+'/'+RID:
            return 200,{'id':RID,'identifier':ORG_IDENTIFIER,
                        'scopes':[{'name':v.VIEW_SCOPE},{'name':v.SCOPE}]},''
        if path==v.APP_ROOT+'/'+CREATOR:
            return 200,{'id':CREATOR,'name':v.APP_NAME,'description':v.DESCRIPTION,
                        'isManagementApp':True,'applicationEnabled':True},''
        if path==v.APP_ROOT+'/'+CREATOR+'/inbound-protocols/oidc':
            return 200,{'clientId':'clientId-only-test','clientSecret':self.client_secret,
                        'grantTypes':['client_credentials'],'publicClient':False},''
        if path==v.APP_ROOT+'/'+CREATOR+'/authorized-apis':
            if self.missing_auth:return 200,[],''
            if not self.authorized:return 200,[],''
            scopes=[{'name':v.SCOPE}]
            if self.extra_scopes:scopes.append({'name':v.VIEW_SCOPE})
            return 200,[{'id':RID,'policyId':'RBAC','authorizedScopes':scopes}],''
        raise AssertionError('UNEXPECTED_GET: '+path)

class FakeModule:
    secure_dir=staticmethod(lambda path: None)
    UUID=UUID
    API_ID=re.compile(r'^[A-Za-z0-9_-]{3,150}$')
    ALLOWED_API_IDENTIFIERS=('/api/server/v1/organizations',ORG_IDENTIFIER)
    @staticmethod
    def hash_id(value):
        if value==RID:return v.EXPECTED_CREATE_RESOURCE_FP
        if value==VIEW:return v.EXPECTED_VIEW_APP_FP
        return 'fingerprint_created_id'
    @staticmethod
    def inventory(http,root,coll,admin):
        offset=0; all_rows=[]
        for _ in range(10):
            status,doc,_=http.call('GET',f'{root}?limit=100&offset={offset}',basic=admin)
            if status !=200 or not isinstance(doc.get(coll),list):raise v.Stop('INVENTORY_INVALID')
            rows=doc[coll]; all_rows+=rows
            if len(all_rows)==doc['totalResults']:return all_rows
            if not rows:raise v.Stop('INVENTORY_TRUNCATED')
            offset+=len(rows)
        raise v.Stop('INVENTORY_TOO_MANY_PAGES')
    @staticmethod
    def _complete_filtered_api_resource_page(doc):
        if len(doc['apiResources'])!=doc['totalResults'] or any(l.get('rel')=='next' for l in doc['links']):
            raise v.Stop('RESOURCE_INCOMPLETE')
        return doc['apiResources']
    @staticmethod
    def get_oidc(http,admin,app_id):
        status,doc,_=http.call('GET',v.APP_ROOT+'/'+app_id+'/inbound-protocols/oidc',basic=admin)
        if status!=200 or doc['grantTypes']!=['client_credentials'] or doc['publicClient'] is not False:
            raise v.Stop('BAD_OIDC_GRANTS')
        return doc['clientId'],doc['clientSecret']
    @staticmethod
    def exclusive_json(path,doc):
        with open(path,'x') as f:json.dump(doc,f)
    @staticmethod
    def replace_json(path,doc):
        if not path.is_file():raise v.Stop('JOURNAL_MISSING')
        path.write_text(json.dumps(doc))
    @staticmethod
    def read_json_private(path):return json.loads(path.read_text())

class V12Tests(unittest.TestCase):
    def setUp(self):
        self.http=FakeHttp()
        self.view={'appId':VIEW,'resourceId':RID}
        self.v10=SimpleNamespace(plan_cli=lambda *args:{'action':'CREATE'})
        self.v11=object()
    def test_parse_absolute_location(self):
        self.assertEqual(v.parse_post_identity(FakeModule(),{},self.http.location),CREATOR)
    def test_parse_relative_location(self):
        self.assertEqual(v.parse_post_identity(FakeModule(),{},v.APP_ROOT+'/'+CREATOR),CREATOR)
    def test_parse_missing_location_binds_by_delta_only(self):
        self.assertIsNone(v.parse_post_identity(FakeModule(),{},''))
        self.http.created=True
        self.assertEqual(v.candidate_after_create_bound(FakeModule(),self.http,'admin',
              [VIEW]+OTHER,VIEW,None),CREATOR)
    def test_cross_tenant_or_http_location_denied(self):
        for path in ['https://localhost:9444/t/brisa.identity.test/api/server/v1/applications/'+CREATOR,
                     'http://localhost:9444'+v.APP_ROOT+'/'+CREATOR,
                     'https://foreign.example'+v.APP_ROOT+'/'+CREATOR,
                     'https://localhost:9444'+v.APP_ROOT+'/'+CREATOR+'?scope=admin']:
            with self.subTest(path=path),self.assertRaises(v.Stop):
                v.parse_post_identity(FakeModule(),{},path)
    def test_body_location_conflict(self):
        with self.assertRaisesRegex(v.Stop,'CREATE_BODY_LOCATION_ID_CONFLICT'):
            v.parse_post_identity(FakeModule(),{'id':VIEW},self.http.location)
    def test_resource_one_exact_create_scope(self):
        self.assertEqual(v.create_resource(FakeModule(),self.http,'admin',RID),RID)
        self.assertFalse(any(method=='POST' for method,_ in self.http.calls))
    def test_resource_mismatch_denied(self):
        with self.assertRaisesRegex(v.Stop,'PINNED_VIEW_RESOURCE_CHANGED'):
            v.create_resource(FakeModule(),self.http,'admin','wrong')
    def test_authz_rejects_other_scope_and_extra_grants(self):
        self.http.authorized=True; self.http.extra_scopes=True
        with self.assertRaisesRegex(v.Stop,'CREATOR_SCOPE_NOT_EXACTLY_CREATE'):
            v.authz_readback(self.http,'admin',CREATOR,RID)
    def test_authz_rejects_preauthorized(self):
        self.http.authorized=True
        with self.assertRaisesRegex(v.Stop,'CREATOR_APP_PREAUTHORIZED'):
            v.authz_readback(self.http,'admin',CREATOR,RID,expect_empty=True)
    def test_app_delta_rejects_concurrent_creation(self):
        self.http.created=True;self.http.extra_new=True
        with self.assertRaisesRegex(v.Stop,'POST_CREATE_INVENTORY_DELTA'):
            v.candidate_after_create_bound(FakeModule(),self.http,'admin',[VIEW]+OTHER,VIEW,None)
    def run_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.VIEW_JOURNAL).write_text(json.dumps(self.view))
            with patch.object(v,'request_creator_token',return_value=True):
                result=v.apply_once(private,private,FakeModule(),self.v10,self.v11,'admin',self.http)
            record=json.loads((private/v.CREATOR_JOURNAL).read_text())
            creds=json.loads((private/v.CREATOR_CREDS).read_text())
            return result,record,creds
    def test_success_only_two_exact_posts(self):
        result,record,creds=self.run_apply()
        self.assertEqual(len(self.http.posts),2)
        self.assertEqual([row[0] for row in self.http.posts],
                         [v.APP_ROOT,v.APP_ROOT+'/'+CREATOR+'/authorized-apis'])
        self.assertEqual(record['phase'],'COMPLETE')
        self.assertEqual(record['remoteWritesAttempted'],2)
        self.assertEqual(creds['authorizedScopes'],[v.SCOPE])
        self.assertEqual(result['managementWritesAttempted'],2)
        self.assertFalse(result['issuedTokenStored'])
        self.assertNotIn('clientSecret',json.dumps(record))
    def test_non201_authorization_with_exact_get_is_accepted(self):
        self.http.auth_status=204
        result,record,_=self.run_apply()
        self.assertFalse(record['authResponse201'])
        self.assertEqual(result['status'],'VERIFIED')
    def test_create_body_and_no_location_uses_strict_delta(self):
        self.http.location=''; self.http.body={}
        result,record,_=self.run_apply()
        self.assertEqual(record['createIdentitySource'],'201_PLUS_EXACT_INVENTORY_DELTA_GET')
        self.assertEqual(result['status'],'VERIFIED')
    def test_create_failure_leaves_intent_and_no_retry(self):
        self.http.create_status=500
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.VIEW_JOURNAL).write_text(json.dumps(self.view))
            with self.assertRaisesRegex(v.Stop,'CREATE_APP_POST_NOT_201_NO_RETRY'):
                v.apply_once(private,private,FakeModule(),self.v10,self.v11,'admin',self.http)
            self.assertEqual([x[0] for x in self.http.posts],[v.APP_ROOT])
            record=json.loads((private/v.CREATOR_JOURNAL).read_text())
            self.assertEqual(record['phase'],'CREATE_INTENT')
            self.assertEqual(record['remoteWritesAttempted'],1)
            self.assertFalse((private/v.CREATOR_CREDS).exists())
    def test_authorization_not_persisted_remains_intent(self):
        self.http.missing_auth=True
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.VIEW_JOURNAL).write_text(json.dumps(self.view))
            with self.assertRaisesRegex(v.Stop,'CREATOR_AUTHORIZED_API_NOT_EXACT'):
                v.apply_once(private,private,FakeModule(),self.v10,self.v11,'admin',self.http)
            self.assertEqual(len(self.http.posts),2)
            record=json.loads((private/v.CREATOR_JOURNAL).read_text())
            self.assertEqual(record['phase'],'AUTHORIZATION_INTENT')
    def test_concurrent_sentinel_record_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.CREATOR_JOURNAL).write_text('{}')
            with self.assertRaisesRegex(v.Stop,'CREATOR_JOURNAL_EXISTS_RECONCILE_NO_RETRY'):
                v.preflight(private,private,None,None,None)
    def test_partner_journal_always_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.PARTNER_JOURNAL).write_text('{}')
            with self.assertRaisesRegex(v.Stop,'PARTNER_CREATION_JOURNAL_ALREADY_PRESENT'):
                v.no_partner_journal(private)
    def test_permission_token_request_rejects_extra_scope(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps({'token_type':'Bearer','access_token':'x'*60,
                             'scope':v.SCOPE+' '+v.VIEW_SCOPE}).encode()
        class Opener:
            def open(self,req,timeout=18):return Response()
        with self.assertRaisesRegex(v.Stop,'CREATOR_TOKEN_SCOPE_NOT_EXACT'):
            v.request_creator_token(SimpleNamespace(opener=Opener()),'ciddd','secret123456')
    def test_token_not_retained_even_when_accepted(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps({'token_type':'Bearer','access_token':'x'*60,
                                                'scope':v.SCOPE}).encode()
        class Opener:
            def open(self,req,timeout=18):
                self.form=req.data.decode()
                self.authorization=req.get_header('Authorization')
                return Response()
        op=Opener()
        self.assertTrue(v.request_creator_token(SimpleNamespace(opener=op),'ciddd','secret123456'))
        self.assertIn('client_credentials',op.form)
        self.assertNotIn('internal_org_organization_view',op.form)
    def test_reconcile_get_only_does_not_modify_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            journal={'schema':v.SCHEMA,'tenant':v.TENANT,'name':v.APP_NAME,
                     'scope':v.SCOPE,'actorSpecFingerprint':v.EXPECTED_V11_FP,
                     'phase':'CREATE_INTENT','preexistingAppIds':[VIEW]+OTHER}
            (private/v.CREATOR_JOURNAL).write_text(json.dumps(journal))
            self.http.created=True
            before=(private/v.CREATOR_JOURNAL).read_bytes()
            r=v.reconcile_only(FakeModule(),private,'admin',self.http)
            self.assertEqual(r['code'],'ONE_NEW_CREATOR_CANDIDATE_NEEDS_OWNERSHIP_RECONCILIATION')
            self.assertEqual(self.http.posts,[])
            self.assertEqual(before,(private/v.CREATOR_JOURNAL).read_bytes())
    def test_post_exception_but_get_exact_scope_is_reconciled_once(self):
        # A successful remote write can still yield a transport error. GET,
        # never a second POST, is the proof required for acceptance.
        transport=self.http
        prior_call=transport.call
        def interrupted(method,path,**kwargs):
            if method=='POST' and path.endswith('/authorized-apis'):
                prior_call(method,path,**kwargs)
                raise OSError('connection reset after WSO2 stored authorization')
            return prior_call(method,path,**kwargs)
        transport.call=interrupted
        result,record,_=self.run_apply()
        self.assertEqual(len(transport.posts),2)
        self.assertFalse(record['authResponse201'])
        self.assertEqual(result['code'],'CREATOR_APP_AND_EXACT_CREATE_SCOPE_VERIFIED')

    def test_unexpected_extra_authorization_blocks_completion(self):
        self.http.extra_scopes=True
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.VIEW_JOURNAL).write_text(json.dumps(self.view))
            with self.assertRaisesRegex(v.Stop,'CREATOR_SCOPE_NOT_EXACTLY_CREATE'):
                v.apply_once(private,private,FakeModule(),self.v10,self.v11,'admin',self.http)
            self.assertEqual(len(self.http.posts),2)
            self.assertEqual(json.loads((private/v.CREATOR_JOURNAL).read_text())['phase'],
                             'AUTHORIZATION_INTENT')

    def test_token_failure_after_persisted_grant_preserves_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.VIEW_JOURNAL).write_text(json.dumps(self.view))
            with patch.object(v,'request_creator_token',side_effect=v.Stop('CREATOR_TOKEN_SCOPE_NOT_EXACT')):
                with self.assertRaisesRegex(v.Stop,'CREATOR_TOKEN_NOT_VERIFIED_JOURNAL_PRESERVED'):
                    v.apply_once(private,private,FakeModule(),self.v10,self.v11,'admin',self.http)
            self.assertEqual(len(self.http.posts),2)
            record=json.loads((private/v.CREATOR_JOURNAL).read_text())
            self.assertEqual(record['phase'],'AUTHORIZATION_GET_VERIFIED')

    def test_finished_authorization_get_only_recovery_never_replays_remote_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.VIEW_JOURNAL).write_text(json.dumps(self.view))
            with patch.object(v,'request_creator_token',side_effect=v.Stop('TOKEN_GATED')):
                with self.assertRaisesRegex(v.Stop,'CREATOR_TOKEN_NOT_VERIFIED_JOURNAL_PRESERVED'):
                    v.apply_once(private,private,FakeModule(),self.v10,self.v11,'admin',self.http)
            count=len(self.http.posts)
            with patch.object(v,'request_creator_token',return_value=True):
                out=v.finish_get_only(FakeModule(),private,'admin',self.http)
            self.assertEqual(len(self.http.posts),count)
            self.assertEqual(out['managementWritesAttempted'],0)
            self.assertEqual(out['journalPhase'],'COMPLETE')
            self.assertEqual(json.loads((private/v.CREATOR_JOURNAL).read_text())['phase'],'COMPLETE')
            self.assertEqual(json.loads((private/v.CREATOR_CREDS).read_text())['phase'],'SCOPE_VERIFIED')

    def test_unpersisted_authorization_cannot_be_locally_finished(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.VIEW_JOURNAL).write_text(json.dumps(self.view))
            self.http.missing_auth=True
            with self.assertRaises(v.Stop):
                v.apply_once(private,private,FakeModule(),self.v10,self.v11,'admin',self.http)
            with self.assertRaisesRegex(v.Stop,'CREATOR_AUTHORIZED_API_NOT_EXACT'):
                v.finish_get_only(FakeModule(),private,'admin',self.http)
            self.assertEqual(len(self.http.posts),2)

    def test_existing_incomplete_journal_blocks_apply_without_post(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)
            (private/v.CREATOR_JOURNAL).write_text(json.dumps({'phase':'AUTHORIZATION_INTENT'}))
            with patch.object(v,'sources',return_value=(FakeModule(),None,None)), \
                 patch.object(v,'verify_local',return_value=(self.view,'admin',self.http)), \
                 patch.object(v,'operation_lock',return_value=__import__('contextlib').nullcontext()):
                with self.assertRaisesRegex(v.Stop,'CREATOR_JOURNAL_INCOMPLETE_NO_POST_RETRY'):
                    # main requires a repository root; use an isolated fixture.
                    with patch.object(v.Path,'cwd',return_value=private), patch.dict(v.os.environ, {'P2_PRIVATE_DIR':str(private)}):
                        (private/'scripts/p2').mkdir(parents=True)
                        (private/'scripts/ciam-v10.sh').write_text('#fixture')
                        (private/'scripts/p2/creator_actor_plan_v11.py').write_text('#fixture')
                        (private/'scripts/p2/m2m_bootstrap.py').write_text('#fixture')
                        v.main(['apply','--approve='+v.APPROVAL])
            self.assertEqual(self.http.posts,[])

    def test_source_runner_never_calls_partner_create(self):
        runner=Path(__file__).resolve().parents[2]/'scripts/p2/run-approved-creator-v12.sh'
        if runner.exists():
            body=runner.read_text()
            self.assertNotIn('create-partner',body)
            self.assertIn('--approve=APPROVE_AURORA_CREATOR_M2M_CREATE_ONLY_V12',body)
    def test_apply_requires_exact_approval(self):
        with self.assertRaisesRegex(v.Stop,'USE_PLAN_APPLY_RECONCILE_OR_FINISH'):
            v.main(['apply'])
    def test_safe_report_never_contains_secret(self):
        import contextlib
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            v.report('BLOCKED','TOKEN_UNVERIFIED',managementWritesAttempted='UNKNOWN')
        self.assertNotIn('secret',out.getvalue().lower())
        self.assertNotIn('clientId',out.getvalue())

if __name__=='__main__':unittest.main()
