"""Offline guarded P2.24 M2M bootstrap acceptance tests (no WSO2 traffic)."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2]/'scripts/p2/m2m_bootstrap.py'
spec = importlib.util.spec_from_file_location('m2m_bootstrap', MODULE)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
APP='12345678-1234-4234-8234-123456789abc'
API='22345678-1234-4234-8234-123456789abc'
ROOT='32345678-1234-4234-8234-123456789abc'
admin=('admin@aurora.identity.test','local-private-secret')
class Fake:
    def __init__(self, existing=False, extra_scope=False, missing_resource=False):
        self.calls=[]; self.existing=existing; self.extra_scope=extra_scope; self.missing_resource=missing_resource
    def call(self, method, path, **kwargs):
        self.calls.append((method,path,kwargs))
        if method=='GET' and path==m.APP_ROOT+'?limit=100&offset=0':
            return (200, {'totalResults':int(self.existing),'applications':
                           ([{'id':APP,'name':m.NAME}] if self.existing else [])}, '')
        if method=='GET' and path.startswith(m.API_ROOT+'?'):
            from urllib.parse import parse_qs, urlsplit
            identifier=parse_qs(urlsplit(path).query)['filter'][0].removeprefix('identifier eq ')
            rows=[{'id':API,'identifier':'/api/server/v1/organizations'}] if identifier=='/api/server/v1/organizations' else []
            return (200, {'totalResults':len(rows),'APIResources':rows,'links':[]}, '')
        if method=='GET' and path==m.API_ROOT+'/'+API:
            scopes=[] if self.missing_resource else [{'name':m.SCOPE}]
            return (200, {'id':API,'identifier':'/api/server/v1/organizations','scopes':scopes}, '')
        if method=='POST' and path==m.APP_ROOT:
            return (201, {'id':APP}, '')
        if method=='GET' and path==m.APP_ROOT+'/'+APP:
            return (200, {'id':APP,'name':m.NAME,'isManagementApp':True,
                          'applicationEnabled':True}, '')
        if method=='GET' and path==m.APP_ROOT+'/'+APP+'/inbound-protocols/oidc':
            return (200, {'grantTypes':['client_credentials'], 'publicClient':False,
                          'clientId':'client-id-unique', 'clientSecret':'generated-secret-123'}, '')
        if method=='POST' and path==m.APP_ROOT+'/'+APP+'/authorized-apis':
            return (201, {}, '')
        if method=='GET' and path==m.APP_ROOT+'/'+APP+'/authorized-apis':
            scopes=[{'name':m.SCOPE}]
            if self.extra_scope: scopes.append({'name':'internal_org_organization_create'})
            return (200, [{'id':API,'authorizedScopes':scopes}], '')
        if method=='GET' and path==m.ORG_ROOT+'/metadata':
            return (200, {'id':ROOT,'type':'TENANT','orgHandle':m.TENANT,
                          'status':'ACTIVE','parent':{'id':'carbon-parent-identifier'}}, '')
        raise AssertionError((method,path))

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.private=Path(self.tmp.name)
        os.chmod(self.private,0o700)
    def tearDown(self): self.tmp.cleanup()
    def test_plan_is_read_only(self):
        f=Fake(); result=m.bootstrap(f,self.private,admin,'plan')
        self.assertEqual(result['remoteManagementWrites'],0)
        self.assertTrue(all(method=='GET' for method,_,_ in f.calls))
        self.assertEqual(list(self.private.iterdir()),[])
    def test_m2m_complete_with_exact_scope_and_root_parent(self):
        f=Fake()
        with patch.object(m,'oauth_token',return_value='a'*40):
            result=m.bootstrap(f,self.private,admin,'apply')
        self.assertEqual(result['remoteManagementWrites'],2)
        posts=[(p,k['data']) for method,p,k in f.calls if method=='POST']
        self.assertEqual([p for p,_ in posts], [m.APP_ROOT,m.APP_ROOT+'/'+APP+'/authorized-apis'])
        self.assertEqual(posts[0][1]['inboundProtocolConfiguration']['oidc']['grantTypes'], ['client_credentials'])
        self.assertEqual(posts[1][1]['scopes'],[m.SCOPE])
        self.assertEqual(m.read_json_private(self.private/'p2-aurora-orgview-bootstrap.private.json')['phase'],'COMPLETE')
        tokenfile=self.private/'p2-aurora-root-token.private.txt'
        self.assertEqual(stat.S_IMODE(tokenfile.stat().st_mode),0o600)
        self.assertEqual(tokenfile.read_text(),'a'*40)
    def test_verified_completed_journal_reruns_without_post(self):
        f=Fake()
        with patch.object(m,'oauth_token',return_value='b'*40):
            first=m.bootstrap(f,self.private,admin,'apply')
        self.assertEqual(first['action'],'CREATED_AND_READBACK_VERIFIED')
        again=Fake(existing=True)
        with patch.object(m,'oauth_token',return_value='c'*40):
            result=m.bootstrap(again,self.private,admin,'apply')
        self.assertEqual(result['action'],'ALREADY_VERIFIED')
        self.assertEqual(result['remoteManagementWrites'],0)
        self.assertFalse(any(method=='POST' for method,_,_ in again.calls))
        self.assertEqual((self.private/'p2-aurora-root-token.private.txt').read_text(),'c'*40)
    def test_interrupted_write_never_retries(self):
        f=Fake(extra_scope=True)
        with self.assertRaises(m.Block): m.bootstrap(f,self.private,admin,'apply')
        repeat=Fake()
        with self.assertRaisesRegex(m.Block,'PREVIOUS_BOOTSTRAP_JOURNAL'):
            m.bootstrap(repeat,self.private,admin,'apply')
        self.assertEqual(repeat.calls,[])
    def test_existing_named_application_blocks_without_mutation(self):
        f=Fake(existing=True)
        with self.assertRaisesRegex(m.Block,'DEDICATED_APP_ALREADY_EXISTS'):
            m.bootstrap(f,self.private,admin,'apply')
        self.assertEqual([v for v in f.calls if v[0]=='POST'],[])
    def test_api_missing_view_blocks(self):
        f=Fake(missing_resource=True)
        with self.assertRaisesRegex(m.Block,'ORG_MANAGEMENT_RESOURCE_NOT_UNAMBIGUOUS'):
            m.bootstrap(f,self.private,admin,'apply')
        self.assertEqual([v for v in f.calls if v[0]=='POST'],[])
    def test_extra_authorized_scope_fails_without_token(self):
        f=Fake(extra_scope=True)
        with patch.object(m,'oauth_token') as tok:
            with self.assertRaisesRegex(m.Block,'AUTHORIZED_SCOPE_READBACK_NOT_EXACTLY_VIEW'):
                m.bootstrap(f,self.private,admin,'apply')
            tok.assert_not_called()
        j=m.read_json_private(self.private/'p2-aurora-orgview-bootstrap.private.json')
        self.assertEqual(j['phase'],'AUTHORIZATION_INTENT')
    def test_runtime_guard_requires_exact_existing_image_and_v2(self):
        from unittest.mock import Mock
        m.exclusive_json(self.private/'bootstrap-authority-v10.private.json',{'roleApiVersion':'v2'})
        inspect={'Name':'/wso2-ciam-v10-is-1','Config':{'Image':'wso2/wso2is:7.3.0'},
                 'Image':m.EXPECTED_IMAGE_SHA,'State':{'Running':True}}
        proof={'methods':['GET'],'remoteWrites':0,
               'tenantStates':{'aurora':{'rolesV2':{'tenantQualifiedBasic':200}},
                               'brisa':{'rolesV2':{'tenantQualifiedBasic':200}}}}
        import json
        ok=[Mock(returncode=0,stdout=json.dumps([inspect])),
            Mock(returncode=0,stdout=json.dumps(proof))]
        with patch.object(m.subprocess,'run',side_effect=ok) as run:
            m.runtime_guard(Path(self.tmp.name),self.private)
            self.assertEqual(run.call_count,2)
        inspect['Image']='sha256:unapproved'
        with patch.object(m.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps([inspect]))):
            with self.assertRaisesRegex(m.Block,'WSO2_IMAGE_OR_RUNTIME_DRIFT'):
                m.runtime_guard(Path(self.tmp.name),self.private)
    def test_runtime_guard_rejects_failed_live_preflight(self):
        from unittest.mock import Mock
        import json
        m.exclusive_json(self.private/'bootstrap-authority-v10.private.json',{'roleApiVersion':'v2'})
        inspect={'Name':'/wso2-ciam-v10-is-1','Config':{'Image':'wso2/wso2is:7.3.0'},
                 'Image':m.EXPECTED_IMAGE_SHA,'State':{'Running':True}}
        results=[Mock(returncode=0,stdout=json.dumps([inspect])),Mock(returncode=2,stdout='')]
        with patch.object(m.subprocess,'run',side_effect=results):
            with self.assertRaisesRegex(m.Block,'JOURNAL_PINNED_AUTHORITY_PREFLIGHT_FAILED'):
                m.runtime_guard(Path(self.tmp.name),self.private)
    def test_prior_journal_stops_all_api_calls(self):
        m.exclusive_json(self.private/'p2-aurora-orgview-bootstrap.private.json',{'phase':'CREATE_INTENT'})
        f=Fake()
        with self.assertRaisesRegex(m.Block,'PREVIOUS_BOOTSTRAP_JOURNAL'):
            m.bootstrap(f,self.private,admin,'apply')
        self.assertEqual(f.calls,[])
    def test_unqualified_root_admin_rejected(self):
        wrong={'tenants':{'brisa':{'username':'admin','password':'a'},
                          'aurora':{'username':'admin','password':'right'}}}
        self.assertEqual(m.find_tenant_admin(wrong),[(f'admin@{m.TENANT}','right')])
        self.assertEqual(m.find_tenant_admin({'tenants':{'brisa':{'username':'admin','password':'a'}}}),[])
    def test_conflicting_creds_refused(self):
        doc={'tenants':{'aurora':{'admins':[{'username':'admin','password':'one'},
                                             {'username':'admin','password':'two'}]}}}
        with self.assertRaisesRegex(m.Block,'MULTIPLE_AURORA_ADMIN'):
            m.find_tenant_admin(doc)
    def test_root_must_be_tenant_not_child(self):
        f=Fake()
        self.assertEqual(m.root_readback(f,'a'*40),ROOT)
        class Child(Fake):
            def call(self,*args,**kwargs):
                status, doc, loc=super().call(*args,**kwargs)
                if args[1]==m.ORG_ROOT+'/metadata':doc['type']='ORGANIZATION'
                return status,doc,loc
        with self.assertRaisesRegex(m.Block,'ORG_ROOT_NOT_ACTIVE_TENANT'):
            m.root_readback(Child(),'a'*40)
    def test_output_scope_exact_no_escalation(self):
        m.exact_authorization([{'id':API,'authorizedScopes':[{'name':m.SCOPE}]}],API)
        with self.assertRaisesRegex(m.Block,'AUTHORIZED_SCOPE_READBACK_NOT_EXACTLY_VIEW'):
            m.exact_authorization([{'id':API,'authorizedScopes':[{'name':m.SCOPE},{'name':'create'}]}],API)
    def test_create_payload_only_two_approved_post_operations(self):
        f=Fake()
        with patch.object(m,'oauth_token',return_value='a'*40):m.bootstrap(f,self.private,admin,'apply')
        self.assertTrue(all(p.startswith(f'/t/{m.TENANT}/') for _,p,_ in f.calls))
        self.assertFalse(any('/t/brisa.' in p or '/t/carbon.' in p for _,p,_ in f.calls))

if __name__=='__main__': unittest.main()
