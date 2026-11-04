import importlib.util
import tempfile
import unittest
from pathlib import Path

PARENT=Path(__file__).resolve().parents[1]
SCRIPT=(PARENT/'scripts/p2-bootstrap-authority.py' if (PARENT/'scripts').is_dir()
        else PARENT/'p2-bootstrap-authority.py')
spec=importlib.util.spec_from_file_location('p224_authority',SCRIPT)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

UUID_ROOT='af4744c7-82c3-42f9-8b29-41813ccebcfa'
APP_ID='fb74a97e-6fb4-412b-9f0a-a66aba10c007'
API_IDS={ident:('ID_%02d'%i).ljust(12,'x') for i,ident in enumerate(a.POLICY)}

class FakeWire:
    def __init__(self):
        self.apps=[];self.auth={};self.calls=[];self.fail_post=False;self.self_id=UUID_ROOT
        self.extra_scope=False; self.missing_resource=None; self.invalid_token=False
        self.fail_after_create=False; self.fail_after_auth=False
    def call(self,method,path,*,auth,payload=None,form=None):
        self.calls.append((method,path,payload,form))
        if path.startswith(a.CATALOG+'?'):
            items=[{'id':API_IDS[x],'identifier':x} for x in a.POLICY if x!=self.missing_resource]
            return 200,{'APIResources':items,'totalResults':len(items)},None
        for ident,rid in API_IDS.items():
            if path==a.CATALOG+'/'+rid:
                return 200,{'id':rid,'identifier':ident,'scopes':[{'name':x} for x in a.POLICY[ident]]},None
        if path.startswith(a.APP_PREFIX+'?'):
            return 200,{'applications':[{'id':x['id'],'name':x['name']} for x in self.apps], 'totalResults':len(self.apps)},None
        if path==a.APP_PREFIX and method=='POST':
            if self.fail_post: raise ConnectionError('simulated unknown create result')
            self.apps.append({'id':APP_ID,**payload})
            if self.fail_after_create: raise ConnectionError('response lost after create')
            return 201,{'id':APP_ID},None
        if path==a.APP_PREFIX+'/V10MGT123456':
            return 200,{'id':'V10MGT123456','name':'Identity Lab AURORA Management Bootstrap','isManagementApp':True},None
        if path==a.APP_PREFIX+'/'+APP_ID:
            return 200,self.apps[0],None
        if path==a.APP_PREFIX+'/'+APP_ID+'/inbound-protocols/oidc':
            return 200,{'grantTypes':['client_credentials','organization_switch'], 'clientId':'clientid123456', 'clientSecret':'very-secret-value'},None
        if path==a.APP_PREFIX+'/'+APP_ID+'/authorized-apis' and method=='POST':
            if self.fail_post:raise ConnectionError('unknown auth outcome')
            self.auth[payload['id']]={'id':payload['id'],'policyIdentifier':'RBAC','authorizedScopes':[{'name':x} for x in payload['scopes']]}
            if self.fail_after_auth: raise ConnectionError('response lost after authorization')
            return 201,{},None
        if path.startswith(a.APP_PREFIX+'/'+APP_ID+'/authorized-apis/') and method=='PATCH':
            rid=path.rsplit('/',1)[-1]
            current=self.auth[rid]
            values=[x['name'] for x in current['authorizedScopes']]
            assert payload.get('removedScopes')==[]
            for name in payload['addedScopes']:
                assert name not in values
                current['authorizedScopes'].append({'name':name})
            return 200,{},None
        if path==a.APP_PREFIX+'/'+APP_ID+'/authorized-apis':
            return 200,{'authorizedAPIs':list(self.auth.values())},None
        if path=='/t/'+a.DOMAIN+'/oauth2/token':
            return 200,{'access_token':'long-token-issued-from-wso2', 'token_type':'Bearer',
                        'scope':'internal_org_organization_view' if self.invalid_token else ' '.join(a.ROOT_SCOPES)},None
        if path=='/t/'+a.DOMAIN+'/o/api/server/v1/organizations/self':
            return 200,{'id':self.self_id,'status':'ACTIVE'},None
        raise AssertionError((method,path))

class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name); self.p=self.home/'private'; self.p.mkdir(mode=0o700)
        self.w=FakeWire()
    def run_flow(self,write):
        return a.reconcile(self.w,home=self.home,owner='Basic trusted',previous_app_id='V10MGT123456',write=write)
    def writes(self):
        return [(m,p) for m,p,_,_ in self.w.calls if m=='POST' and '/oauth2/token' not in p]
    def test_read_only_plan_does_not_create_anything(self):
        v=self.run_flow(False);self.assertEqual(v['state'],'MISSING');self.assertFalse(self.w.apps)
        self.assertEqual(self.writes(),[])
    def test_apply_provisions_and_rerun_readback_no_writes(self):
        v=self.run_flow(True);self.assertEqual(v['state'],'VERIFIED')
        j=a.private_read(self.p/'p2-bootstrap-authority.private.json')
        self.assertEqual(j['aurora.identity.test']['clientId'],'clientid123456')
        self.assertEqual(j['rootOrganizationId'],UUID_ROOT)
        before=len(self.writes());self.assertEqual(before,6)
        self.assertEqual(self.run_flow(True)['state'],'VERIFIED')
        self.assertEqual(len(self.writes()),before)
    def test_missing_required_api_stops_before_create(self):
        self.w.missing_resource=a.GROUPS_ID
        with self.assertRaisesRegex(a.Stop,'P2_REQUIRED_API_RESOURCE_NOT_UNIQUE'):self.run_flow(True)
        self.assertEqual(self.writes(),[])
    def test_unjournaled_name_collision_stops_before_write(self):
        self.w.apps.append({'id':APP_ID,'name':a.APP_NAME,'description':'someone-else','isManagementApp':True})
        with self.assertRaisesRegex(a.Stop,'UNJOURNALED_P2_MANAGEMENT_APP_COLLISION'):self.run_flow(True)
        self.assertEqual(self.writes(),[])
    def test_unknown_create_result_cannot_be_retried(self):
        self.w.fail_post=True
        with self.assertRaises(ConnectionError):self.run_flow(True)
        self.w.fail_post=False
        with self.assertRaisesRegex(a.Stop,'P2_CREATE_OUTCOME_UNCERTAIN_NO_AUTOMATIC_RETRY'):self.run_flow(True)
        self.assertEqual(len(self.writes()),1)  # never repeats the uncertain POST
    def test_uncertain_create_recovery_only_if_owned_marker_matches(self):
        self.w.fail_after_create=True
        with self.assertRaises(ConnectionError):self.run_flow(True)
        self.w.fail_after_create=False
        v=self.run_flow(True)
        self.assertEqual(v['state'],'VERIFIED')
        self.assertEqual(sum(p==a.APP_PREFIX for _,p in self.writes()),1)
    def test_uncertain_authorization_is_adopted_only_on_readback(self):
        self.w.fail_after_auth=True
        with self.assertRaises(ConnectionError):self.run_flow(True)
        self.w.fail_after_auth=False
        v=self.run_flow(True)
        self.assertEqual(v['state'],'VERIFIED')
        self.assertEqual(len(self.writes()),6)
    def test_cannot_resume_with_foreign_application_marker(self):
        self.w.fail_after_create=True
        with self.assertRaises(ConnectionError):self.run_flow(True)
        self.w.fail_after_create=False
        self.w.apps[0]['description']='foreign-owned'
        with self.assertRaisesRegex(a.Stop,'P2_UNCERTAIN_CREATE_NO_PROVEN_OWNERSHIP'):self.run_flow(True)
        self.assertEqual(len(self.writes()),1)
    def test_wrong_root_organization_readback_denied(self):
        self.w.self_id='invalid'
        with self.assertRaisesRegex(a.Stop,'P2_ROOT_TOKEN_NOT_BOUND'):self.run_flow(True)
        j=a.private_read(self.p/'p2-bootstrap-authority.private.json')
        self.assertNotIn('aurora.identity.test',j)
    def test_missing_scope_denied_without_authority_handoff(self):
        self.w.invalid_token=True
        with self.assertRaisesRegex(a.Stop,'P2_ROOT_TOKEN_GRANT_NOT_VERIFIED'):self.run_flow(True)
        self.assertNotIn('aurora.identity.test',a.private_read(self.p/'p2-bootstrap-authority.private.json'))
    def test_monotonic_user_scope_migration_patch_and_readback(self):
        self.run_flow(True)
        rid=API_IDS[a.USERS_ID]
        user=self.w.auth[rid]
        user['authorizedScopes']=[x for x in user['authorizedScopes'] if x['name'] not in ('internal_org_user_mgt_create', 'internal_org_user_mgt_update')]
        result=self.run_flow(False)
        self.assertEqual(result['state'],'SCOPE_UPGRADE_REQUIRED')
        self.assertFalse(any(m=='PATCH' for m,_,_,_ in self.w.calls))
        self.run_flow(True)
        self.assertEqual({x['name'] for x in self.w.auth[rid]['authorizedScopes']},set(a.POLICY[a.USERS_ID]))
        patches=[x for x in self.w.calls if x[0]=='PATCH']
        self.assertEqual(len(patches),1)
        self.assertEqual(patches[0][2]['removedScopes'],[])
        self.run_flow(True)
        self.assertEqual(len([x for x in self.w.calls if x[0]=='PATCH']),1)
    def test_existing_three_scope_user_profile_gains_update_only(self):
        self.run_flow(True)
        rid=API_IDS[a.USERS_ID]
        self.w.auth[rid]['authorizedScopes']=[x for x in self.w.auth[rid]['authorizedScopes']
          if x['name']!='internal_org_user_mgt_update']
        result=self.run_flow(False)
        self.assertEqual(result['state'],'SCOPE_UPGRADE_REQUIRED')
        self.assertFalse(any(call[0]=='PATCH' for call in self.w.calls))
        self.run_flow(True)
        patches=[call for call in self.w.calls if call[0]=='PATCH']
        self.assertEqual(len(patches),1)
        self.assertEqual(patches[0][2],{
           'addedScopes':['internal_org_user_mgt_update'],'removedScopes':[]})
        before=len([call for call in self.w.calls if call[0]=='PATCH'])
        self.run_flow(True)
        self.assertEqual(len([call for call in self.w.calls if call[0]=='PATCH']),before)

    def test_uncertain_scope_update_not_blindly_retried(self):
        self.run_flow(True)
        rid=API_IDS[a.USERS_ID]
        user=self.w.auth[rid]
        user['authorizedScopes']=[x for x in user['authorizedScopes'] if x['name'] not in ('internal_org_user_mgt_create', 'internal_org_user_mgt_update')]
        original=self.w.call
        def fail_patch(method,path,*,auth,payload=None,form=None):
            if method=='PATCH': raise ConnectionError('uncertain patch')
            return original(method,path,auth=auth,payload=payload,form=form)
        self.w.call=fail_patch
        with self.assertRaises(ConnectionError): self.run_flow(True)
        self.w.call=original
        with self.assertRaisesRegex(a.Stop,'P2_SCOPE_UPGRADE_OUTCOME_UNCERTAIN_NO_RETRY'):
            self.run_flow(True)
        self.assertFalse(any(method=='PATCH' for method,_,_,_ in self.w.calls))
    def test_excess_scope_on_existing_auth_is_denied(self):
        self.run_flow(True)
        first=next(iter(self.w.auth.values()))
        first['authorizedScopes'].append({'name':'internal_org_organization_delete'})
        with self.assertRaisesRegex(a.Stop,'P2_PARTIAL_OR_EXCESS_API_AUTH_SCOPE_BLOCKED'):self.run_flow(True)
    def test_app_identity_tamper_denied(self):
        self.run_flow(True);self.w.apps[0]['isManagementApp']=False
        with self.assertRaisesRegex(a.Stop,'P2_APP_READBACK_IDENTITY_MISMATCH'):self.run_flow(True)
    def test_owner_only_private_storage(self):
        self.run_flow(True)
        self.assertEqual((self.p/'p2-bootstrap-authority.private.json').stat().st_mode & 0o777,0o600)
    def test_wire_denies_foreign_tenant_before_network(self):
        fake=a.Wire(None)
        with self.assertRaisesRegex(a.Stop,'HTTP_PATH_OR_METHOD_NOT_ALLOWED'):
            fake.call('GET','/t/brisa.identity.test/api/server/v1/applications',auth='Basic test')
        with self.assertRaisesRegex(a.Stop,'HTTP_PATH_OR_METHOD_NOT_ALLOWED'):
            fake.call('POST','/api/server/v1/tenants',auth='Basic test')
    def test_no_unapproved_tenant_paths(self):
        self.run_flow(True)
        self.assertTrue(all(path.startswith('/t/aurora.identity.test/') for _,path,_,_ in self.w.calls))

if __name__=='__main__':unittest.main()
