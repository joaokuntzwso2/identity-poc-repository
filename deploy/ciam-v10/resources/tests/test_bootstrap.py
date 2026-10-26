import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / 'bootstrap.py'
spec = importlib.util.spec_from_file_location('v10_resources', SRC)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class Fake:
    def __init__(self):
        self.calls=[]; self.apps={};self.authorized={};self.users={};self.nextid=0
        self.token_scope=True;self.deny=None;self.partial_auth=False;self.failed_posts=set();self.auth_post_status=201;self.auth_post_persist=True
    def mkid(self):
        self.nextid+=1
        return 'aaaa0000-aaaa-0000-0000-'+str(self.nextid).zfill(12)
    def call(self,method,path,*,auth,data=None,form=None):
        self.calls.append((method,path))
        if self.deny and self.deny in path:return (401,{},None)
        brand='aurora' if '/t/aurora.identity.test/' in path else 'brisa'
        if path.startswith('/api/server/v1/tenants/'):
            oid=path.split('/')[-1]
            return (200,{'id':oid,'username':'labtenantadmin'},None)
        root='/t/'+b.DOMAINS[brand]
        rel=path[len(root):]
        if rel.startswith('/api/server/v1/api-resources'):
            if rel.endswith('/scopes'):
                is_user='user-resource' in rel
                return (200,[{'name':x} for x in (b.USER_SCOPES if is_user else b.APP_SCOPES)],None)
            if 'filter=' in rel:
                is_user='%2Fscim2%2FUsers' in rel or '/scim2/Users' in rel
                return (200,{'APIResources':[{'id':('user-resource' if is_user else 'app-resource'),'identifier':(b.USER_RESOURCE if is_user else b.APP_RESOURCE)}]},None)
            return (200,{'APIResources':[]},None)
        if rel.startswith('/api/server/v1/applications'):
            pathpart=rel.split('?')[0]
            chunks=pathpart.split('/')
            if method=='GET' and pathpart=='/api/server/v1/applications':
                if 'filter=' in rel:
                    return (200,{'applications':[v for (k,v) in self.apps.items() if k.startswith(brand) and v['name'] in rel.replace('+',' ')]},None)
                return (200,{'totalResults':0,'applications':[]},None)
            if method=='POST' and pathpart=='/api/server/v1/applications':
                if path in self.failed_posts:return (206,{},None)
                appid=self.mkid();self.apps[brand+appid]={'id':appid,**data};self.authorized[brand+appid]=[]
                return (201,{'id':appid},None)
            appid=chunks[5] if len(chunks)>5 else None
            key=brand+str(appid)
            if key not in self.apps:return (404,{},None)
            if pathpart.endswith('/authorized-apis'):
                if method=='POST':
                    if self.partial_auth:return (206,{},None)
                    if self.auth_post_persist:
                        self.authorized[key].append({'id':data['id'],'authorizedScopes':data['scopes']})
                    return (self.auth_post_status,{},None)
                return (200,{'authorizedAPIs':self.authorized[key]},None)
            if pathpart.endswith('/inbound-protocols/oidc'):
                return (200,{'clientId':'id-'+appid,'clientSecret':'secret-'+appid},None)
            if method=='GET':return (200,self.apps[key],None)
        if rel=='/oauth2/token':
            scopes=set(form['scope'].split())
            if not self.token_scope: scopes.remove('internal_user_mgt_create')
            return (200,{'access_token':'fake-token','scope':' '.join(scopes),'token_type':'Bearer'},None)
        if rel.startswith('/scim2/Users'):
            if method=='POST':
                uid=self.mkid();v=dict(data);v['id']=uid;self.users[brand]=v
                return (201,v,None)
            if '?' in rel:
                current=self.users.get(brand)
                return (200,{'totalResults':1 if current else 0,'Resources':[current] if current else []},None)
            uid=rel.split('/')[-1]
            current=self.users.get(brand)
            return (200,current,None) if current and uid==current['id'] else (404,{},None)
        raise AssertionError((method,path))

def fixture():
    tenants={'schema':'identity.wso2.ciam.v10.tenants','base':b.BASE,'domains':b.DOMAINS,
             'tenants':{x:{'domain':d,'status':'readback-verified','tenantId':'tenant-'+x,'ownerId':'owner-'+x,
                           'owner':{'username':'labtenantadmin','password':'secret-'+x}} for x,d in b.DOMAINS.items()}}
    return tenants

class Tests(unittest.TestCase):
    def run_case(self, mode='apply', fake=None):
        fake=fake or Fake();ts=fixture();s=b.initial(ts)
        snapshots=[]
        def save():snapshots.append(str(s))
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            result=b.run(mode,fake,b.basic('admin','root'),ts,s,save)
        return fake,s,result,snapshots

    def test_two_management_two_authorizations_each_two_nonadmin_users(self):
        f,s,r,_=self.run_case()
        self.assertEqual(r['managementClients'],'2_AUTHORIZED_BEARER_VERIFIED')
        self.assertEqual(len(f.apps),2);self.assertEqual(len(f.users),2)
        self.assertTrue(all(len(x)==2 for x in f.authorized.values()))
        self.assertEqual({v['userName'] for v in f.users.values()},{'ciam_aurora','ciam_brisa'})
        self.assertEqual(s['acceptance'],'MANAGEMENT_AND_USERS_VERIFIED_OIDC_NOT_PROVISIONED')
        writes=len([c for c in f.calls if c[0]=='POST' and not c[1].endswith('/oauth2/token')])
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
        self.assertEqual(writes,len([c for c in f.calls if c[0]=='POST' and not c[1].endswith('/oauth2/token')]))
    def test_plan_is_get_only_and_does_not_mutate(self):
        f,s,report,snapshots=self.run_case('plan')
        self.assertEqual(report['writes'],0)
        self.assertEqual(snapshots,[])
        self.assertFalse(any(method!='GET' for method,_ in f.calls))
    def test_requires_explicit_confirmation(self):
        f=Fake();s=b.initial(fixture())
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':''}):
            with self.assertRaisesRegex(b.Refuse,'CONFIRMATION'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
        self.assertFalse(any(x[0]=='POST' for x in f.calls))
    def test_authorization_partial_never_repeats(self):
        f=Fake();f.partial_auth=True;s=b.initial(fixture())
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            with self.assertRaisesRegex(b.Refuse,'AUTHORIZATION_POST_HTTP_206'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
            before=sum(x[0]=='POST' for x in f.calls)
            with self.assertRaisesRegex(b.Refuse,'AUTHORIZATION_UNCERTAIN'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
            self.assertEqual(before,sum(x[0]=='POST' for x in f.calls))
    def test_authorization_http_200_with_verified_readback_is_accepted(self):
        f=Fake();f.auth_post_status=200
        f,s,r,_=self.run_case(fake=f)
        self.assertEqual(r['managementClients'],'2_AUTHORIZED_BEARER_VERIFIED')
        self.assertTrue(all(len(v)==2 for v in f.authorized.values()))

    def test_authorization_http_200_missing_readback_does_not_retry(self):
        f=Fake();f.auth_post_status=200;f.auth_post_persist=False
        s=b.initial(fixture())
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            with self.assertRaisesRegex(b.Refuse,'AUTHORIZATION_READBACK_MISSING'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
            writes=sum(c[0]=='POST' for c in f.calls)
            with self.assertRaisesRegex(b.Refuse,'AUTHORIZATION_UNCERTAIN'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
            self.assertEqual(writes,sum(c[0]=='POST' for c in f.calls))

    def test_interrupted_v1_http_200_reconciles_and_resumes_without_duplicate(self):
        f=Fake();f.auth_post_status=200
        s=b.initial(fixture())
        # Simulate v1: application created, HTTP 200 authorization persisted,
        # but v1 stopped because it expected 201.
        brand='aurora';name=f'Identity Lab {brand.upper()} Management Bootstrap'
        appid=f.mkid()
        f.apps[brand+appid]={'id':appid,'name':name,'description':'Isolated v10 lab-owned tenant automation',
            'isManagementApp':True,'inboundProtocolConfiguration':{'oidc':{'grantTypes':['client_credentials'],'publicClient':False}}}
        app_resource={'id':'app-resource','scopes':list(b.APP_SCOPES)}
        f.authorized[brand+appid]=[{'id':app_resource['id'],'authorizedScopes':app_resource['scopes']}]
        s['tenants'][brand]['management']={'state':'auth-started','name':name,
             'domain':b.DOMAINS[brand],'id':appid,'authStarted':b.APP_RESOURCE}
        oldwrites=sum(c[0]=='POST' for c in f.calls)
        report=b.reconcile(f,b.basic('admin','root'),fixture(),s)
        self.assertTrue(report['safeToResume'])
        self.assertEqual(report['tenants']['aurora']['pendingWriteReadback'],'VERIFIED')
        self.assertEqual(oldwrites,sum(c[0]=='POST' for c in f.calls))
        self.assertIn('authStarted',s['tenants'][brand]['management'])
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            result=b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
        self.assertEqual(result['managementClients'],'2_AUTHORIZED_BEARER_VERIFIED')
        self.assertNotIn('authStarted',s['tenants'][brand]['management'])
        self.assertEqual(len(f.authorized[brand+appid]),2)  # No duplicate grant

    def test_pending_unconfirmed_readback_blocks_reconcile_and_apply(self):
        f=Fake();s=b.initial(fixture())
        brand='aurora';appid=f.mkid();name=f'Identity Lab {brand.upper()} Management Bootstrap'
        f.apps[brand+appid]={'id':appid,'name':name,'isManagementApp':True}
        f.authorized[brand+appid]=[]
        s['tenants'][brand]['management']={'state':'auth-started','name':name,'domain':b.DOMAINS[brand],
                'id':appid,'authStarted':b.APP_RESOURCE}
        report=b.reconcile(f,b.basic('admin','root'),fixture(),s)
        self.assertFalse(report['safeToResume'])
        before=sum(c[0]=='POST' for c in f.calls)
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            with self.assertRaisesRegex(b.Refuse,'AUTHORIZATION_UNCERTAIN'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
        self.assertEqual(before,sum(c[0]=='POST' for c in f.calls))

    def test_denied_tenant_api_stops_before_writes(self):
        f=Fake();f.deny='/api/server/v1/api-resources?limit=1'
        s=b.initial(fixture())
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            with self.assertRaisesRegex(b.Refuse,'QUALIFIED_ADMIN_resources'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
        self.assertFalse(any(x[0]=='POST' for x in f.calls))
    def test_missing_token_scope_fails_closed(self):
        f=Fake();f.token_scope=False;s=b.initial(fixture())
        with patch.dict(os.environ,{'WSO2_CIAM_V10_RESOURCE_CONFIRM':'PROVISION_MANAGEMENT_AND_USERS'}):
            with self.assertRaisesRegex(b.Refuse,'M2M_TOKEN_MISSING_REQUIRED_SCOPES'):
                b.run('apply',f,b.basic('admin','root'),fixture(),s,lambda:None)
        self.assertEqual(len(f.users),0)
    def test_private_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'s';p.write_text('{}');p.chmod(0o644)
            with self.assertRaisesRegex(b.Refuse,'UNSAFE'):b.private_read(p)
            p.chmod(0o600);self.assertEqual(b.private_read(p),{})
            symlink=Path(d)/'link';symlink.symlink_to(p)
            with self.assertRaisesRegex(b.Refuse,'SYMLINK'):b.private_read(symlink)
    def test_owner_id_drift_rejected(self):
        t=fixture();s=b.initial(t);s['tenants']['aurora']['ownerId']='different-owner'
        with self.assertRaisesRegex(b.Refuse,'TENANT_ID_DRIFT|RESOURCE_TENANT_ID_DRIFT'):
            b.validate_state(s,t)

if __name__ == '__main__':unittest.main()
