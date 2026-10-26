import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

FILE=Path(__file__).resolve().parents[1]/'bootstrap.py'
spec=importlib.util.spec_from_file_location('ciam_authority_p0', FILE)
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def fixture():
    ts={'schema':'identity.wso2.ciam.v10.tenants','base':a.resources.BASE,'domains':a.DOMAINS,'tenants':{}}
    rs={'schema':'identity.wso2.ciam.v10.resources.v1','base':a.resources.BASE,
        'acceptance':'MANAGEMENT_AND_USERS_VERIFIED_OIDC_NOT_PROVISIONED','tenants':{}}
    oidc={'schema':'identity.wso2.ciam.v10.oidc.v1','base':a.resources.BASE,'tenants':{}}
    for b,d in a.DOMAINS.items():
        ts['tenants'][b]={'domain':d,'status':'readback-verified','tenantId':'tenant-'+b,
                          'owner':{'username':'labtenantadmin','password':'secret-'+b}}
        rs['tenants'][b]={'domain':d,'management':{'id':'mgmt-'+b,'state':'verified'},
                          'user':{'id':'user-'+b+'-id','state':'verified-browser-not-tested'}}
        oidc['tenants'][b]={'tenantId':'tenant-'+b,'domain':d,'managementAppId':'mgmt-'+b,
                            'clients':{c:{'id':f'{b}-{c}-appid','name':f'Identity Lab v10 {b.title()} {c}',
                                           'state':'verified','domain':d,'clientId':f'client-{b}-{c}'}
                                       for c in ('web','app')}}
    return ts,rs,oidc,a.new_journal(ts,oidc)


class Fake:
    def __init__(self,ts,rs,oidc):
        self.ts=ts;self.rs=rs;self.oidc=oidc
        self.calls=[];self.api={};self.auths={};self.roles={}
        self.failed=None;self.deny_roles=False
    def call(self,method,path,*,auth,data=None,form=None):
        self.calls.append((method,path))
        brand=next((b for b,d in a.DOMAINS.items() if path.startswith('/t/'+d+'/')),None)
        if brand is None:raise AssertionError('cross-origin path '+path)
        if f'labtenantadmin@{a.DOMAINS[brand]}' not in __import__('base64').b64decode(auth.split()[1]).decode():
            raise AssertionError('unqualified tenant credentials')
        rel=path.split('/t/'+a.DOMAINS[brand],1)[1]
        if self.failed and method=='POST' and rel.startswith(self.failed):return (502,{},None)
        if rel.startswith('/api/server/v1/api-resources'):
            if '/resource-' in rel and not rel.endswith('/scopes'):
                return (200,self.api[brand],None) if brand in self.api else (404,{},None)
            if rel.endswith('/scopes'):
                return (200,[{'name':a.API_SCOPE}],None) if brand in self.api else (404,{},None)
            if method=='POST':
                self.api[brand]={'id':'resource-'+brand,'identifier':data['identifier'], 'description':data['description'], 'requiresAuthorization':data['requiresAuthorization']}
                return (201,{'id':'resource-'+brand},None)
            rows=[self.api[brand]] if brand in self.api else []
            return (200,{'APIResources':rows,'totalResults':len(rows)},None)
        if rel.startswith('/api/server/v1/applications/'):
            parts=rel.split('/')
            appid=parts[5]
            app=next((x for x in self.oidc['tenants'][brand]['clients'].values() if x['id']==appid),None)
            if not app:raise AssertionError('unrecognized application id '+appid)
            if '/authorized-apis' in rel:
                if method=='POST':
                    self.auths[(brand,appid)]=[{'id':data['id'],'authorizedScopes':data['scopes']}]
                    return (201,{},None)
                return (200,{'authorizedAPIs':self.auths.get((brand,appid),[])},None)
            return (200,{'id':appid,'name':app['name']},None)
        if rel.startswith('/scim2/v3/Roles'):
            if self.deny_roles:return (401,{},None)
            if method=='POST':
                role={'id':'role-'+brand+'-'+data['displayName'].split()[-1],**data}
                self.roles[(brand,data['displayName'])]=role
                return (201,role,None)
            if '?' in rel:
                from urllib.parse import parse_qs,unquote_plus
                q=parse_qs(rel.split('?',1)[1]);flt=q['filter'][0]
                found=[x for (b,n),x in self.roles.items() if b==brand and n in flt]
                return (200,{'Resources':found,'totalResults':len(found)},None)
            roleid=rel.split('/')[-1]
            role=next((x for (b,n),x in self.roles.items() if b==brand and x['id']==roleid),None)
            return (200,role,None) if role else (404,{},None)
        raise AssertionError((method,path))


class SecurityTests(unittest.TestCase):
    def make(self):
        ts,rs,oidc,journal=fixture()
        return ts,rs,oidc,journal,Fake(ts,rs,oidc)
    def test_plan_is_get_only(self):
        ts,rs,oidc,j,f=self.make()
        result=a.plan(f,ts,rs,oidc,j)
        self.assertTrue(result['safeToApply'])
        self.assertEqual(result['remoteWrites'],0)
        self.assertTrue(all(m=='GET' for m,p in f.calls))
    def test_roles_v3_401_stops_before_writes(self):
        ts,rs,oidc,j,f=self.make();f.deny_roles=True
        with self.assertRaisesRegex(a.Refuse,'ROLES_V3'):
            with patch.dict(os.environ,{'WSO2_CIAM_V10_AUTHORITY_CONFIRM':a.CONFIRM}):
                a.apply(f,ts,rs,oidc,j,lambda:None)
        self.assertTrue(all(m=='GET' for m,p in f.calls))
    def test_write_requires_exact_confirmation(self):
        ts,rs,oidc,j,f=self.make()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_AUTHORITY_CONFIRM':'not-authorized'}):
            with self.assertRaisesRegex(a.Refuse,'CONFIRMATION'):
                a.apply(f,ts,rs,oidc,j,lambda:None)
        self.assertEqual(f.calls,[])
    def test_apply_exact_readback_and_idempotence(self):
        ts,rs,oidc,j,f=self.make()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_AUTHORITY_CONFIRM':a.CONFIRM}):
            result=a.apply(f,ts,rs,oidc,j,lambda:None)
            self.assertEqual(result['status'],'PROVISIONING_READBACK_VERIFIED_BROWSER_NOT_TESTED')
            first=sum(m=='POST' for m,p in f.calls)
            self.assertEqual(first,10)  # 2 resources, 4 app grants, 4 application roles
            a.apply(f,ts,rs,oidc,j,lambda:None)
            self.assertEqual(first,sum(m=='POST' for m,p in f.calls))
        self.assertEqual(len(f.roles),4)
        for (brand,name),role in f.roles.items():
            self.assertEqual(role['users'],[{'value':'user-'+brand+'-id'}])
            self.assertEqual(role['permissions'][0]['value'],a.API_SCOPE)
    def test_uncertain_write_is_never_repeated(self):
        ts,rs,oidc,j,f=self.make();f.failed='/api/server/v1/api-resources'
        with patch.dict(os.environ,{'WSO2_CIAM_V10_AUTHORITY_CONFIRM':a.CONFIRM}):
            with self.assertRaisesRegex(a.Refuse,'UNCERTAIN'):
                a.apply(f,ts,rs,oidc,j,lambda:None)
            count=sum(m=='POST' for m,p in f.calls)
            with self.assertRaisesRegex(a.Refuse,'UNCERTAIN|READ_ONLY_PRECHECK'):
                a.apply(f,ts,rs,oidc,j,lambda:None)
            self.assertEqual(count,sum(m=='POST' for m,p in f.calls))
    def test_journal_tenant_drift_denied(self):
        ts,rs,oidc,j,f=self.make();j['tenants']['brisa']['apps']['web']='other-app'
        with patch.object(a.resources,'private_read',return_value=j):
            with self.assertRaisesRegex(a.Refuse,'AUTHORITY_JOURNAL_TENANT_DRIFT'):
                a.read_journal(ts,oidc)
        self.assertEqual(f.calls,[])
    def test_unowned_resource_collision_refused(self):
        ts,rs,oidc,j,f=self.make()
        f.api['aurora']={'id':'resource-aurora','identifier':a.API_IDENTIFIER,
                         'description':'other-tenant-owned','requiresAuthorization':True}
        with self.assertRaisesRegex(a.Refuse,'UNJOURNALED_BUSINESS_API_COLLISION'):
            a.plan(f,ts,rs,oidc,j)
        self.assertTrue(all(m=='GET' for m,p in f.calls))
    def test_owned_marker_drift_refused(self):
        ts,rs,oidc,j,f=self.make()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_AUTHORITY_CONFIRM':a.CONFIRM}):
            a.apply(f,ts,rs,oidc,j,lambda:None)
        f.api['aurora']['description']='tampered'
        with self.assertRaisesRegex(a.Refuse,'OWNERSHIP_OR_POLICY'):
            a.plan(f,ts,rs,oidc,j)
    def test_role_missing_user_and_scope_refused(self):
        ts,rs,oidc,j,f=self.make()
        f.roles[('aurora',a.role_name('web'))]={'id':'role-aurora-WEB','displayName':a.role_name('web'),
            'audience':{'type':'application','value':'aurora-web-appid'},'permissions':[],'users':[]}
        with self.assertRaisesRegex(a.Refuse,'PERMISSIONS_OR_USERS'):
            a.role_readback(f,'aurora',a.tenant_auth(ts,'aurora'),'role-aurora-WEB',
                            'aurora-web-appid','user-aurora-id','web')

if __name__=='__main__':unittest.main()
