import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

SRC=Path(__file__).parents[1]/'bootstrap.py'
spec=importlib.util.spec_from_file_location('oidc_v10',SRC)
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class Fake:
    def __init__(self):
        self.calls=[];self.apps={};self.number=0;self.create_status=201;self.fail_readback=False
    def mkid(self):
        self.number+=1
        return '12345678-abcd-abcd-abcd-'+str(self.number).zfill(12)
    def call(self,method,path,*,auth=None,data=None,form=None):
        self.calls.append((method,path))
        brand=next((k for k,v in b.DOMAINS.items() if f'/t/{v}/' in path),None)
        if not brand:raise AssertionError('unexpected '+path)
        key=brand+':'
        if method=='POST' and path.endswith('/oauth2/token'):
            return 200,{'token_type':'Bearer','access_token':'token','scope':form['scope']},None
        if 'openid-configuration' in path:
            return 200,{'issuer':f'https://localhost:9444/t/{b.DOMAINS[brand]}/oauth2/token',
                        'jwks_uri':f'https://localhost:9444/t/{b.DOMAINS[brand]}/oauth2/jwks'},None
        endpoint=f'/t/{b.DOMAINS[brand]}/api/server/v1/applications'
        if method=='GET' and path.startswith(endpoint+'?'):
            return 200,{'totalResults':0 if not [a for k,a in self.apps.items() if k.startswith(key) and a['name'] in path.replace('+',' ').replace('%20',' ')] else 1,
                        'applications':[{'id':a['id'],'name':a['name']} for k,a in self.apps.items() if k.startswith(key) and a['name'] in path.replace('+',' ').replace('%20',' ')]},None
        if method=='POST' and path==endpoint:
            if self.create_status!=201:return self.create_status,{},None
            appid=self.mkid();self.apps[key+appid]={'id':appid,**data};return 201,{'id':appid},None
        if method=='GET' and path.startswith(endpoint+'/'):
            suffix=path[len(endpoint)+1:].split('/')
            appid=suffix[0];app=self.apps.get(key+appid)
            if not app:return 404,{},None
            if len(suffix)==1:return 200,app,None
            if suffix[1:]!=['inbound-protocols','oidc']:raise AssertionError(path)
            item={**app['inboundProtocolConfiguration']['oidc'],'clientId':'oidc-id-'+appid,'clientSecret':'oidc-secret-'+appid}
            if self.fail_readback:item['callbackURLs']=['http://untrusted.invalid']
            return 200,item,None
        raise AssertionError((method,path))

def state():
    ts={'schema':'identity.wso2.ciam.v10.tenants','base':b.BASE,'domains':b.DOMAINS,
        'tenants':{x:{'status':'readback-verified','domain':d,'tenantId':'tenant-'+x,'ownerId':'owner-'+x} for x,d in b.DOMAINS.items()}}
    rs={'schema':'identity.wso2.ciam.v10.resources.v1','base':b.BASE,
        'acceptance':'MANAGEMENT_AND_USERS_VERIFIED_OIDC_NOT_PROVISIONED',
        'tenants':{x:{'domain':d,'tenantId':'tenant-'+x,'ownerId':'owner-'+x,
                      'management':{'state':'verified','id':'manager-'+x,'clientId':'id-'+x,'clientSecret':'secret-'+x},
                      'user':{'state':'verified-browser-not-tested','username':'ciam_'+x,'id':'user-'+x}}
                   for x,d in b.DOMAINS.items()}}
    return ts,rs,b.default_state(ts,rs)

class Tests(unittest.TestCase):
    def test_plan_does_not_write_resources_or_journal(self):
        f=Fake();t,r,s=state(); snapshots=[]
        result=b.run(f,t,r,s,'plan',lambda:snapshots.append(1))
        self.assertEqual(result['clientsPlanned'],4)
        self.assertFalse(snapshots)
        self.assertFalse(any(m=='POST' and not p.endswith('/oauth2/token') for m,p in f.calls))
    def test_apply_four_clients_and_idempotent(self):
        f=Fake();t,r,s=state(); snapshots=[]
        with patch.dict(os.environ,{'WSO2_CIAM_V10_OIDC_CONFIRM':b.CONFIRM}):
            result=b.run(f,t,r,s,'apply',lambda:snapshots.append(repr(s)))
            self.assertEqual(result['oidcClients'],'FOUR_REGISTERED_AND_READBACK_VERIFIED')
            created=sum(m=='POST' and p.endswith('/applications') for m,p in f.calls)
            self.assertEqual(created,4)
            again=b.run(f,t,r,s,'apply',lambda:None)
            self.assertEqual(again['oidcClients'],'FOUR_REGISTERED_AND_READBACK_VERIFIED')
            self.assertEqual(created,sum(m=='POST' and p.endswith('/applications') for m,p in f.calls))
        manifest=b.bridge_manifest(s)
        self.assertEqual(manifest['brands']['aurora']['clients']['web']['callback'],b.CALLBACK('aurora','web'))
        self.assertNotEqual(manifest['brands']['aurora']['issuer'],manifest['brands']['brisa']['issuer'])
        self.assertEqual(len(snapshots)>4,True)
    def test_requires_confirmation(self):
        f=Fake();t,r,s=state()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_OIDC_CONFIRM':''}):
            with self.assertRaisesRegex(b.Refuse,'CONFIRMATION'):
                b.run(f,t,r,s,'apply',lambda:None)
        self.assertFalse(any(m=='POST' and p.endswith('/applications') for m,p in f.calls))
    def test_unexpected_create_response_is_not_retried(self):
        f=Fake();f.create_status=206;t,r,s=state()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_OIDC_CONFIRM':b.CONFIRM}):
            with self.assertRaisesRegex(b.Refuse,'OIDC_CREATE_HTTP_206'):
                b.run(f,t,r,s,'apply',lambda:None)
            count=sum(m=='POST' and p.endswith('/applications') for m,p in f.calls)
            with self.assertRaisesRegex(b.Refuse,'UNCERTAIN'):
                b.run(f,t,r,s,'apply',lambda:None)
            self.assertEqual(count,sum(m=='POST' and p.endswith('/applications') for m,p in f.calls))
    def test_readback_mismatch_stops_and_preserves_creation(self):
        f=Fake();f.fail_readback=True;t,r,s=state()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_OIDC_CONFIRM':b.CONFIRM}):
            with self.assertRaisesRegex(b.Refuse,'CALLBACK_MISMATCH'):
                b.run(f,t,r,s,'apply',lambda:None)
            self.assertEqual(s['tenants']['aurora']['clients']['web']['state'],'created')
        self.assertEqual(len(f.apps),1)
    def test_no_unjournaled_application_adoption(self):
        f=Fake();t,r,s=state()
        appid=f.mkid()
        f.apps['aurora:'+appid]={'id':appid,'name':b.NAME('aurora','web'),'description':'external',
                                 'isManagementApp':False,'inboundProtocolConfiguration':{'oidc':{}}}
        with patch.dict(os.environ,{'WSO2_CIAM_V10_OIDC_CONFIRM':b.CONFIRM}):
            with self.assertRaisesRegex(b.Refuse,'UNJOURNALED'):
                b.run(f,t,r,s,'apply',lambda:None)
    def test_bridge_requires_all_four(self):
        t,r,s=state()
        with self.assertRaisesRegex(b.Refuse,'FOUR_OIDC_APPS'):
            b.bridge_manifest(s)
    def test_context_drift_refused(self):
        t,r,s=state();s['bffOrigin']='http://127.0.0.1:4000'
        with self.assertRaisesRegex(b.Refuse,'DRIFT'):
            b.check_state(s,t,r)

if __name__=='__main__':unittest.main()
