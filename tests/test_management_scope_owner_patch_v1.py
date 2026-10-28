"""Pure offline security regression cases; never contacts WSO2."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/ciam-v10/oidc/management_scope_owner_patch_v1.py'
spec = importlib.util.spec_from_file_location('p0_2_owner_patch_test', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Reader:
    @staticmethod
    def unwrap_authorizations(value):
        if isinstance(value, list): return value
        if isinstance(value, dict) and list(value) == ['authorizedAPIs']:
            return value['authorizedAPIs']
        raise ValueError('bad')
    @staticmethod
    def parse_scope_names(items):
        if not isinstance(items,list): raise ValueError('bad')
        names=[x if isinstance(x,str) else x['name'] for x in items]
        if len(names) != len(set(names)): raise ValueError('duplicate')
        return set(names)

RESOURCE = 'ABCDEF'
BASE = {'id':RESOURCE,'identifier':m.APP_API,'type':'TENANT', 'policyId':'RBAC',
        'authorizedScopes':[{'name':scope, 'id': str(i)} for i, scope in enumerate(sorted(m.REQUIRED_BEFORE))]}

def changes():
    before=[{'id':'OTHER','authorizedScopes':[{'name':'irrelevant'}]},BASE]
    after=json.loads(json.dumps(before))
    after[1]['authorizedScopes'].append({'name':m.ADD,'id':'new-id'})
    return before,after

class PureTests(unittest.TestCase):
    def test_exact_scope_only_delta(self):
        before, after=changes()
        self.assertTrue(m.is_exact_scope_delta(Reader,before,after,RESOURCE))
    def test_no_added_scope_fails(self):
        b,a=changes();a[1]['authorizedScopes'].pop()
        with self.assertRaises(m.Refuse): m.is_exact_scope_delta(Reader,b,a,RESOURCE)
    def test_replacing_existing_scope_fails(self):
        b,a=changes();a[1]['authorizedScopes'][0]['id']='changed'
        with self.assertRaises(m.Refuse): m.is_exact_scope_delta(Reader,b,a,RESOURCE)
    def test_other_authorization_changed_fails(self):
        b,a=changes();a[0]['authorizedScopes'].append({'name':'extra'})
        with self.assertRaises(m.Refuse): m.is_exact_scope_delta(Reader,b,a,RESOURCE)
    def test_policy_or_type_drift_fails(self):
        for k,v in [('type','BUSINESS'),('policyId','OTHER'),('identifier','wrong')]:
            b,a=changes();a[1][k]=v
            with self.subTest(k=k), self.assertRaises(m.Refuse):m.is_exact_scope_delta(Reader,b,a,RESOURCE)
    def test_duplicate_api_resource_fails(self):
        b,a=changes();a.append(a[1])
        with self.assertRaises(m.Refuse):m.is_exact_scope_delta(Reader,b,a,RESOURCE)
    def test_missing_previous_scope_fails(self):
        b,a=changes();b[1]['authorizedScopes'].pop()
        with self.assertRaises(m.Refuse):m.is_exact_scope_delta(Reader,b,a,RESOURCE)
    def test_patch_path_allows_only_aurora_management_api(self):
        good=f'/t/{m.DOMAIN}/api/server/v1/applications/abcde/authorized-apis/abcde'
        self.assertIsNotNone(m.MUTATION_PATH.fullmatch(good))
        for bad in [good.replace('aurora','brisa'),good.replace('/t/aurora.identity.test/', '/t/evil.identity.test/'),
                    '/api/server/v1/applications/abcde/authorized-apis/abcde',
                    good.replace('/authorized-apis/','/inbound-protocols/oidc/'), good+'?force=true',
                    good.replace('/api/server/v1/applications/', '/scim2/Users/')]:
            self.assertIsNone(m.MUTATION_PATH.fullmatch(bad))
    def test_patch_body_exactly_additive_and_only_one_request(self):
        calls=[]
        class Conn:
            def __init__(self,*a,**kw): self.hostname=a[0]; self.port=a[1]
            def request(self,method,path,body,headers): calls.append((method,path,json.loads(body),self.hostname,self.port,headers['Content-Type']))
            def getresponse(self):
                class Resp:
                    status=200
                    def read(self,n): return b''
                return Resp()
            def close(self): pass
        path=f'/t/{m.DOMAIN}/api/server/v1/applications/abcde/authorized-apis/abcde'
        with patch.object(m.http.client,'HTTPSConnection',Conn):m.patch_once(None,path,'Basic test')
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][0],'PATCH')
        self.assertEqual(calls[0][2],{'addedScopes':[m.ADD],'removedScopes':[]})
        self.assertEqual(calls[0][3:5],('localhost',9444))
    def test_patch_non_2xx_refuses(self):
        class Conn:
            def __init__(self,*a,**k):pass
            def request(self,*a,**k):pass
            def getresponse(self):
                class Resp:
                    status=403
                    def read(self,n):return b'{}'
                return Resp()
            def close(self):pass
        with patch.object(m.http.client,'HTTPSConnection',Conn):
            with self.assertRaises(m.Refuse): m.patch_once(None,f'/t/{m.DOMAIN}/api/server/v1/applications/abcde/authorized-apis/abcde','Basic test')
    def test_backup_exclusive_owner_only_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'before.private.json'
            m.exclusive_json(p,{'test':'value'})
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            self.assertEqual(m.private_json(p),{'test':'value'})
            with self.assertRaises(FileExistsError):m.exclusive_json(p,{'test':'other'})
            self.assertEqual(m.private_json(p),{'test':'value'})
    def test_unsafe_private_dir_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'private';p.mkdir(mode=0o700)
            m.check_safe_dir(p)
            p.chmod(0o755)
            with self.assertRaises(m.Refuse):m.check_safe_dir(p)
    def test_no_secret_or_raw_response_in_report(self):
        from io import StringIO
        import contextlib
        stream=StringIO()
        with contextlib.redirect_stdout(stream): m.report('NOT_VERIFIED','SCOPE_REFUSED')
        data=json.loads(stream.getvalue())
        self.assertEqual(data['managementResourceWrites'],0)
        self.assertEqual(data['status'],'NOT_VERIFIED')
    def test_does_not_modify_original_bootstrap(self):
        src=SOURCE.read_text()
        self.assertNotIn('docker restart',src)
        self.assertNotIn('fresh-bootstrap',src)
        self.assertNotIn("conn.request('PUT'",src)
        self.assertNotIn("conn.request('DELETE'",src)
        self.assertIn('PATCH_ATTEMPT_STARTED_NO_AUTOMATIC_RETRY',src)

if __name__=='__main__':unittest.main()
