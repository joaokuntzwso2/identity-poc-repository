import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parent
REPO=ROOT.parents[1]
SRC=REPO/'scripts/p2/recover_orgview_v7.py'
sp=importlib.util.spec_from_file_location('recover_orgview',SRC)
r=importlib.util.module_from_spec(sp);sp.loader.exec_module(r)

BASE=REPO/'scripts/p2/m2m_bootstrap.py'
sp=importlib.util.spec_from_file_location('fixture_m2m',BASE)
underlying=importlib.util.module_from_spec(sp);sp.loader.exec_module(underlying)
APP_ID='123e4567-e89b-42d3-a456-426614174000'
API_ID='orgApiResId1'
ROOT_ID='987e6543-e21b-42d3-a456-426614174000'
GOOD_NAME=r.APP_NAME

class MockHttp:
    def __init__(self):
        self.calls=[];self.posts=0;self.fail_post=False
        self.name=GOOD_NAME;self.desc=underlying.DESCRIPTION
        self.secret='s'*32;self.has_auth=False
        self.custom_apps=None;self.extra_grants=False
        self.api_id=API_ID
    def call(self,method,path,**kwargs):
        self.calls.append((method,path,kwargs.get('data')))
        if method=='POST':
            if path != r.APP_ROOT+'/'+APP_ID+'/authorized-apis':
                raise AssertionError('UNEXPECTED MANAGEMENT POST')
            self.posts+=1
            if self.fail_post: raise underlying.Block('WSO2_POST_OUTCOME_UNKNOWN_NO_RETRY')
            assert kwargs.get('data') == {'id':API_ID,'policyIdentifier':'RBAC','scopes':[r.SCOPE]}
            self.has_auth=True
            return 201,{},''
        assert method=='GET'
        if path==r.APP_ROOT+'?limit=100&offset=0':
            apps=self.custom_apps
            if apps is None:
                apps=[{'id':f'0000000{i}-e89b-42d3-a456-426614174000', 'name':f'Other {i}'} for i in range(6)]
                apps.append({'id':APP_ID,'name':self.name})
            return 200,{'applications':apps,'totalResults':len(apps)},''
        if path==r.APP_ROOT+'/'+APP_ID:
            return 200,{'id':APP_ID,'name':self.name,'isManagementApp':True,
                         'applicationEnabled':True,'description':self.desc},''
        if path==r.APP_ROOT+'/'+APP_ID+'/inbound-protocols/oidc':
            grants=['client_credentials','password'] if self.extra_grants else ['client_credentials']
            return 200,{'grantTypes':grants,'publicClient':False,'clientId':'aurora-client-001',
                        'clientSecret':self.secret},''
        if path==r.APP_ROOT+'/'+APP_ID+'/authorized-apis':
            if self.has_auth:
                return 200,[{'id':API_ID,'authorizedScopes':[{'name':r.SCOPE}]}],''
            return 200,[],''
        if path.startswith(r.API_ROOT+'?'):
            import urllib.parse
            q=urllib.parse.parse_qs(path.split('?',1)[1])
            query=q['filter'][0]
            identifier=query.removeprefix('identifier eq ')
            if identifier=='/o/api/server/v1/organizations':
                return 200,{'apiResources':[{'id':API_ID,'identifier':identifier}],
                            'totalResults':1,'links':[]},''
            return 200,{'apiResources':[],'totalResults':0,'links':[]},''
        if path==r.API_ROOT+'/'+API_ID:
            return 200,{'id':self.api_id,'identifier':'/o/api/server/v1/organizations',
                        'scopes':[{'name':r.SCOPE}]},''
        raise AssertionError(f'UNEXPECTED {method} {path}')

class Tests(unittest.TestCase):
    def setUp(self):
        self.http=MockHttp()
        # Module copy changes only public fingerprint helper, not source globals.
        self.m=SimpleNamespace(**{key:getattr(underlying,key) for key in dir(underlying)
                                  if not key.startswith('__')})
        self.m.hash_id=lambda v: r.FINGERPRINT if v==APP_ID else 'other'
        self.intent={'schema':'p2.24.aurora.m2m.bootstrap.v1','phase':'CREATE_INTENT',
                     'tenant':r.TENANT,'appName':r.APP_NAME,'resourceId':API_ID,
                     'scope':r.SCOPE,'remoteWritesAttempted':0}
    def test_plan_is_get_only_and_binds_candidate(self):
        state=r.assess(self.m,self.http,'approvedAdmin',self.intent)
        self.assertEqual(state['appId'],APP_ID)
        self.assertEqual(state['resourceId'],API_ID)
        self.assertEqual(self.http.posts,0)
        self.assertTrue(all(x[0]=='GET' for x in self.http.calls))
    def test_wrong_fingerprint_rejected_without_post(self):
        self.m.hash_id=lambda _: 'wrong'
        with self.assertRaisesRegex(r.Halt,'CANDIDATE_FINGERPRINT_CHANGED'):
            r.assess(self.m,self.http,'admin',self.intent)
        self.assertEqual(self.http.posts,0)
    def test_duplicate_candidate_rejected(self):
        other=[{'id':f'0000000{i}-e89b-42d3-a456-426614174000','name':'Other'} for i in range(5)]
        self.http.custom_apps=other+[{'id':APP_ID,'name':GOOD_NAME},
            {'id':'aaaaaaaa-e89b-42d3-a456-426614174000','name':GOOD_NAME}]
        with self.assertRaisesRegex(r.Halt,'CANDIDATE_NAME_NOT_UNIQUE'):
            r.assess(self.m,self.http,'admin',self.intent)
    def test_inventory_count_changed_rejected(self):
        self.http.custom_apps=[{'id':APP_ID,'name':GOOD_NAME}]
        with self.assertRaisesRegex(r.Halt,'APPLICATION_INVENTORY_COUNT_DRIFT'):
            r.assess(self.m,self.http,'admin',self.intent)
    def test_description_must_be_exact(self):
        self.http.desc='unknown'
        with self.assertRaisesRegex(r.Halt,'CANDIDATE_DESCRIPTION_NOT_EXACT'):
            r.assess(self.m,self.http,'admin',self.intent)
    def test_unexpected_grant_rejected(self):
        self.http.extra_grants=True
        with self.assertRaisesRegex(r.Halt,'CANDIDATE_OIDC_SECRET_OR_GRANT_NOT_VERIFIED'):
            r.assess(self.m,self.http,'admin',self.intent)
    def test_secret_missing_stops_before_writes(self):
        self.http.secret=None
        with self.assertRaisesRegex(r.Halt,'CANDIDATE_OIDC_SECRET_OR_GRANT_NOT_VERIFIED'):
            r.assess(self.m,self.http,'admin',self.intent)
        self.assertEqual(self.http.posts,0)
    def test_preauthorized_app_refused(self):
        self.http.has_auth=True
        with self.assertRaisesRegex(r.Halt,'CANDIDATE_ALREADY_AUTHORIZED_OR_SHAPE_DRIFT'):
            r.assess(self.m,self.http,'admin',self.intent)
    def test_api_resource_drift(self):
        self.http.api_id='wrong'
        with self.assertRaisesRegex(r.Halt,'ORGANIZATION_API_RESOURCE_NOT_VERIFIED'):
            r.assess(self.m,self.http,'admin',self.intent)
    def test_write_or_foreign_get_never_passes_readonly_wrapper(self):
        h=r.ReadOnly(self.http)
        with self.assertRaisesRegex(r.Halt,'WRITE_IN_READ_ONLY_PHASE_REFUSED'):
            h.call('POST',r.APP_ROOT,data={})
        with self.assertRaisesRegex(r.Halt,'READ_OUTSIDE_APPROVED_AURORA_PATHS'):
            h.call('GET','/t/brisa.identity.test/api/server/v1/applications')
        self.assertEqual(self.http.calls,[])
    def test_apply_posts_only_auth_and_completes_journal(self):
        with tempfile.TemporaryDirectory() as dir:
            path=Path(dir)
            underlying.exclusive_json(path/r.JOURNAL_NAME,self.intent)
            assessed=r.assess(self.m,self.http,'admin',self.intent)
            with patch.object(self.m,'oauth_token',return_value='secure-test-token-with-length-123456'),\
                 patch.object(self.m,'root_readback',return_value=ROOT_ID):
                output=r.apply_scope(self.m,self.http,'admin',path,self.intent,assessed)
            self.assertEqual(self.http.posts,1)
            self.assertEqual(output['managementAuthorizationPosts'],1)
            self.assertEqual(output['applicationCreatePosts'],0)
            record=json.loads((path/r.JOURNAL_NAME).read_text())
            self.assertEqual(record['phase'],'COMPLETE')
            self.assertEqual(record['remoteWritesAttempted'],2)
            self.assertEqual(record['rootId'],ROOT_ID)
            self.assertEqual((path/r.CREDS_NAME).stat().st_mode & 0o777,0o600)
            self.assertEqual((path/r.TOKEN_NAME).stat().st_mode & 0o777,0o600)
            self.assertNotIn('secure-test-token',json.dumps(record))
    def test_uncertain_post_does_not_retry_or_complete(self):
        with tempfile.TemporaryDirectory() as dir:
            path=Path(dir)
            underlying.exclusive_json(path/r.JOURNAL_NAME,self.intent)
            assessed=r.assess(self.m,self.http,'admin',self.intent)
            self.http.fail_post=True
            with self.assertRaisesRegex(underlying.Block,'WSO2_POST_OUTCOME_UNKNOWN_NO_RETRY'):
                r.apply_scope(self.m,self.http,'admin',path,self.intent,assessed)
            self.assertEqual(self.http.posts,1)
            record=json.loads((path/r.JOURNAL_NAME).read_text())
            self.assertEqual(record['phase'],'AUTHORIZATION_INTENT')
            self.assertEqual(record['remoteWritesAttempted'],1)
            with self.assertRaisesRegex(r.Halt,'CREATE_INTENT_UNEXPECTED_OR_ALREADY_ADVANCED'):
                r.read_intent(self.m,path)
    def test_cancellation_before_post_does_not_post(self):
        with tempfile.TemporaryDirectory() as dir:
            path=Path(dir)
            underlying.exclusive_json(path/r.JOURNAL_NAME,self.intent)
            assessed=r.assess(self.m,self.http,'admin',self.intent)
            # Existing file ensures O_EXCL refusal, before intent+POST
            underlying.exclusive_json(path/r.CREDS_NAME,{'existing':True})
            with self.assertRaisesRegex(underlying.Block,'WRITE_AHEAD_JOURNAL_EXISTS_NO_RETRY'):
                r.apply_scope(self.m,self.http,'admin',path,self.intent,assessed)
            self.assertEqual(self.http.posts,0)
    def test_report_never_prints_secrets(self):
        import io,contextlib
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):
            r.public_report('PLAN_ONLY','CODE',getRequests=7)
        self.assertNotIn('secret',stream.getvalue().lower())
        self.assertNotIn('clientId',stream.getvalue())

if __name__=='__main__':unittest.main()
