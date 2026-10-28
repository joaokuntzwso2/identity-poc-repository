"""Offline safety tests for separate additive cases RBAC stage."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / 'bootstrap.py'
spec = importlib.util.spec_from_file_location('ciam_cases_bootstrap_tested', FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Fake:
    def __init__(self, oidc):
        self.calls = []
        self.oidc=oidc
    def call(self, method, path, *, auth, data=None, form=None):
        self.calls.append((method,path,data))
        if method != 'GET':
            raise AssertionError('preflight wrote to WSO2')
        if '/api/server/v1/api-resources?' in path:
            return 200, {'APIResources':[], 'totalResults':0},None
        if '/api/server/v1/applications/' in path:
            brand = 'aurora' if '/t/aurora.' in path else 'brisa'
            appid = path.split('/')[-1]
            channel = 'web' if appid.endswith('web') else 'app'
            app = self.oidc['tenants'][brand]['clients'][channel]
            return 200, {'id':appid, 'name':app['name'], 'associatedRoles':{'allowedAudience':'APPLICATION'}},None
        if '/scim2/Users/' in path:
            return 200, {'id':path.split('/')[-1], 'active':True},None
        if '/scim2/v2/Roles?' in path:
            return 200, {'Resources':[],'totalResults':0},None
        raise AssertionError('Unexpected GET: ' + path)

def fixture():
    ts={'tenants': {b:{'owner':{'password':'local-test-password'}} for b in m.DOMAINS}}
    oidc={'tenants':{b:{'clients':{c:{'id':b+'-'+c, 'name':b+'-'+c} for c in ('web','app')}} for b in m.DOMAINS}}
    identities={'tenants':{
        'aurora': {'users':{'customer-ana': {'id':'USER_ANA_A'},'seller-marcos':{'id':'USER_SELLER_A'}}},
        'brisa': {'users':{'customer-ana': {'id':'USER_ANA_B'}}}}}
    seed={'people':[{'key':'customer-ana','type':'customer','brands':['aurora','brisa']},
                    {'key':'seller-marcos','type':'seller','brands':['aurora']}]}
    authority={}
    journal={'tenants':{b:{'resource':None,'authorizations':{},'roles':{}} for b in m.DOMAINS}}
    return (ts,oidc,authority,identities,seed,'v2'), journal

class Tests(unittest.TestCase):
    def test_scope_policy_separates_roles(self):
        self.assertNotIn('ciam:cases:approve',m.CUSTOMER_SCOPES)
        self.assertIn('ciam:cases:review',m.SELLER_SCOPES)
        self.assertIn('ciam:cases:read',m.SELLER_SCOPES)
        self.assertEqual(len(m.SCOPES),4)
    def test_https_identifier_explicit(self):
        for value in ('','http://api.example/cases','https://u:p@example/cases','https://x/cases?q=1'):
            with patch.dict(os.environ, {'WSO2_CIAM_CASES_API_IDENTIFIER':value}):
                with self.assertRaises(m.Refuse):m.case_identifier()
        with patch.dict(os.environ, {'WSO2_CIAM_CASES_API_IDENTIFIER':'https://api.ciam-v10.test/cases'}):
            self.assertEqual(m.case_identifier(),'https://api.ciam-v10.test/cases')
    def test_pinned_bff_urn_and_identifier_safety(self):
        with patch.dict(os.environ, {'WSO2_CIAM_CASES_API_IDENTIFIER':'urn:ciampoc:service-requests:v1'}):
            self.assertEqual(m.case_identifier(), 'urn:ciampoc:service-requests:v1')
        for value in (
            'urn:ciampoc:service-requests:v2',
            'urn:ciampoc:other-api:v1',
            '[https://api.ciam-v10.test/cases](https://api.ciam-v10.test/cases)',
            ' https://api.ciam-v10.test/cases',
        ):
            with self.subTest(identifier=value):
                with patch.dict(os.environ, {'WSO2_CIAM_CASES_API_IDENTIFIER':value}):
                    with self.assertRaises(m.Refuse):
                        m.case_identifier()

    def test_plan_hash_changes_for_actual_bff_urn(self):
        old = {'apiIdentifier': 'https://api.ciam-v10.test/cases', 'plannedActions': []}
        new = {'apiIdentifier': 'urn:ciampoc:service-requests:v1', 'plannedActions': []}
        self.assertNotEqual(m.plan_hash(old), m.plan_hash(new))

    def test_read_only_preflight_plans_exact_roles_and_resource(self):
        ctx,journal=fixture();fake=Fake(ctx[1]);
        plan=m.examine(fake,ctx,journal,'https://api.ciam-v10.test/cases')
        self.assertFalse(any(method!='GET' for method,_,_ in fake.calls))
        self.assertEqual(sum(x[-1]=='create_app_role' for x in plan['plannedActions']),6)
        self.assertEqual(sum(x[-1]=='authorize_case_api' for x in plan['plannedActions']),4)
        self.assertEqual(sum(x[-1]=='create_api_resource' for x in plan['plannedActions']),2)
    def test_unjournaled_remote_resource_collision_refused(self):
        ctx,journal=fixture()
        class Collision(Fake):
            def call(self,method,path,*,auth,data=None,form=None):
                if '/api/server/v1/api-resources?' in path:
                    return 200,{'APIResources':[{'identifier':'https://api.ciam-v10.test/cases','id':'OLD_API_ID'}], 'totalResults':1},None
                return super().call(method,path,auth=auth,data=data,form=form)
        with self.assertRaisesRegex(m.Refuse,'UNJOURNALED_CASE_RESOURCE_COLLISION'):
            m.examine(Collision(ctx[1]),ctx,journal,'https://api.ciam-v10.test/cases')
    def test_wrong_application_role_audience_refused(self):
        class RoleClient:
            def call(self,method,path,*,auth,data=None,form=None):
                return 200,{'id':'ROLE_123','displayName':'CIAM v10 Cases Customer WEB',
                    'audience':{'value':'wrong-app','type':'application'},
                    'users':[{'value':'USER_A'}], 'permissions':[{'value':'ciam:cases:create'},{'value':'ciam:cases:read'}]},None
        with self.assertRaisesRegex(m.Refuse,'CASE_ROLE_READBACK_DRIFT'):
            m.verify_role(RoleClient(),'aurora','fake','v2',{'id':'ROLE_123'},
                {'state':'verified'},'CIAM v10 Cases Customer WEB','aurora-web',['USER_A'],m.CUSTOMER_SCOPES)
    def test_plan_hash_changes_with_actions(self):
        self.assertNotEqual(m.plan_hash({'plannedActions':[]}),m.plan_hash({'plannedActions':[['aurora','write']]}))

if __name__=='__main__':unittest.main()
