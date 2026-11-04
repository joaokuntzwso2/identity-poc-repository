"""Regression for v36's observed WSO2 7.3 API authorization HTTP 200 behavior.

Offline only: never contacts WSO2 or changes local data.
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import unittest

BASE=Path(__file__).resolve().parents[2]
SOURCE=BASE/'scripts/p2/p2_24_v36_full_automatic_directory_bootstrap.py'
spec=importlib.util.spec_from_file_location('p224_v45_actual_bootstrap',SOURCE)
v36=importlib.util.module_from_spec(spec)
spec.loader.exec_module(v36)

APP='11111111-1111-1111-1111-111111111111'
U='22222222-2222-2222-2222-222222222222'
G='33333333-3333-3333-3333-333333333333'
P='44444444-4444-4444-4444-444444444444'
USERS=['internal_org_user_mgt_create','internal_org_user_mgt_list','internal_org_user_mgt_view']
GROUPS=['internal_org_group_mgt_create','internal_org_group_mgt_view']

def r(rid,scopes,policy='RBAC'):
    return {'id':rid,'authorizedScopes':[{'name':s} for s in scopes],
            'policyIdentifier':policy}

class Store:
    instance=None
    def __init__(self,*args):
        self.doc={'partnerId':P,'name':v36.NAME,'applicationId':APP,
                  'attempts':{'CREATE_APP':{'state':'VERIFIED'},'SET_OIDC':{'state':'VERIFIED'},
                      'AUTH_USERS':{'state':'RESPONSE_REQUIRES_REVIEW','httpStatus':200,
                         'method':'POST','path':v36.APP_PATH+'/'+APP+'/authorized-apis'}}}
        self.sent=[];self.done_names=[];Store.instance=self
    def attempt(self,stage,method,path,api,body,accepted):
        if stage in self.doc['attempts']:raise v36.Block('REPEATED_ATTEMPT')
        status,_,_=api.call(method,path,body)
        self.sent.append((stage,status))
        self.doc['attempts'][stage]={'state':'ACKNOWLEDGED','httpStatus':status,'method':method,'path':path}
        if status not in accepted:raise v36.Block('REJECTED')
    def done(self,stage):
        self.doc['attempts'][stage]['state']='VERIFIED';self.done_names.append(stage)

class Api:
    def __init__(self,status=200,scopes=GROUPS,policy='RBAC'):
        self.rows=[r(U,USERS)];self.group_status=status;self.group_scopes=scopes;self.group_policy=policy
        self.posts=[]
    def call(self,method,path,body=None):
        if method=='POST':
            self.posts.append(body['id'])
            if body['id'] != G: raise AssertionError('Attempted repeated Users POST')
            self.rows.append(r(G,self.group_scopes,self.group_policy))
            return self.group_status,{},{}
        return 403,{},{}

class Tests(unittest.TestCase):
    def check(self,api,store_cls=Store):
        ctx={'private':Path('/unused'), 'partner':P,
             'v18':SimpleNamespace(SCOPES=tuple(sorted(USERS+GROUPS)))}
        resources={'Users':(U,USERS),'Groups':(G,GROUPS)}
        with mock.patch.object(v36,'Store',store_cls),\
             mock.patch.object(v36,'app_candidates',return_value=[{'applicationId':APP}]),\
             mock.patch.object(v36,'app_detail',return_value={}),\
             mock.patch.object(v36,'oidc_state',return_value={}),\
             mock.patch.object(v36,'oidc_exact',return_value=True),\
             mock.patch.object(v36,'api_authorizations',side_effect=lambda *_:api.rows),\
             mock.patch.object(v36,'share_exact',return_value=False):
            with self.assertRaises(v36.Block):v36.bootstrap(ctx,api,resources)
        return Store.instance
    def test_verified_users_200_does_not_repeat_post(self):
        api=Api(status=200);st=self.check(api)
        self.assertEqual(api.posts,[G]);self.assertEqual(st.done_names,['AUTH_USERS','AUTH_GROUPS'])
    def test_groups_201_also_verified(self):
        api=Api(status=201);st=self.check(api)
        self.assertEqual(api.posts,[G]);self.assertEqual(st.done_names,['AUTH_USERS','AUTH_GROUPS'])
    def test_extra_group_scope_is_blocked(self):
        api=Api(scopes=GROUPS+['internal_org_group_mgt_delete']);st=self.check(api)
        self.assertEqual(st.done_names,['AUTH_USERS'])
    def test_wrong_policy_is_blocked(self):
        api=Api(policy='NONE');st=self.check(api)
        self.assertEqual(st.done_names,['AUTH_USERS'])
    def test_previous_group_intent_is_not_reposted(self):
        class WithGroupIntent(Store):
            def __init__(self,*a):
                super().__init__(*a)
                self.doc['attempts']['AUTH_GROUPS']={'state':'INTENT'}
        api=Api();st=self.check(api,WithGroupIntent)
        self.assertEqual(api.posts,[]);self.assertEqual(st.done_names,['AUTH_USERS'])
    def test_unowned_users_authorization_is_not_adopted(self):
        class MissingUsers(Store):
            def __init__(self,*a):
                super().__init__(*a)
                del self.doc['attempts']['AUTH_USERS']
        api=Api();st=self.check(api,MissingUsers)
        self.assertEqual(api.posts,[]);self.assertEqual(st.done_names,[])

if __name__=='__main__':unittest.main(verbosity=2)
