"""Offline tests for the plan-only audience change and fail-closed refusal."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'deploy/ciam-v10/oidc/audience_plan.py'
spec = importlib.util.spec_from_file_location('ciam_audience_plan', SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PlanTests(unittest.TestCase):
    def setUp(self):
        self.node = {'id':'valid_app_id_123', 'name':'Identity Lab v10 Aurora Web',
                     'description':'v10-managed:test', 'clientId':'public-client-id',
                     'callback':'http://127.0.0.1:4400/auth/aurora-web/callback'}
        self.app = {'id':self.node['id'], 'name':self.node['name'],
                    'description':self.node['description'], 'isManagementApp':False,
                    'associatedRoles':{'allowedAudience':'APPLICATION'}}
        self.oidc = {'clientId':self.node['clientId'], 'clientSecret':'PRIVATE_DO_NOT_PRINT',
                     'callbackURLs':[self.node['callback']], 'publicClient':False,
                     'grantTypes':['authorization_code','refresh_token'],
                     'pkce':{'mandatory':True}, 'subject':{'subjectType':'pairwise'},
                     'accessToken':{'type':'JWT'}, 'idToken':{'audience':[]}}
    def plan(self):
        return mod.make_plan(self.app,self.oidc,self.node,self.node['id'],self.node['name'])
    def test_minimal_change_and_no_secrets(self):
        result=self.plan()
        self.assertEqual(result['proposedChange']['path'], '/idToken/audience')
        self.assertEqual(result['proposedChange']['after'],[mod.AUDIENCE])
        self.assertNotIn('PRIVATE_DO_NOT_PRINT',str(result))
        self.assertNotIn('public-client-id',str(result))
        self.assertFalse(result['safeForAutomaticApply'])
    def test_reject_nonempty_audience(self):
        self.oidc['idToken']['audience']=['https://other.example/api']
        with self.assertRaises(mod.Refuse):self.plan()
    def test_reject_role_audience_drift(self):
        self.app['associatedRoles']['allowedAudience']='ORGANIZATION'
        with self.assertRaises(mod.Refuse):self.plan()
    def test_reject_callback_drift(self):
        self.oidc['callbackURLs']=['http://127.0.0.1:4400/other']
        with self.assertRaises(mod.Refuse):self.plan()
    def test_reject_missing_audience_field(self):
        self.oidc['idToken']={}
        with self.assertRaises(mod.Refuse):self.plan()
    def test_reject_wrong_client(self):
        self.oidc['clientId']='untracked-client'
        with self.assertRaises(mod.Refuse):self.plan()

if __name__=='__main__':unittest.main()
