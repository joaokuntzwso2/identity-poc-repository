"""Fresh OIDC clients must explicitly consume WSO2 APPLICATION roles."""
import os
import unittest
from unittest.mock import patch
from test_bootstrap import b, Fake, state

class ApplicationAudience(unittest.TestCase):
    def test_all_four_create_payloads_explicit_application_audience(self):
        f=Fake(); t,r,s=state()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_OIDC_CONFIRM':b.CONFIRM}):
            result=b.run(f,t,r,s,'apply',lambda:None)
        self.assertEqual(result['oidcClients'],'FOUR_REGISTERED_AND_READBACK_VERIFIED')
        self.assertEqual(len(f.apps),4)
        for app in f.apps.values():
            self.assertEqual(app['associatedRoles']['allowedAudience'],'APPLICATION')
            self.assertEqual(app['associatedRoles']['roles'],[])

    def test_readback_rejects_wrong_audience_without_updates(self):
        f=Fake();t,r,s=state()
        with patch.dict(os.environ,{'WSO2_CIAM_V10_OIDC_CONFIRM':b.CONFIRM}):
            b.run(f,t,r,s,'apply',lambda:None)
        brand='aurora';channel='web'
        node=s['tenants'][brand]['clients'][channel]
        f.apps[brand+':'+node['id']]['associatedRoles']['allowedAudience']='ORGANIZATION'
        before=sum(method=='POST' for method,_ in f.calls)
        with self.assertRaisesRegex(b.Refuse,'APPLICATION_ROLE_AUDIENCE_NOT_VERIFIED'):
            b.check_app(f,brand,channel,'Bearer fixture',node)
        self.assertEqual(before,sum(method=='POST' for method,_ in f.calls))

if __name__=='__main__':unittest.main()
