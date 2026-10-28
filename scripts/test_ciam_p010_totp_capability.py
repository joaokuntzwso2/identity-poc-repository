import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).with_name('ciam-p010-totp-capability.py')
SPEC = importlib.util.spec_from_file_location('p010_totp_audit_test', PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

class Transport:
    def __init__(self, statuses=None, bodies=None):
        self.calls = []
        self.statuses = statuses or {}
        self.bodies = bodies or {}
    def call(self, method, path, *, auth=None):
        self.calls.append((method,path,auth))
        return self.statuses.get(path,200), self.bodies.get(path,[{'name':'totp','type':'LOCAL','isEnabled':True}]), None

class Tests(unittest.TestCase):
    def test_list_response(self):
        self.assertTrue(M.summarize([{'name':'totp','type':'LOCAL','isEnabled':True}])['totpEnabled'])
    def test_object_response(self):
        self.assertTrue(M.summarize({'authenticators':[{'name':'TOTPAuthenticator','type':'LOCAL','isEnabled':True}]})['totpEnabled'])
    def test_missing_not_inferred(self):
        self.assertFalse(M.summarize([{'name':'BasicAuthenticator','isEnabled':True}])['totpAuthenticatorListed'])
    def test_disabled(self):
        self.assertFalse(M.summarize([{'name':'totp','isEnabled':False,'type':'LOCAL'}])['totpEnabled'])
    def test_missing_enabled_refused(self):
        with self.assertRaisesRegex(M.Refused,'ENABLEMENT'):
            M.summarize([{'name':'totp','type':'LOCAL'}])
    def test_wrong_type_refused(self):
        with self.assertRaisesRegex(M.Refused,'ENABLEMENT'):
            M.summarize([{'name':'totp','isEnabled':True,'type':'FEDERATED'}])
    def test_duplicate_refused(self):
        with self.assertRaisesRegex(M.Refused,'AMBIGUOUS'):
            M.summarize([{'name':'totp','isEnabled':True},{'name':'TOTPAuthenticator','isEnabled':True}])
    def test_malformed_result_refused(self):
        for obj in ({'wrong':[]}, {'items':{},'authenticators':[]}, 'text'):
            with self.subTest(obj=obj),self.assertRaises(M.Refused):M.summarize(obj)
    def test_get_only_prevents_writes_and_other_urls(self):
        c=M.GetOnly(Transport())
        for method,path in [('POST',M.PATH_NEW.format(domain='aurora.identity.test')),
                            ('GET','/t/evil/api/server/v1/authenticators'),
                            ('PUT',M.PATH_OLD.format(domain='brisa.identity.test'))]:
            with self.subTest(method=method,path=path),self.assertRaisesRegex(M.Refused,'GET_ONLY'):
                c.call(method,path,auth='secret')
        self.assertEqual(c.requests,0)
    def test_fallback_on_404(self):
        p=M.PATH_NEW.format(domain='aurora.identity.test'); t=Transport({p:404}); c=M.GetOnly(t)
        self.assertTrue(M.probe(c,'aurora.identity.test','x')['totpEnabled']);self.assertEqual(c.requests,2)
    def test_no_fallback_on_403(self):
        p=M.PATH_NEW.format(domain='aurora.identity.test');t=Transport({p:403});c=M.GetOnly(t)
        with self.assertRaisesRegex(M.Refused,'PERMISSION_REQUIRED'):M.probe(c,'aurora.identity.test','x')
        self.assertEqual(c.requests,1)
    def test_remote_500_refused(self):
        p=M.PATH_NEW.format(domain='aurora.identity.test');t=Transport({p:500});c=M.GetOnly(t)
        with self.assertRaisesRegex(M.Refused,'UNAVAILABLE'):M.probe(c,'aurora.identity.test','x')
    def test_two_tenants_no_secret_in_result(self):
        t=Transport();c=M.GetOnly(t)
        ts={'domains':M.DOMAINS,'tenants':{b:{'domain':d,'owner':{'username':'owner','password':'private_'+b}} for b,d in M.DOMAINS.items()}}
        r=M.audit(c,ts,basic=lambda u,p:'Basic '+u+':'+p,owner='owner')
        self.assertEqual(r['status'],'AURORA_TOTP_AUTHENTICATOR_AVAILABLE_POLICY_AND_ENROLLMENT_PENDING')
        self.assertEqual(r['getRequests'],2)
        self.assertNotIn('private_',str(r))
        self.assertIn('SIGNED_ACR_AMR_AUTH_TIME',r['assertionsNotMade'])
    def test_wrong_owner_refused(self):
        ts={'domains':M.DOMAINS,'tenants':{b:{'domain':d,'owner':{'username':'wrong','password':'x'}} for b,d in M.DOMAINS.items()}}
        with self.assertRaisesRegex(M.Refused,'OWNER_CONTEXT_DRIFT'):
            M.audit(M.GetOnly(Transport()),ts,basic=lambda *_:'secret',owner='owner')

if __name__ == '__main__':unittest.main()
