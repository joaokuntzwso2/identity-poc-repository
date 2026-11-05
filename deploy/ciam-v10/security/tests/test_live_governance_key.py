"""Regression evidence from the observed GA 7.3 REST connector response."""
import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('g_runtime_key', root/'governance.py')
g=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

class LiveGAGovernanceProperty(unittest.TestCase):
    def test_live_connector_property_not_latest_docs_alias(self):
        key='account.lock.handler.lock.on.max.failed.attempts.enable'
        for tenant, fields in g.DESIRED.items():
            with self.subTest(tenant=tenant):
                self.assertEqual(fields[key], 'true')
                self.assertNotIn('account.lock.handler.enable', fields)

    def test_real_catalog_shape_discovery_no_alias_needed(self):
        key='account.lock.handler.lock.on.max.failed.attempts.enable'
        tenant='aurora.identity.test'
        def getter(t, path):
            self.assertEqual(t, tenant)
            if path=='/api/server/v1/identity-governance':
                return [{'id':'logins','name':'Login Attempts Security'}]
            if path.endswith('/connectors'):
                return [{'id':'account.lock.handler','name':'account.lock.handler',
                         'properties':[{'name':key,'value':'false'},
                                       {'name':'account.lock.handler.On.Failure.Max.Attempts','value':'5'},
                                       {'name':'account.lock.handler.Time','value':'3'},
                                       {'name':'account.lock.handler.login.fail.timeout.ratio','value':'2'}]}]
            raise AssertionError('unrecognized catalog endpoint: '+path)
        found=g.discovered(tenant,getter)
        self.assertEqual(set(found),set(g.DESIRED[tenant]))
        self.assertEqual(g.delta(tenant,found)[key]['after'],'true')

if __name__=='__main__':unittest.main()
