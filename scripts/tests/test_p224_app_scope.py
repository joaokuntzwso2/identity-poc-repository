"""WSO2 7.3 GA org-application permission contract: view replaces invalid list.

Standalone tests import the installed authority module. No network or secrets.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'p2-bootstrap-authority.py'
spec = spec_from_file_location('p224_app_scope_authority', SOURCE)
a = module_from_spec(spec)
spec.loader.exec_module(a)

EXPECTED_APP = (
    'internal_org_application_mgt_view',
    'internal_org_application_mgt_create',
    'internal_org_application_mgt_update',
)

class Wire:
    def __init__(self, *, omit_view=False, standalone=False):
        self.calls = []
        self.ids = {identifier:'catalog_'+str(i+100) for i,identifier in enumerate(a.POLICY)}
        self.omit_view = omit_view
        self.standalone = standalone

    def call(self, method, path, *, auth, payload=None, form=None):
        self.calls.append((method,path))
        assert method == 'GET' and auth == 'Basic fixture-only' and payload is None and form is None
        if path.startswith(a.CATALOG+'?'):
            return 200, {
                'APIResources':[{'id':v,'identifier':k} for k,v in self.ids.items()],
                'totalResults':len(self.ids)
            }, None
        for ident,rid in self.ids.items():
            if path == a.CATALOG+'/'+rid:
                scopes = list(EXPECTED_APP) if ident==a.APPS_ID else list(a.POLICY[ident])
                if ident==a.APPS_ID and self.omit_view:
                    scopes.remove('internal_org_application_mgt_view')
                body={'id':rid,'identifier':ident}
                if not self.standalone: body['scopes']=[{'name':x} for x in scopes]
                return 200,body,None
            if path == a.CATALOG+'/'+rid+'/scopes':
                scopes = list(EXPECTED_APP) if ident==a.APPS_ID else list(a.POLICY[ident])
                if ident==a.APPS_ID and self.omit_view:
                    scopes.remove('internal_org_application_mgt_view')
                return 200,[{'name':x} for x in scopes],None
        raise AssertionError((method,path))

class ScopeContractTests(unittest.TestCase):
    def test_org_apps_exact_verified_permission_family(self):
        self.assertEqual(a.POLICY[a.APPS_ID],EXPECTED_APP)
        self.assertNotIn('internal_org_application_mgt_list',a.POLICY[a.APPS_ID])
        self.assertNotIn(a.ROOT_ID,a.POLICY)

    def test_realistic_catalog_permission_inventory_passes_without_writes(self):
        w=Wire()
        result=a.discovery(w,'Basic fixture-only')
        self.assertEqual(result[a.APPS_ID],w.ids[a.APPS_ID])
        self.assertEqual(len(result),5)
        self.assertTrue(all(method=='GET' for method,_ in w.calls))

    def test_dedicated_scopes_readback_is_supported(self):
        w=Wire(standalone=True)
        result=a.discovery(w,'Basic fixture-only')
        self.assertEqual(result[a.APPS_ID],w.ids[a.APPS_ID])
        self.assertTrue(any(p.endswith('/scopes') for _,p in w.calls))

    def test_missing_real_view_permission_fails_closed(self):
        w=Wire(omit_view=True)
        with self.assertRaisesRegex(a.Stop,'API_RESOURCE_REQUIRED_SCOPE_UNSUPPORTED_applications_internal_org_application_mgt_view'):
            a.discovery(w,'Basic fixture-only')
        self.assertTrue(all(m=='GET' for m,_ in w.calls))

if __name__=='__main__': unittest.main()
