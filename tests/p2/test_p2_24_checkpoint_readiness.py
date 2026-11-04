import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

modpath=Path(__file__).resolve().parents[2] / 'scripts/p2/p2_24_checkpoint/readiness.py'
spec=importlib.util.spec_from_file_location('v47',modpath)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_401_denied(self):self.assertEqual(m.classify_denial(401),'EXPLICITLY_DENIED')
    def test_403_denied(self):self.assertEqual(m.classify_denial(403),'EXPLICITLY_DENIED')
    def test_200_is_critical(self):self.assertIn('VIOLATION',m.classify_denial(200))
    def test_404_is_not_proof_of_denial(self):self.assertEqual(m.classify_denial(404),'INCONCLUSIVE')
    def test_timeout_is_inconclusive(self):self.assertEqual(m.classify_denial(None),'INCONCLUSIVE')
    def test_role_org_only(self):
        r=m.role_resources([{'id':'1','identifier':'https://localhost:9444/t/aurora/o/scim2/v2/Roles'},
             {'id':'2','identifier':'https://localhost:9444/t/aurora/scim2/v2/Roles'}])
        self.assertEqual(len(r),1)
    def test_role_duplicate_rejected(self):
        with self.assertRaises(m.Blocked):m.role_resources([{'id':'1','identifier':'/o/scim2/v2/Roles'},
                                            {'id':'1','identifier':'/o/scim2/v2/Roles'}])
    def test_root_roles_not_treated_as_org(self):self.assertEqual(m.role_resources([{'id':'1','identifier':'/scim2/v2/Roles'}]),[])
    def test_bearer_path_reject_rootless(self):
        with self.assertRaises(m.Blocked): m.get_bearer_status('a'*26,'https://host/scim2/Users?count=1',Path('/fake'))
    def test_bearer_path_reject_traversal(self):
        with self.assertRaises(m.Blocked):m.get_bearer_status('a'*26,'/t/aurora.identity.test/../scim2/Users?count=1',Path('/fake'))
    def test_inventory_omits_private(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'private').mkdir();(p/'private'/'sensitive.ts').write_text('secret')
            (p/'web').mkdir();(p/'web'/'package.json').write_text(json.dumps({'dependencies':{'react':'*','vite':'*'},'scripts':{'build':'vite build'}}))
            (p/'web'/'PartnerAdmin.tsx').write_text('export const X = 1')
            x=m.inventory(p)
            self.assertEqual(len(x['packageManifests']),1)
            self.assertIn('web/PartnerAdmin.tsx',x['likelyIntegrationFiles'])
            self.assertNotIn('private/sensitive.ts',x['likelyIntegrationFiles'])
    def test_inventory_ignores_build(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'dist').mkdir();(p/'dist'/'PartnerAdmin.tsx').write_text('no')
            self.assertFalse(m.inventory(p)['likelyIntegrationFiles'])
    def test_only_audit(self):
        with self.assertRaises(m.Blocked): m.main(['bootstrap'])

if __name__=='__main__':unittest.main(verbosity=2)
