"""No network: verify v4 bridge supports actual diagnostic auth helper layout."""
import base64
import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE=Path(__file__).resolve().parents[2]/'scripts/p2/m2m_bootstrap.py'
spec=importlib.util.spec_from_file_location('m2m_bridge_v4_test',MODULE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def build_source(tenant='aurora.identity.test', auth_mode='namespaced',
                 wrong_method=False, two=False, unqualified=False, wrong_origin=False):
    username='service-owner' if unqualified else 'service-owner@'+tenant
    method='POST' if wrong_method else 'GET'
    path='/t/aurora.identity.test/api/server/v1/api-resources'
    if wrong_origin: path='https://evil.invalid'+path
    base=f'''\nimport base64\nclass Namespace:\n    @staticmethod\n    def basic(pair):\n        return 'Basic '+base64.b64encode((pair[0]+':'+pair[1]).encode()).decode()\nresources=Namespace()\ndef private_context():\n    return ({{'aurora':{{'username':{username!r},'password':'private-value'}}}},{{}},{{}})\ndef diagnostic(client,ts,rs,oidc):\n    try:client.call({method!r},{path!r},headers={{'Authorization':resources.basic((ts['aurora']['username'],ts['aurora']['password']))}})\n    except OSError:pass\n'''
    if auth_mode=='module':
        base+='\ndef basic(pair):return resources.basic(pair)\n'
    if auth_mode=='missing':
        base=base.replace('resources.basic((ts[','(ts[').replace("ts['aurora']['password']))}","ts['aurora']['password'])}")
    if two:
        base+='''\n    try:client.call('GET','/t/aurora.identity.test/api/server/v1/api-resources',headers={'Authorization':resources.basic(('other@aurora.identity.test','different-secret'))})\n    except OSError:pass\n'''
    return base

class Tests(unittest.TestCase):
    def check(self,source,works):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            path=root/'deploy/ciam-v10/authority/bootstrap.py'
            path.parent.mkdir(parents=True)
            path.write_text(source)
            if works:
                got=m.read_existing_authority_admin(root)
                self.assertIsInstance(got,m.AuthorityBasic)
                self.assertTrue(m._approved_basic_header(got._header))
                self.assertNotIn('private-value',repr(got))
            else:
                with self.assertRaises(m.Block):
                    m.read_existing_authority_admin(root)

    def test_namespaced_basic_no_module_basic(self):
        self.check(build_source(),True)
    def test_module_basic_also_supported(self):
        self.check(build_source(auth_mode='module'),True)
    def test_foreign_tenant_rejected(self):
        self.check(build_source(tenant='brisa.identity.test'),False)
    def test_unqualified_rejected(self):
        self.check(build_source(unqualified=True),False)
    def test_non_get_rejected(self):
        self.check(build_source(wrong_method=True),False)
    def test_wrong_origin_rejected(self):
        self.check(build_source(wrong_origin=True),False)
    def test_conflicting_candidates_rejected(self):
        self.check(build_source(two=True),False)
    def test_absent_authorization_rejected(self):
        src=build_source().replace("headers={'Authorization':resources.basic((ts['aurora']['username'],ts['aurora']['password']))}","headers={'X-Other':'value'}")
        self.check(src,False)

if __name__=='__main__':unittest.main()
