"""Offline P2 v10 authority Basic header bridge tests. No network/WSO2 writes."""
import base64
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE=Path(__file__).resolve().parents[2]/'scripts/p2/m2m_bootstrap.py'
spec=importlib.util.spec_from_file_location('p2_bridge_test',MODULE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class BridgeTests(unittest.TestCase):
    def test_approved_only_aurora_qualified(self):
        def h(user, pw='private-value'):
            return 'Basic '+base64.b64encode((user+':'+pw).encode()).decode()
        self.assertTrue(m._approved_basic_header(h('owner@aurora.identity.test')))
        for bad in ('owner','admin@brisa.identity.test','admin@carbon.super','',
                    '@aurora.identity.test','bad@brisa.identity.test@aurora.identity.test','owner@aurora.identity.test\n'):
            self.assertFalse(m._approved_basic_header(h(bad)),bad)
        self.assertFalse(m._approved_basic_header('Basic non_base64'))
        self.assertFalse(m._approved_basic_header('Bearer anything'))

    def test_source_basic_is_redacted(self):
        obj=m.AuthorityBasic('Basic sensitive-example')
        self.assertNotIn('sensitive-example',str(obj))
        self.assertNotIn('sensitive-example',repr(obj))

    def fixture(self, username='aurora-owner', domain='aurora.identity.test',
                duplicate=False, include_bad=False):
        d=tempfile.TemporaryDirectory()
        repo=Path(d.name)
        folder=repo/'deploy/ciam-v10/authority'
        folder.mkdir(parents=True)
        source='''
import base64
TENANT='aurora.identity.test'
def private_context():
    return ({'tenants':{'aurora':{'username':%r,'password':'private-secret-123'}}},{},{})
def tenant_auth(ts,brand):
    t=ts['tenants'][brand]
    return t['username']+'@'+%r,t['password']
def basic(pair):
    return 'Basic '+base64.b64encode((pair[0]+':'+pair[1]).encode()).decode()
def diagnostic(client,ts,rs,oidc):
    try:client.call('GET','/t/aurora.identity.test/api/server/v1/api-resources',headers={'Authorization':basic(tenant_auth(ts,'aurora'))})
    except OSError: pass
'''%(username,domain)
        if duplicate:
            source+='''
    try:client.call('GET','/t/aurora.identity.test/api/server/v1/api-resources',headers={'Authorization':basic(('another-owner@aurora.identity.test','different-secret'))})
    except OSError: pass
'''
        if include_bad:
            source+='''
    try:client.call('GET','/t/brisa.identity.test/api/server/v1/api-resources',headers={'Authorization':basic(('brisa-owner@brisa.identity.test','other-secret'))})
    except OSError: pass
'''
        (folder/'bootstrap.py').write_text(source)
        return d,repo

    def test_captures_only_real_v10_helper_result(self):
        d,repo=self.fixture(include_bad=True)
        with d:
            got=m.read_existing_authority_admin(repo)
            self.assertIsInstance(got,m.AuthorityBasic)
            self.assertTrue(m._approved_basic_header(got._header))
            self.assertNotIn('private-secret-123',repr(got))

    def test_foreign_basic_denied_without_network(self):
        d,repo=self.fixture(domain='brisa.identity.test')
        with d:
            with self.assertRaisesRegex(m.Block,'NOT_UNAMBIGUOUS'):
                m.read_existing_authority_admin(repo)

    def test_unqualified_basic_denied(self):
        d,repo=self.fixture(domain='')
        with d:
            with self.assertRaisesRegex(m.Block,'NOT_UNAMBIGUOUS'):
                m.read_existing_authority_admin(repo)

    def test_multiple_aurora_candidates_denied(self):
        d,repo=self.fixture(duplicate=True)
        with d:
            with self.assertRaisesRegex(m.Block,'NOT_UNAMBIGUOUS'):
                m.read_existing_authority_admin(repo)

    def test_capture_ignores_nonGET(self):
        d,repo=self.fixture()
        with d:
            p=repo/'deploy/ciam-v10/authority/bootstrap.py'
            s=p.read_text().replace("client.call('GET'","client.call('POST'")
            p.write_text(s)
            with self.assertRaisesRegex(m.Block,'NOT_UNAMBIGUOUS'):
                m.read_existing_authority_admin(repo)

    def test_basic_extraction_not_from_unmarked_secret_fields(self):
        encoded='Basic '+base64.b64encode(b'admin@aurora.identity.test:password').decode()
        self.assertEqual(m._extract_basic({'secret':encoded}),[])
        self.assertEqual(m._extract_basic({'Authorization':encoded}),[encoded])

if __name__=='__main__': unittest.main()
