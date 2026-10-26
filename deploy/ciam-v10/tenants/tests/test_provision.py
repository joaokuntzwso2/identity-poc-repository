import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('provision', Path(__file__).parents[1] / 'provision.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class FakeClient:
    def __init__(self):
        self.items = {}
        self.writes = 0
        self.post_status = 201
    def call(self, method, path, payload=None, basic_override=None):
        if path.startswith('/t/'):
            return 403, {}
        if path == '/api/server/v1/tenants?limit=100&offset=0':
            return 200, {'totalResults': len(self.items), 'count': len(self.items), 'tenants': [
                {'domain': domain, 'id': x['tid']} for domain,x in self.items.items()]}
        if method == 'POST':
            assert path == '/api/server/v1/tenants'
            self.writes += 1
            if self.post_status != 201:
                return self.post_status, {}
            domain = payload['domain']
            self.items[domain] = {'tid': 'tenant-'+domain.split('.')[0], 'oid': 'owner-'+domain.split('.')[0], 'owner': payload['owners'][0]}
            return 201, {'id': self.items[domain]['tid']}
        if path.startswith('/api/server/v1/tenants/domain/'):
            domain = path.split('/')[-1]
            x = self.items.get(domain)
            if not x: return 404, {}
            return 200, {'id': x['tid'], 'domain': domain, 'lifecycleStatus': {'activated': True}}
        if path.endswith('/owners'):
            tid = path.split('/')[5]
            v = next((v for v in self.items.values() if v['tid'] == tid), None)
            return (200, [{'id': v['oid'], 'username': 'labtenantadmin'}]) if v else (404, {})
        if '/owners/' in path:
            parts = path.split('/')
            tid, oid = parts[5], parts[7]
            v = next((v for v in self.items.values() if v['tid'] == tid and v['oid'] == oid), None)
            return (200, {'id': oid, **{k: v['owner'][k] for k in ('username','firstname','lastname','email')}}) if v else (404, {})
        raise AssertionError((method,path,payload))

class V10TenantTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'bootstrap.private.json'
        self.client = FakeClient()
        self.patch = patch.dict(os.environ, {'WSO2_CIAM_V10_CONFIRM':'CREATE_TWO_NEW_ROOT_TENANTS'})
        self.patch.start();self.addCleanup(self.patch.stop)

    def test_plan_writes_nothing(self):
        result=p.run(self.client,self.state,'plan')
        self.assertEqual(result['writes'],0)
        self.assertFalse(self.state.exists())

    def test_apply_two_and_idempotent_rerun(self):
        result=p.run(self.client,self.state,'apply')
        self.assertEqual(result['tenants']['aurora']['status'],'readback-verified')
        self.assertEqual(self.client.writes,2)
        self.assertEqual(self.state.stat().st_mode & 0o777,0o600)
        private=json.loads(self.state.read_text())
        self.assertGreaterEqual(len(private['tenants']['brisa']['owner']['password']),28)
        self.assertNotIn(private['tenants']['brisa']['owner']['password'],json.dumps(result))
        again=p.run(self.client,self.state,'apply')
        self.assertEqual(self.client.writes,2)
        self.assertEqual(again['ownerLogin'],'NOT_BROWSER_VERIFIED')
        self.assertEqual(again['tenantApiAuthorization']['aurora']['tenantLocalOwnerApplicationReadHTTP'],403)

    def test_partial_response_is_not_retried(self):
        self.client.post_status=206
        with self.assertRaisesRegex(p.Refuse,'DO_NOT_RETRY'):
            p.run(self.client,self.state,'apply')
        self.assertEqual(self.client.writes,1)
        with self.assertRaisesRegex(p.Refuse,'UNRESOLVED_TENANT_CREATION'):
            p.run(self.client,self.state,'apply')
        self.assertEqual(self.client.writes,1)

    def test_unowned_domain_refused_before_write(self):
        self.client.items['aurora.identity.test']={'tid':'tenant-aurora','oid':'owner-aurora','owner':p.fresh_owner('aurora')}
        with self.assertRaisesRegex(p.Refuse,'UNJOURNALED'):
            p.run(self.client,self.state,'apply')
        self.assertEqual(self.client.writes,0)

    def test_requires_write_confirmation(self):
        with patch.dict(os.environ, {'WSO2_CIAM_V10_CONFIRM':'NO'}, clear=True):
            with self.assertRaisesRegex(p.Refuse,'EXPLICIT'):
                p.run(self.client,self.state,'apply')
        self.assertFalse(self.state.exists())

    def test_reject_journal_symlink(self):
        target=Path(self.tmp.name)/'target'
        target.write_text('{}')
        self.state.symlink_to(target)
        with self.assertRaisesRegex(p.Refuse,'PRIVATE_FILE_NOT_REGULAR'):
            p.run(self.client,self.state,'plan')

if __name__=='__main__': unittest.main()
