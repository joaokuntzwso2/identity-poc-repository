#!/usr/bin/env python3
"""Offline safety tests for the one-role-at-a-time SCIM v2 approval removal."""
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / 'admin_approval_remediation.py'
spec = importlib.util.spec_from_file_location('ciam_admin_remediation', FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MockResources:
    BASE = 'https://localhost:9444'
    HOST = 'localhost'
    PORT = 9444
    OWNER = 'labtenantadmin'
    DOMAINS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}
    ID = re.compile(r'^[A-Za-z0-9_-]{5,256}={0,2}$')
    def __init__(self, root): self.ROOT = root
    def basic(self, name, pwd): return 'Basic mocked'
    def private_read(self, path, required=True):
        if not path.exists(): return None
        return json.loads(path.read_text())
    def atomic_save(self, path, value):
        if path.is_symlink(): raise m.Refuse('PRIVATE_SYMLINK')
        tmp = path.with_suffix('.part')
        tmp.write_text(json.dumps(value))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

class FakeStage:
    DOMAINS = MockResources.DOMAINS
    def __init__(self, root): self.resources = MockResources(root)
    def path(self, brand, suffix): return '/t/' + self.DOMAINS[brand] + suffix
    def exact_role(self, client, brand, auth, version, name):
        return {'id': client.roles[brand][name]['id']}
    def list_items(self, body, *names):
        for n in names:
            if isinstance(body.get(n), list): return body[n]
        if body.get('totalResults') == 0: return []
        raise m.Refuse('UNRECOGNIZED_COLLECTION')

class FakeClient:
    def __init__(self, with_etag=False):
        self.roles = {}
        self.groups = {'aurora': [], 'brisa': []}
        self.patch_count = 0
        self.fail_patch = False
        self.with_etag = with_etag
        for brand in ('aurora','brisa'):
            self.roles[brand] = {}
            for channel in ('app','web'):
                name = 'CIAM Business Administrator ' + channel.upper()
                self.roles[brand][name] = {'id': 'role-' + brand + '-' + channel,
                                             'displayName': name,
                                             'audience': {'type': 'application', 'value': 'client-' + brand + '-' + channel},
                                             'permissions': [{'value': v} for v in sorted(m.BEFORE)],
                                             'users': [{'value': 'admin-' + brand}],
                                             # WSO2 omitted role-side groups in live reports.
                                             }
    def call(self, method, path, *, auth, data=None, form=None):
        status, obj, etag = self.request(method,path,auth=auth,data=data)
        return status, obj, etag
    def request(self, method, path, *, auth, data=None, etag=None):
        brand = 'aurora' if path.startswith('/t/aurora.') else 'brisa'
        if '/scim2/Groups' in path:
            if path.rstrip('/').split('?')[0].endswith('/Groups'):
                return 200, {'totalResults': len(self.groups[brand]), 'Resources': [
                    {'id': obj['id']} for obj in self.groups[brand]]}, None
            gid = path.split('/Groups/')[1].split('?')[0]
            return 200, next(g for g in self.groups[brand] if g['id'] == gid), None
        if '/scim2/v2/Roles/' in path:
            rid = path.split('/Roles/')[1].split('?')[0]
            node = next(n for n in self.roles[brand].values() if n['id'] == rid)
            if method == 'GET':
                return 200, dict(node), '"version-1"' if self.with_etag else None
            if method == 'PATCH':
                self.patch_count += 1
                if self.fail_patch: raise OSError('connection reset after request')
                if data != m.patch_payload(): raise AssertionError('BAD_PATCH')
                node['permissions'] = [{'value': v} for v in sorted(m.AFTER)]
                return 200, dict(node), None
        raise AssertionError('UNKNOWN_REQUEST ' + method + ' ' + path)

def fixture(root):
    stage = FakeStage(root)
    client = FakeClient()
    ts = {'tenants': {b: {'tenantId': 'tenant-' + b, 'owner': {'password': 'mock'}} for b in ('aurora','brisa')}}
    oidc = {'tenants': {b: {'clients': {c: {'id': 'client-' + b + '-' + c, 'state': 'verified'}
                                               for c in ('app','web')}} for b in ('aurora','brisa')}}
    identities = {'tenants': {b: {'users': {'admin_' + b: {'id': 'admin-' + b, 'state': 'verified'}}}
                              for b in ('aurora','brisa')}}
    seed = {'people': [{'key': 'admin_' + b, 'brands': [b], 'type': 'administrator'}
                       for b in ('aurora','brisa')]}
    return stage, client, (ts, oidc, {}, identities, seed, 'v2')

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'private').mkdir(mode=0o700)
        self.stage, self.client, self.ctx = fixture(self.root)
        self.env = patch.dict(os.environ, {'WSO2_CIAM_CASES_API_IDENTIFIER': m.PINNED})
        self.env.start(); self.addCleanup(self.env.stop)

    def plan(self):
        return m.execute(['plan'],stage=self.stage,client=self.client,ctx=self.ctx)

    def apply(self, key, plan_hash=None, extra=None):
        plan_hash = plan_hash or self.plan()['planSha256']
        args = ['apply','--role',key,'--plan-sha256',plan_hash,'--confirm',m.CONFIRM]
        if extra is None: extra=['--allow-no-etag']
        return m.execute(args + extra,stage=self.stage,client=self.client,ctx=self.ctx)

    def test_patch_payload_is_narrow(self):
        self.assertEqual(m.patch_payload()['Operations'],
                         [{'op':'remove','path':'permissions[value eq "ciam:cases:approve"]'}])
        self.assertNotIn('users',json.dumps(m.patch_payload()))

    def test_transport_restricts_operations_and_paths(self):
        fn = m.Transport.allowed
        base = '/t/aurora.identity.test/scim2/v2/Roles/a-valid-id'
        self.assertTrue(fn('PATCH',base,m.patch_payload()))
        self.assertFalse(fn('PUT',base,m.patch_payload()))
        self.assertFalse(fn('DELETE',base,None))
        self.assertFalse(fn('PATCH',base.replace('/Roles/','/Users/'),m.patch_payload()))
        self.assertFalse(fn('PATCH',base,{'Operations':[{'op':'remove','path':'users'}]}))
        self.assertFalse(fn('PATCH','/t/other.example/scim2/v2/Roles/valid-id',m.patch_payload()))

    def test_read_only_plan_four_roles(self):
        p = self.plan()
        self.assertEqual(p['pending'], list(m.ROLE_KEYS))
        self.assertEqual(self.client.patch_count, 0)
        self.assertEqual(p['conditionalUpdateEnforcement'], 'NOT_INDEPENDENTLY_VERIFIED')
        self.assertFalse((self.root/'private'/m.JOURNAL_NAME).exists())

    def test_wrong_audience_refuses(self):
        self.client.roles['aurora']['CIAM Business Administrator WEB']['audience']['value'] = 'wrong-client'
        with self.assertRaisesRegex(m.Refuse,'AUDIENCE_DRIFT'): self.plan()

    def test_unexpected_extra_permission_refuses(self):
        self.client.roles['aurora']['CIAM Business Administrator WEB']['permissions'].append({'value':'other:write'})
        with self.assertRaisesRegex(m.Refuse,'SCOPE_DRIFT'): self.plan()

    def test_unexpected_admin_direct_user_refuses(self):
        self.client.roles['aurora']['CIAM Business Administrator WEB']['users'].append({'value':'unknown-person'})
        with self.assertRaisesRegex(m.Refuse,'MEMBERSHIP_DRIFT'): self.plan()

    def test_role_group_link_refuses(self):
        self.client.groups['aurora'] = [{'id':'a-group-id','roles':[{'value':'role-aurora-web'}]}]
        with self.assertRaisesRegex(m.Refuse,'GROUP_LINK_PRESENT'): self.plan()

    def test_group_side_omission_refuses(self):
        self.client.groups['aurora'] = [{'id':'a-group-id'}]
        with self.assertRaisesRegex(m.Refuse,'FIELD_NOT_ATTESTED'): self.plan()

    def test_malformed_role_group_field_refuses(self):
        self.client.roles['aurora']['CIAM Business Administrator WEB']['groups'] = 'not a list'
        with self.assertRaisesRegex(m.Refuse,'BAD_GROUPS'): self.plan()

    def test_invalid_confirmation_or_digest_refuses_without_write(self):
        with self.assertRaises(m.Refuse):
            m.execute(['apply','--role','aurora:web','--plan-sha256','0'*64,'--confirm',m.CONFIRM],
                      stage=self.stage,client=self.client,ctx=self.ctx)
        self.assertEqual(self.client.patch_count,0)
        self.assertFalse((self.root/'private'/m.JOURNAL_NAME).exists())

    def test_no_etag_requires_extra_explicit_ack(self):
        p = self.plan()
        with self.assertRaisesRegex(m.Refuse, 'NO_ETAG_REQUIRES'):
            self.apply('aurora:web',p['planSha256'],extra=[])
        self.assertEqual(self.client.patch_count,0)

    def test_one_scope_patch_and_journal(self):
        p = self.plan()
        out = self.apply('aurora:web',p['planSha256'])
        self.assertEqual(out['remoteWrites'],1)
        self.assertEqual(self.client.patch_count,1)
        self.assertEqual(m.refs(self.client.roles['aurora']['CIAM Business Administrator WEB'],'permissions',mandatory=True),m.AFTER)
        self.assertEqual(m.read_journal(self.stage,self.ctx)['roles']['aurora:web']['state'],'verified')
        self.assertEqual(len(self.plan()['pending']),3)

    def test_old_plan_hash_cannot_be_replayed(self):
        p = self.plan()
        self.apply('aurora:web',p['planSha256'])
        with self.assertRaisesRegex(m.Refuse,'PLAN_HASH_MISMATCH'):
            self.apply('brisa:web',p['planSha256'])
        self.assertEqual(self.client.patch_count,1)

    def test_write_ahead_and_uncertain_do_not_retry(self):
        p = self.plan()
        self.client.fail_patch = True
        with self.assertRaisesRegex(m.Refuse,'UNCERTAIN_STOP_NO_RETRY'):
            self.apply('aurora:web',p['planSha256'])
        self.assertEqual(self.client.patch_count,1)
        self.assertEqual(m.read_journal(self.stage,self.ctx)['roles']['aurora:web']['state'],'patch-started')
        self.client.fail_patch = False
        with self.assertRaisesRegex(m.Refuse,'UNCERTAIN_PREVIOUS_PATCH'):
            self.plan()
        self.assertEqual(self.client.patch_count,1)

    def test_all_four_can_be_verified_sequentially(self):
        for key in m.ROLE_KEYS:
            self.apply(key)
        p = m.execute(['verify'],stage=self.stage,client=self.client,ctx=self.ctx)
        self.assertEqual(p['status'],'ALL_FOUR_ROLES_READBACK_VERIFIED')
        self.assertEqual(p['verified'],list(m.ROLE_KEYS))
        self.assertEqual(self.client.patch_count,4)
        self.assertTrue(all(r['permissions'] == sorted(m.AFTER) for r in p['roles'].values()))

    def test_verify_requires_all_four(self):
        with self.assertRaisesRegex(m.Refuse,'VERIFICATION_REQUIRES'):
            m.execute(['verify'],stage=self.stage,client=self.client,ctx=self.ctx)

    def test_unjournaled_already_removed_refuses_adoption(self):
        self.client.roles['aurora']['CIAM Business Administrator WEB']['permissions'] = [{'value':v} for v in m.AFTER]
        with self.assertRaisesRegex(m.Refuse,'UNJOURNALED_ROLE_CHANGED'):
            self.plan()

    def test_pinned_urn_is_required(self):
        with patch.dict(os.environ,{'WSO2_CIAM_CASES_API_IDENTIFIER':'https://wrong.example'}):
            with self.assertRaisesRegex(m.Refuse,'PINNED_CASES_API_IDENTIFIER'):
                self.plan()

if __name__ == '__main__':
    unittest.main()
