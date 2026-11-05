"""Offline regression for journal-owned OIDC app discovery; no live WSO2."""
import json
import pathlib
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bootstrap as b
from application_sequences import UnsafeSequence, compose

NAMES = {
    ('aurora.identity.test', 'aurora-web'): 'Identity Lab v10 Aurora Web',
    ('aurora.identity.test', 'aurora-app'): 'Identity Lab v10 Aurora Mobile Browser Preview',
    ('brisa.identity.test', 'brisa-web'): 'Identity Lab v10 Brisa Web',
    ('brisa.identity.test', 'brisa-app'): 'Identity Lab v10 Brisa Mobile Browser Preview',
}

class JournalIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = pathlib.Path(self.tmp.name)
        (self.home / 'private').mkdir(mode=0o700)
        self.ids = {}
        self.records = {'tenants': {}}
        for tenant in b.BRANDS:
            brand = tenant.split('.')[0]
            clients = {}
            for channel in ('web','app'):
                alias = brand + '-' + channel
                app_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, tenant + channel))
                self.ids[(tenant,alias)] = app_id
                clients[channel] = dict(name=NAMES[(tenant,alias)], id=app_id,
                                        clientId='client-'+brand+'-'+channel,
                                        domain=tenant, channel=channel, state='CREATED')
            self.records['tenants'][brand] = {'domain': tenant, 'clients': clients}
        self.write(self.records)

    def write(self, data):
        f = self.home / 'private/bootstrap-oidc-v10.private.json'
        f.write_text(json.dumps(data))
        f.chmod(0o600)

    def request(self, tenant, path, method='GET', body=None):
        self.assertEqual(method,'GET'); self.assertIsNone(body)
        self.assertIn(tenant, b.BRANDS)
        rid = path.split('/api/server/v1/applications/',1)[-1].split('/')[0]
        for (t,alias),aid in self.ids.items():
            if t != tenant or rid != aid:
                continue
            brand,channel = alias.split('-')
            if path.endswith('/inbound-protocols/oidc'):
                return {'clientId': 'client-'+brand+'-'+channel}
            return {'id':rid, 'name':NAMES[(t,alias)], 'authenticationSequence':{'steps':[]}}
        raise AssertionError('untrusted application ID requested')

    def test_exact_four_verified_id_readbacks_and_no_name_search(self):
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request',side_effect=self.request) as request:
            apps=b.apps()
        self.assertEqual(set(apps),set(self.ids))
        self.assertEqual(request.call_count,8)
        self.assertTrue(all('?filter' not in item.args[1] and 'limit=' not in item.args[1] for item in request.call_args_list))

    def test_new_real_display_names_allowed_by_composer(self):
        from test_live_script_contract import live
        for (tenant,alias),name in NAMES.items():
            app={'id':self.ids[(tenant,alias)], 'name':name,
                 'authenticationSequence':{'type':'USER_DEFINED',
                    'steps':[{'id':1,'options':[{'idp':'LOCAL','authenticator':'basic'}]},
                             {'id':2,'options':[{'idp':'LOCAL','authenticator':'totp'}]}],
                    'script':live(tenant)}}
            result=compose(tenant,alias,app,'unused')
            self.assertEqual(len(result['steps']),2)
            self.assertIn('MAGALU_RISK_GATE_V2', result['script'])
            app['name']='attacker-edited'
            with self.assertRaises(UnsafeSequence):
                compose(tenant,alias,app,'')

    def test_changed_journal_name_denied_without_remote_request(self):
        self.records['tenants']['aurora']['clients']['web']['name'] = 'Different App'
        self.write(self.records)
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request') as req:
            with self.assertRaisesRegex(b.GuardError,'IDENTITY_DRIFT'):
                b.apps()
            req.assert_not_called()

    def test_changed_journal_tenant_denied(self):
        self.records['tenants']['brisa']['clients']['web']['domain'] = 'aurora.identity.test'
        self.write(self.records)
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request') as req:
            with self.assertRaisesRegex(b.GuardError,'IDENTITY_DRIFT'):
                b.apps()
            req.assert_not_called()

    def test_bad_uuid_denied(self):
        self.records['tenants']['aurora']['clients']['app']['id'] = '../foreign'
        self.write(self.records)
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request') as req:
            with self.assertRaisesRegex(b.GuardError,'ID_INVALID'):
                b.apps()
            req.assert_not_called()

    def test_untrusted_live_name_denied(self):
        def fake(tenant,path,method='GET',body=None):
            return {'id':self.ids[(tenant,'aurora-web')], 'name':'Not Aurora',
                    'authenticationSequence':{'steps':[]}}
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request',side_effect=fake):
            with self.assertRaisesRegex(b.GuardError,'IDENTITY_MISMATCH'):
                b.apps()

    def test_untrusted_oidc_client_id_denied(self):
        def fake(tenant,path,method='GET',body=None):
            if path.endswith('/inbound-protocols/oidc'):
                return {'clientId':'some-other-client'}
            aid=path.rsplit('/',1)[-1]
            return {'id':aid,'name':next(n for (t,a),n in NAMES.items() if t==tenant and self.ids[(t,a)]==aid),
                    'authenticationSequence':{'steps':[]}}
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request',side_effect=fake):
            with self.assertRaisesRegex(b.GuardError,'CLIENT_ID_MISMATCH'):
                b.apps()

    def test_console_readback_identifies_actual_display_name(self):
        item = {'name':'Identity Lab v10 Aurora Web',
                'authenticationSequence':{'steps':[]}}
        marks = b.verify_console({('aurora.identity.test','aurora-web'):item})
        self.assertEqual(marks[0]['display_name'], 'Identity Lab v10 Aurora Web')
        self.assertEqual(marks[0]['console'], 'Applications > Identity Lab v10 Aurora Web > Login Flow')

    def test_missing_private_journal_denied(self):
        (self.home/'private/bootstrap-oidc-v10.private.json').unlink()
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request') as req:
            with self.assertRaisesRegex(b.GuardError,'JOURNAL_UNAVAILABLE'):
                b.apps()
            req.assert_not_called()

    def test_insecure_private_journal_denied(self):
        (self.home/'private/bootstrap-oidc-v10.private.json').chmod(0o644)
        with patch.object(b,'home',return_value=self.home), patch.object(b,'request') as req:
            with self.assertRaisesRegex(b.GuardError,'JOURNAL_UNSAFE'):
                b.apps()
            req.assert_not_called()

if __name__ == '__main__':
    unittest.main()
