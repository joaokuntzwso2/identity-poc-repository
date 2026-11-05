import unittest
from test_live_script_contract import staged, live, seq

class ComposerTest(unittest.TestCase):
    def test_aurora_preserves_acr_path(self):
        new=staged('aurora.identity.test','aurora-web')
        self.assertIn('context.selectedAcr = MAGALU_APPROVAL_ACR;',new['script'])
        self.assertIn('magaluRiskCheck(',new['script'])
        self.assertEqual(len(new['steps']),2)
    def test_brisa_preserves_current_totp_without_recreating_app(self):
        new=staged('brisa.identity.test','brisa-web')
        self.assertEqual(len(new['steps']),2)
        self.assertEqual(new['steps'][1]['options'][0]['authenticator'],'totp')
    def test_unknown_script_fails_closed(self):
        tenant='aurora.identity.test';alias='aurora-app'
        a={'id':'a'*36,'name':seq.DISPLAY_NAMES[(tenant,alias)],
           'authenticationSequence':staged(tenant,alias)}
        with self.assertRaises(seq.UnsafeSequence):seq.compose(tenant,alias,a)
    def test_alternate_tenant_fails_closed(self):
        tenant='brisa.identity.test';alias='brisa-app'
        a={'id':'a'*36,'name':seq.DISPLAY_NAMES[(tenant,alias)],
           'authenticationSequence':{'type':'USER_DEFINED','script':live(tenant),'steps':[]}}
        with self.assertRaises(seq.UnsafeSequence):seq.compose('carbon.super',alias,a)
    def test_drift_fails_closed(self):
        tenant='brisa.identity.test';alias='brisa-web'
        a={'id':'a'*36,'name':seq.DISPLAY_NAMES[(tenant,alias)],
           'authenticationSequence':staged(tenant,alias)}
        a['authenticationSequence']['steps'].append({'id':3})
        with self.assertRaises(seq.UnsafeSequence):seq.compose(tenant,alias,a)

if __name__=='__main__':unittest.main()
