import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

script=Path(__file__).parent/'ciam_p010_seller_live_gate.py'
spec=importlib.util.spec_from_file_location('seller_gate',script)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def verify():
    return {'status':'ALL_TWO_AURORA_POLICY_READBACK_VERIFIED','pending':[],
      'brisaWrites':0,'approvalAcr':m.ACR,'liveTotpChallengeAttested':False,
      'aurora':{'web':{'state':'after'},'app':{'state':'after'}},
      'brisa':{'web':{'state':'before'},'app':{'state':'before'}}}

def cap(): return {'tenants':{'aurora':{'totpEnabled':True}}}

def four():
    return {'fourClientsReadyForInteractiveLogin':True,
       'clients':{k:{name:True for name in ('runtimeConfigured','runtimeDiscoveryVerified',
         'wso2RegistrationVerified','callbackVerified','codeAndPkceS256Verified',
         'applicationRoleAudienceVerified','readyForInteractiveLogin')} for k in m.CLIENTS}}

class GateTests(unittest.TestCase):
    def test_valid_policy_registration_and_capability_is_not_mfa_proof(self):
        obj=m.gate(verify(),cap(),four())
        self.assertEqual(obj['status'],'POLICY_REGISTRATION_TOTP_CAPABILITY_READBACK_VERIFIED')
        self.assertFalse(obj['signedAmrAcrAuthTimeVerified'])
        self.assertEqual(obj['businessWrites'],0)

    def test_aurora_must_be_exact_verified_after(self):
        x=verify();x['aurora']['app']['state']='before'
        with self.assertRaisesRegex(m.Stop,'AURORA_POLICY_NOT_APPLIED_app'):m.gate(x,cap(),four())
        x=verify();x['pending']=['aurora:app']
        with self.assertRaisesRegex(m.Stop,'AURORA_TWO_POLICY'):m.gate(x,cap(),four())

    def test_brisa_must_remain_unchanged(self):
        x=verify();x['brisa']['web']['state']='after'
        with self.assertRaisesRegex(m.Stop,'BRISA_AUTH_POLICY_DRIFT'):m.gate(x,cap(),four())

    def test_no_capability_refuses(self):
        x=cap();x['tenants']['aurora']['totpEnabled']=False
        with self.assertRaisesRegex(m.Stop,'AURORA_TOTP_AUTHENTICATOR'):m.gate(verify(),x,four())

    def test_missing_or_duplicate_client_refuses(self):
        x=four(); del x['clients']['brisa-app']
        with self.assertRaisesRegex(m.Stop,'FOUR_CLIENTS_SET'):m.gate(verify(),cap(),x)
        x=four();x['clients']['aurora-web']['callbackVerified']=False
        with self.assertRaisesRegex(m.Stop,'OIDC_CLIENT_NOT_READY'):m.gate(verify(),cap(),x)

    def test_actual_totp_claim_never_inferred_from_readback(self):
        x=verify();x['liveTotpChallengeAttested']=True
        with self.assertRaisesRegex(m.Stop,'APPROVAL_ASSURANCE_UNEXPECTED_OR_UNTRUSTED'):m.gate(x,cap(),four())

    def test_restart_requires_exact_confirmation_before_any_subprocess(self):
        with patch.object(m,'run_json') as r:
            with self.assertRaisesRegex(m.Stop,'SCOPED_BFF_RESTART_CONFIRMATION'):
                m.restart_bff(Path('/ignored'),{},{} ,'')
            r.assert_not_called()

    def test_restart_requires_known_process(self):
        with patch.object(m,'run_json',return_value={'decision':'REFUSE_NO_CHANGES'}) as r:
            with self.assertRaisesRegex(m.Stop,'V10_BFF_PROCESS_NOT_EXACTLY_VERIFIED'):
                m.restart_bff(Path('/ignored'),{}, {},m.CONFIRM)
            self.assertEqual(r.call_count,1)

    def test_restart_provides_only_declared_assurance_and_keeps_other_environment(self):
        original={'KEEP_OTHER_SOURCE_SETTING':'yes','WSO2_TOTP_STEPUP_AMR':'previous'}
        env=m.restart_env(original)
        self.assertEqual(env['KEEP_OTHER_SOURCE_SETTING'],'yes')
        self.assertEqual(env['WSO2_TOTP_STEPUP_AMR'],'totp')
        self.assertEqual(env['WSO2_TOTP_STEPUP_ACR'],m.ACR)
        self.assertEqual(env['WSO2_CASES_API_AUDIENCE'],m.AUD)
        self.assertNotIn('WSO2_TOTP_STEPUP_ACR',original)

    def test_restart_process_failure_never_retry(self):
        plan={'decision':'MAY_RESTART_WITH_EXPLICIT_CONFIRMATION',
              'port4400Listening':True,'exactProcessOwnershipVerified':True}
        with patch.object(m,'run_json',side_effect=[plan,m.Stop('RESTART_ERR')]) as r:
            with self.assertRaisesRegex(m.Stop,'RESTART_ERR'):
                m.restart_bff(Path('/ignored'),{}, {},m.CONFIRM)
            self.assertEqual(r.call_count,2)

    def test_interactive_approval_required_before_browser_side_effect(self):
        with patch.object(m,'preflight') as r:
            with self.assertRaisesRegex(m.Stop,'EXPLICIT_PERSISTENT_CASE_WRITE'):
                m.run_live(Path('/ignored'),{},'')
            r.assert_not_called()

    def test_repository_guard_refuses_symlinks_and_missing_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'.git').mkdir();(root/'wso2-lab.sh').write_text('')
            for p in m.REQUIRED:
                f=root/p;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('')
            self.assertEqual(m.validate_repo(root),root)
            f=root/m.REQUIRED[0];f.unlink();f.symlink_to(root/m.REQUIRED[1])
            with self.assertRaisesRegex(m.Stop,'MISSING_OR_SYMLINK'):m.validate_repo(root)

    def test_never_prints_raw_readback_failure_or_stdout(self):
        class Fake:
            returncode=1
            stdout='VERY_SECRET_SHOULD_NEVER_APPEAR'
            stderr='VERY_SECRET_SHOULD_NEVER_APPEAR'
        with patch.object(m.subprocess,'run',return_value=Fake()):
            with self.assertRaisesRegex(m.Stop,'PRECONDITION_COMMAND_FAILED') as c:
                m.run_json(['python3','secret-script.py'],Path('/ignored'))
            self.assertNotIn('VERY_SECRET',str(c.exception))

if __name__=='__main__':unittest.main(verbosity=2)
