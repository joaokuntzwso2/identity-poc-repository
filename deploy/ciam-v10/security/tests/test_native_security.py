"""OFFLINE_TEST only. Never interpret a fake transport as live WSO2 evidence."""
import json
from pathlib import Path
import sys
import unittest
import stat
import tempfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import cli as native
import recaptcha

class TestPolicy(unittest.TestCase):
    def test_tenant_policy_isolation(self):
        policies=native.policies()
        self.assertEqual(set(policies),{'aurora','brisa'})
        self.assertNotEqual(policies['aurora']['loginAttempts']['maximumFailures'],
                            policies['brisa']['loginAttempts']['maximumFailures'])
        self.assertEqual(policies['aurora']['domain'],'aurora.identity.test')
        self.assertEqual(policies['brisa']['domain'],'brisa.identity.test')

    def test_stepup_below_lock_and_policy_shapes(self):
        for p in native.policies().values():
            self.assertTrue(p['loginAttempts']['stepUpAfterFailures'] < p['loginAttempts']['maximumFailures'])
            self.assertFalse(p['recaptcha']['always'])
            self.assertEqual(len(native.spec_values(p)),7)

    def test_script_is_brand_specific(self):
        policy=native.policies()
        a=native.script_for('aurora', policy['aurora'])
        b=native.script_for('brisa', policy['brisa'])
        self.assertNotEqual(a,b)
        self.assertIn('var MAGALU_APPROVAL_ENABLED = true;',a)
        self.assertIn('var MAGALU_APPROVAL_ENABLED = false;',b)
        self.assertIn('failedLoginAttemptsBeforeSuccess',a)
        self.assertIn('context.selectedAcr = MAGALU_APPROVAL_ACR;',a)
        self.assertNotIn('__MAGALU_', a)

    def test_default_basic_auth_sequence(self):
        sequence={'type':'DEFAULT','steps':[{'id':1,'options':[
            {'idp':'LOCAL','authenticator':'BasicAuthenticator'}]}]}
        want=native.script_for('brisa',native.policies()['brisa'])
        self.assertEqual(native.sequence_kind(sequence,want),'default')
        after=native.desired_seq(sequence,want)
        self.assertEqual(native.sequence_kind(after,want),'desired')
        self.assertTrue(native.totp_step(after))

    def test_reject_rogue_script(self):
        want=native.script_for('aurora',native.policies()['aurora'])
        seq={'type':'USER_DEFINED','steps':[{'id':1,'options':[
            {'idp':'LOCAL','authenticator':'BasicAuthenticator'}]},
            {'id':2,'options':[{'idp':'LOCAL','authenticator':'totp'}]}],
            'script':'some unrelated extension'}
        with self.assertRaisesRegex(native.Refused,'UNOWNED_AUTHENTICATION_SCRIPT'):
            native.sequence_kind(seq,want)

    def test_cross_tenant_identifier_rejected(self):
        for v in ('../../carbon.super','../applications','bad?secret=a','evil#fragment'):
            with self.assertRaises(native.Refused):native.safe_id(v)

    def test_initial_plan_contains_no_secrets(self):
        data={b:{'summary':{'policy':{},'apps':{}}} for b in native.DOMAINS}
        policy=native.policies()
        out=native.planned(data,policy,{'configured':False,'restartRequired':True})
        self.assertEqual(len(out['planSha256']),64)
        self.assertNotIn('clientSecret',json.dumps(out))
        self.assertEqual(out['changes'],[])

class TestRecaptcha(unittest.TestCase):
    def setUp(self):
        self.creds={'version':'v3','site_key':'TEST_SITE_KEY_NOT_LIVE','secret_key':'TEST_SECRET_NOT_LIVE','threshold':0.5}

    def test_idempotent_render(self):
        text='[server]\nhostname = "localhost"\n'
        rendered=recaptcha.render(text,self.creds)
        self.assertEqual(recaptcha.render(rendered,self.creds),rendered)
        self.assertTrue(recaptcha.verify_rendered(rendered,self.creds))
        self.assertIn('[recaptcha]',rendered)

    def test_no_silent_unowned_adoption(self):
        with self.assertRaisesRegex(recaptcha.Refused,'UNOWNED_RECAPTCHA'):
            recaptcha.render('[recaptcha]\nenabled=true\n',self.creds)

    def test_v2_v3_render_modes(self):
        v2=dict(self.creds,version='v2')
        self.assertNotIn('threshold =', recaptcha.render('[server]\n',v2))
        self.assertIn('threshold = \"0.5\"', recaptcha.render('[server]\n',self.creds))

    def test_no_environment_mock_credentials(self):
        self.assertNotIn('fake',repr(recaptcha.load_credentials))

class InMemoryGovernanceOnly:
    """Pure unit-test double; it never performs HTTP or configures WSO2."""
    def __init__(self):
        self.values={k:'false' for k in tuple(native.LOCK_KEYS)+tuple(native.BOT_KEYS)}
        self.calls=[]
    def call(self,brand,auth,method,path,data=None,etag=None):
        self.calls.append((brand,method,path))
        if method=='GET':
            if path.endswith('/identity-governance'): return {'categories':[{'id':'account'}]},None
            return {'connectors':[{'id':'actual-connector','properties':[
                {'name':k,'value':v} for k,v in self.values.items()]}]},None
        if method=='PATCH':
            self.values[data['properties'][0]['name']] = data['properties'][0]['value']
            return None,None
        raise AssertionError('test double only supports governance')

class TestGovernanceDiscovery(unittest.TestCase):
    def test_live_response_ids_used_not_hardcoded(self):
        api=InMemoryGovernanceOnly()
        found=native.gather_properties(api,'aurora',{'auth':'Basic offline'})
        self.assertEqual(found['account.lock.handler.lock.on.max.failed.attempts.enable']['connector'],'actual-connector')
        self.assertEqual(found['sso.login.recaptcha.enable']['category'],'account')
        self.assertFalse(any('/t/brisa.' in p for _,_,p in api.calls))

    def test_patch_followed_by_discovery(self):
        api=InMemoryGovernanceOnly()
        op={'brand':'brisa','key':'account.lock.handler.lock.on.max.failed.attempts.enable','want':'true',
            'category':'account','connector':'actual-connector'}
        native.governance_patch(api,{'auth':'Basic offline'},op)
        self.assertEqual(api.values[op['key']],'true')
        self.assertTrue(any(m=='PATCH' for _,m,_ in api.calls))
        self.assertEqual(api.calls[-1][1],'GET')


class TestWriteAheadSafety(unittest.TestCase):
    def temp_private(self, tmp):
        root=Path(tmp)/'v10'; root.mkdir(mode=0o700)
        private=root/'private'; private.mkdir(mode=0o700)
        (root/'compose.identity.yaml').write_text('services: {}\n')
        return root,private

    def test_governance_write_is_durable_and_read_back(self):
        with tempfile.TemporaryDirectory() as td:
            root,private=self.temp_private(td)
            journal_file=private/'magalu-native-security.private.json'
            op={'resource':'governance','brand':'aurora',
                'key':'account.lock.handler.lock.on.max.failed.attempts.enable','before':'false','want':'true',
                'category':'account','connector':'actual-connector'}
            journal={'operations':[{'state':'pending','op':op}]}
            with patch.multiple(native,ROOT=root,PRIVATE=private,JOURNAL=journal_file):
                api=InMemoryGovernanceOnly()
                native.apply_changes(api,{'aurora':{'auth':'Basic offline'}},native.policies(),[op],journal)
                self.assertEqual(journal['operations'][0]['state'],'verified')
                self.assertEqual(stat.S_IMODE(journal_file.stat().st_mode),0o600)
                self.assertEqual(json.loads(journal_file.read_text())['operations'][0]['state'],'verified')
                self.assertEqual(api.values['account.lock.handler.lock.on.max.failed.attempts.enable'],'true')

    def test_uncertain_remote_write_is_not_retried(self):
        with tempfile.TemporaryDirectory() as td:
            root,private=self.temp_private(td)
            journal_file=private/'magalu-native-security.private.json'
            op={'resource':'governance','brand':'brisa',
                'key':'account.lock.handler.lock.on.max.failed.attempts.enable','before':'false','want':'true',
                'category':'account','connector':'actual-connector'}
            journal={'operations':[{'state':'pending','op':op}]}
            class FailsAfterWrite(InMemoryGovernanceOnly):
                def call(self,brand,auth,method,path,data=None,etag=None):
                    result=super().call(brand,auth,method,path,data,etag)
                    if method=='PATCH':raise OSError('simulated lost response after success')
                    return result
            api=FailsAfterWrite()
            with patch.multiple(native,ROOT=root,PRIVATE=private,JOURNAL=journal_file):
                with self.assertRaisesRegex(native.Refused,'REMOTE_WRITE_UNCERTAIN'):
                    native.apply_changes(api,{'brisa':{'auth':'Basic offline'}},native.policies(),[op],journal)
                self.assertEqual(api.values[op['key']],'true')
                self.assertEqual(journal['operations'][0]['state'],'uncertain')
                self.assertEqual(json.loads(journal_file.read_text())['operations'][0]['state'],'uncertain')
                with self.assertRaisesRegex(native.Refused,'UNCERTAIN_WRITE_REFUSE_REPLAY'):
                    native.apply_changes(api,{'brisa':{'auth':'Basic offline'}},native.policies(),[op],journal)
                self.assertEqual(sum(1 for _,method,_ in api.calls if method=='PATCH'),1)


class TestPreflightBeforeWrites(unittest.TestCase):
    def sample_plan(self):
        return {
            'recaptcha': {'restartRequired': True},
            'changes': [{'resource': 'governance', 'brand': 'aurora', 'key': 'key'},
                        {'resource': 'application', 'brand': 'aurora', 'channel': 'web',
                         'before': 'a', 'want': 'b'}],
            'summary': {'aurora': {'apps': {'web': {
                'before': 'a', 'want': 'b', 'etag': ''}}}}
        }

    def test_restart_approval_missing_rejected_before_any_write(self):
        with patch.dict(native.os.environ, {}, clear=True):
            with self.assertRaisesRegex(native.Refused, 'RESTART_APPROVAL_REQUIRED_BEFORE_WRITE'):
                native.preflight_write_authorizations(self.sample_plan())

    def test_no_etag_approval_missing_rejected_before_any_write(self):
        with patch.dict(native.os.environ,
                        {'MAGALU_SECURITY_ALLOW_RESTART': 'YES_RESTART_ONLY_V10_GA'},
                        clear=True):
            with self.assertRaisesRegex(native.Refused, 'ETAG_MISSING_ACK_REQUIRED_BEFORE_ANY_WRITE'):
                native.preflight_write_authorizations(self.sample_plan())

    def test_both_explicit_approvals_pass(self):
        with patch.dict(native.os.environ, {
            'MAGALU_SECURITY_ALLOW_RESTART': 'YES_RESTART_ONLY_V10_GA',
            'MAGALU_SECURITY_ACK_NO_ETAG':
                'ACK_NO_HTTP_ETAG_EXCLUSIVE_MAINTENANCE_WINDOW'}, clear=True):
            native.preflight_write_authorizations(self.sample_plan())

    def test_real_etag_does_not_require_no_etag_ack(self):
        plan = self.sample_plan()
        plan['summary']['aurora']['apps']['web']['etag'] = '"strong-etag"'
        with patch.dict(native.os.environ,
                        {'MAGALU_SECURITY_ALLOW_RESTART': 'YES_RESTART_ONLY_V10_GA'},
                        clear=True):
            native.preflight_write_authorizations(plan)

if __name__=='__main__':unittest.main()


class TestGraalScriptRepairOwnership(unittest.TestCase):
    """Offline contract tests; NO API calls or installed WSO2 involved."""
    def test_repair_demands_original_verified_app_hash_and_ownership(self):
        original = {'schema':native.SCHEMA,'state':'verified','operations':[]}
        with self.assertRaisesRegex(native.Refused,'ORIGINAL_APP_WRITE_OWNERSHIP_NOT_PROVEN'):
            native.original_app_write(original,'aurora','web')
        original['operations'].append({'state':'verified','op':{
            'resource':'application','brand':'aurora','channel':'web',
            'want':'c'*64}})
        self.assertEqual(native.original_app_write(original,'aurora','web'),'c'*64)
        original['operations'][0]['state']='uncertain'
        with self.assertRaisesRegex(native.Refused,'ORIGINAL_APP_WRITE_OWNERSHIP_NOT_PROVEN'):
            native.original_app_write(original,'aurora','web')

    def test_repair_plans_only_four_owned_scripts_and_rejects_drift(self):
        config = native.policies()
        seq = {'type':'USER_DEFINED','subjectStepId':1,'attributeStepId':1,
               'steps':[{'id':1,'options':[{'idp':'LOCAL','authenticator':'BasicAuthenticator'}]},
                        {'id':2,'options':[{'idp':'LOCAL','authenticator':'totp'}]}],
               'script':'previous-owner-installed-runtime-error-script'}
        previous_hash = native.sha(seq)
        original = {'schema':native.SCHEMA,'state':'verified',
                    'botState':'verified',
                    'policyHashes':{b:native.sha(config[b]) for b in native.DOMAINS},
                    'operations':[{'state':'verified','op':{
                        'resource':'application','brand':b,'channel':c,
                        'want':previous_hash}} for b in native.DOMAINS for c in native.CHANNELS]}
        def apps(_api, _brand, _owner):
            return {c:{'seq':dict(seq),'etag':None} for c in native.CHANNELS}
        def props(_api, brand, owner):
            return {k:{'value':v} for k,v in native.spec_values(config[brand]).items()}
        owners = {b:{'auth':'Basic offline'} for b in native.DOMAINS}
        with patch.object(native,'read_apps',side_effect=apps), \
             patch.object(native,'gather_properties',side_effect=props):
            ops = native.adaptive_repair_inventory(None,owners,config,original,None)
        self.assertEqual([(o['brand'],o['channel']) for o in ops],
                         [('aurora','web'),('aurora','app'),('brisa','web'),('brisa','app')])
        self.assertTrue(all(o['before']==previous_hash and o['after'] != o['before'] for o in ops))
        original['operations'][0]['op']['want'] = 'a'*64
        with patch.object(native,'read_apps',side_effect=apps), \
             patch.object(native,'gather_properties',side_effect=props):
            with self.assertRaisesRegex(native.Refused,'APP_SCRIPT_DRIFT_REFUSE_REPAIR'):
                native.adaptive_repair_inventory(None,owners,config,original,None)

    def test_repair_never_alters_governance_or_recaptcha_keys(self):
        repaired = native.script_for('aurora',native.policies()['aurora'])
        self.assertIn('executeStep(1',repaired)
        self.assertIn('executeStep(2',repaired)
        self.assertNotIn('if (approval || attemptStepUp)',repaired)
        self.assertEqual(len(native.LOCK_KEYS),4)
        self.assertEqual(len(native.BOT_KEYS),3)
