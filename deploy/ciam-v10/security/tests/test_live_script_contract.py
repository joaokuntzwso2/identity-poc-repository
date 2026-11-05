"""OFFLINE only: semantic regression of exactly the scripts uploaded from GA v10.

Node vm is a TEST DOUBLE for WSO2 callbacks; it is NOT proof of signed tokens,
Graal semantics, or native WSO2 OSGi activation.
"""
import importlib.util
import json
import pathlib
import shutil
import subprocess
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1]
FIX = pathlib.Path(__file__).resolve().parent / 'fixtures'
spec = importlib.util.spec_from_file_location('seq_live', BASE / 'application_sequences.py')
seq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seq)

NODE = r'''
const vm = require('vm');
const fs = require('fs');
const p = JSON.parse(fs.readFileSync(0, 'utf8'));
const FAILED = 'http://wso2.org/claims/identity/failedLoginAttemptsBeforeSuccess';
let called = [], denied = false, step2 = false;
let context = {
  requestedAcr: p.approval ? ['urn:ciampoc:assurance:totp:v1'] : [],
  steps: {1:{subject:{username:'controlled-user',localClaims:{}}}}
};
if (p.failed !== null) context.steps[1].subject.localClaims[FAILED] = String(p.failed);
const sandbox = {
  isFinite, Number, String,
  magaluRiskCheck: function(c, user) {
    if(c !== context || user !== 'controlled-user') throw new Error('unverified account');
    called.push('RISK'); return p.action;
  },
  fail: function(reason) {denied = true;called.push('FAIL');},
  executeStep: function(n, options) {
    called.push('STEP_'+n);
    if(n === 1) {
      if(!options || !options.onSuccess) throw new Error('step1 callback missing');
      options.onSuccess(context);
    } else if(n === 2) {
      step2 = true;
      if(p.totp && options && options.onSuccess) options.onSuccess(context);
      if(!p.totp) denied = true;
    } else throw new Error('unrecognized step');
  }
};
vm.createContext(sandbox);
vm.runInContext(p.source, sandbox, {timeout: 1500});
sandbox.onLoginRequest(context);
process.stdout.write(JSON.stringify({
  called, denied, step2, issued: !denied && (!step2 || p.totp),
  acr: context.selectedAcr || null,
  failures: context.steps[1].subject.localClaims[FAILED] || null
}));
'''


def live(tenant):
    return (FIX / ('live-aurora.js' if tenant.startswith('aurora') else 'live-brisa.js')).read_text()


def staged(tenant, alias):
    app = {'id': 'a' * 36, 'name': seq.DISPLAY_NAMES[(tenant, alias)],
           'authenticationSequence': {'type':'USER_DEFINED',
                                      'steps': [
                                          {'id':1,'options':[{'idp':'LOCAL','authenticator':'basic'}]},
                                          {'id':2,'options':[{'idp':'LOCAL','authenticator':'totp'}]}],
                                      'script': live(tenant)}}
    return seq.compose(tenant, alias, app)


class LiveScriptContracts(unittest.TestCase):
    def test_pinned_scripts_preserve_existing_acr_and_failed_claim(self):
        for tenant in seq.APPROVED_LIVE_SCRIPT_SHA256:
            source = live(tenant)
            for channel in ('web','app'):
                alias = tenant.split('.')[0] + '-' + channel
                with self.subTest(tenant=tenant, channel=channel):
                    built = staged(tenant,alias)
                    self.assertEqual(len(built['steps']), 2)
                    self.assertEqual(built['script'].count('magaluRiskCheck('), 1)
                    # Only risk-gated branch changed; everything before/after is verbatim.
                    self.assertEqual(built['script'].replace(seq.GATED_BRANCH, seq.ORIGINAL_BRANCH, 1), source)
                    self.assertIn('context.selectedAcr = MAGALU_APPROVAL_ACR;',built['script'])
                    self.assertIn('authenticated.localClaims[MAGALU_FAILED_CLAIM] = \'0\';',built['script'])

    def test_drift_or_cross_brand_script_is_denied(self):
        t='aurora.identity.test'; a='aurora-web'
        base={'id':'a'*36,'name':seq.DISPLAY_NAMES[(t,a)],
              'authenticationSequence':staged(t,a)}
        with self.assertRaisesRegex(seq.UnsafeSequence,'SHA-256'):
            seq.compose(t,a,base)
        untrusted={'id':'a'*36,'name':seq.DISPLAY_NAMES[(t,a)],
                   'authenticationSequence':{'type':'USER_DEFINED','steps':staged(t,a)['steps'],
                                             'script':live('brisa.identity.test')}}
        with self.assertRaisesRegex(seq.UnsafeSequence,'SHA-256'):
            seq.compose(t,a,untrusted)

    @unittest.skipUnless(shutil.which('node'), 'Node runtime absent; JS callback simulator not run')
    def test_all_risk_decisions_preserve_stepup_and_fail_closed(self):
        for tenant in seq.APPROVED_LIVE_SCRIPT_SHA256:
            alias=tenant.split('.')[0]+'-web'
            script=staged(tenant,alias)['script']
            for action in ('ALLOW','DELAY','CHALLENGE','STEP_UP','DENY','BAD',None):
                with self.subTest(tenant=tenant, action=action):
                    out=self.simulate(script,action=action,approval=False,totp=False,failed=None)
                    self.assertEqual(out['called'].count('RISK'),1)
                    self.assertEqual(out['issued'],action=='ALLOW')
                    self.assertEqual(out['step2'],action in ('CHALLENGE','STEP_UP'))
                    if action in ('DENY','DELAY','BAD',None):
                        self.assertTrue(out['denied'])
                    self.assertIsNone(out['acr'])
            for action in ('CHALLENGE','STEP_UP'):
                out=self.simulate(script,action=action,approval=False,totp=True,failed=None)
                self.assertTrue(out['step2'])
                self.assertTrue(out['issued'])
                self.assertIsNone(out['acr'])

    @unittest.skipUnless(shutil.which('node'), 'Node runtime absent')
    def test_aurora_acr_only_after_real_totp_step_completion(self):
        script=staged('aurora.identity.test','aurora-app')['script']
        for passed in (False,True):
            out=self.simulate(script,action='ALLOW',approval=True,totp=passed,failed=None)
            self.assertTrue(out['step2'])
            self.assertEqual(out['issued'],passed)
            self.assertEqual(out['acr']=='urn:ciampoc:assurance:totp:v1',passed)

    @unittest.skipUnless(shutil.which('node'), 'Node runtime absent')
    def test_brisa_does_not_claim_aurora_approval_acr(self):
        script=staged('brisa.identity.test','brisa-app')['script']
        out=self.simulate(script,action='ALLOW',approval=True,totp=False,failed=None)
        self.assertFalse(out['step2'])
        self.assertIsNone(out['acr'])

    @unittest.skipUnless(shutil.which('node'), 'Node runtime absent')
    def test_prior_failure_claims_require_totp_and_reset_only_on_success(self):
        for tenant, count in [('aurora.identity.test',3),('brisa.identity.test',4)]:
            script=staged(tenant,tenant.split('.')[0]+'-web')['script']
            out=self.simulate(script,action='ALLOW',approval=False,totp=False,failed=count)
            self.assertTrue(out['step2'])
            self.assertFalse(out['issued'])
            self.assertEqual(out['failures'],str(count))
            out=self.simulate(script,action='ALLOW',approval=False,totp=True,failed=count)
            self.assertTrue(out['issued'])
            self.assertEqual(out['failures'],'0')

    @staticmethod
    def simulate(source,action,approval,totp,failed):
        result=subprocess.run(['node','-e',NODE],input=json.dumps({
            'source':source, 'action':action,'approval':approval,'totp':totp,'failed':failed
        }),text=True,capture_output=True,timeout=6)
        if result.returncode:
            raise AssertionError('Node simulator failed: '+result.stderr[:700])
        return json.loads(result.stdout)

if __name__=='__main__': unittest.main()
