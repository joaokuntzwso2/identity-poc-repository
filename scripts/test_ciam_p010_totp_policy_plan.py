import copy,importlib.util,unittest
from pathlib import Path
p=Path(__file__).with_name('ciam-p010-totp-policy-plan.py')
s=importlib.util.spec_from_file_location('p010plan',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

def sample():
    row={'registeredApplicationVerified':True,'callbackVerified':True,
         'codeAndPkceS256Verified':True,'roleAudience':'APPLICATION',
         'mandatoryTotpForRequestedAcrAttested':False,
         'acrAmrFromActualSignedIdTokenAttested':False,
         'conditionalScriptPresent':False,'conditionalScriptSha256':None,
         'sequenceType':'DEFAULT',
         'sequenceSteps':[{'id':1,'authenticators':['BasicAuthenticator']}]}
    return {'stage':'P010_WSO2_APP_ASSURANCE_READBACK','mode':'GET_ONLY','remoteWrites':0,
       'tenants':{b:{c:copy.deepcopy(row) for c in ('web','app')} for b in ('aurora','brisa')}}
class PlanSafety(unittest.TestCase):
    def test_readonly_exact_two_aurora_no_brisa_writes(self):
        out=m.plan(sample());self.assertEqual(out['changesProposed'],2)
        self.assertEqual(out['brisaChangesProposed'],0)
        self.assertEqual({(x['tenant'],x['channel']) for x in out['changes']},{('aurora','web'),('aurora','app')})
        self.assertFalse(out['writesAllowedByThisTool']);self.assertEqual(out['remoteWrites'],0)
    def test_approval_and_real_signed_claims_are_unverified(self):
        out=m.plan(sample());self.assertFalse(out['loginOrTotpSuccessClaimed'])
        self.assertTrue(all(not x['amrClaimReleaseVerified'] and not x['liveSellerEnrollmentVerified'] for x in out['changes']))
    def test_idempotent_snapshot(self):
        self.assertEqual(m.plan(sample())['planSha256'],m.plan(sample())['planSha256'])
    def test_precondition_change_changes_hash(self):
        x=sample();a=m.plan(x)['preconditionSha256'];x['tenants']['brisa']['app']['sequenceType']='OTHER'
        with self.assertRaisesRegex(m.Refused,'EXISTING_LOGIN_FLOW_DRIFT'):m.plan(x)
        self.assertEqual(len(a),64)
    def test_existing_script_refused(self):
        x=sample();x['tenants']['aurora']['web']['conditionalScriptPresent']=True
        with self.assertRaisesRegex(m.Refused,'EXISTING_ADAPTIVE_SCRIPT'):m.plan(x)
    def test_existing_step_2_refused(self):
        x=sample();x['tenants']['aurora']['web']['sequenceSteps'].append({'id':2,'authenticators':['totp']})
        with self.assertRaisesRegex(m.Refused,'EXISTING_LOGIN_FLOW_DRIFT'):m.plan(x)
    def test_mfa_claim_attestation_not_invented(self):
        x=sample();x['tenants']['aurora']['app']['acrAmrFromActualSignedIdTokenAttested']=True
        with self.assertRaisesRegex(m.Refused,'ASSURANCE_ATTESTATION_STATUS_CHANGED'):m.plan(x)
    def test_wrong_audience_denied(self):
        x=sample();x['tenants']['aurora']['app']['roleAudience']='ORGANIZATION'
        with self.assertRaisesRegex(m.Refused,'CLIENT_POLICY_VERIFICATION_DRIFT'):m.plan(x)
    def test_extra_tenant_denied(self):
        x=sample();x['tenants']['super']={}
        with self.assertRaisesRegex(m.Refused,'TENANT_LAYOUT_CHANGED'):m.plan(x)
    def test_non_read_only_source_denied(self):
        x=sample();x['remoteWrites']=1
        with self.assertRaisesRegex(m.Refused,'POLICY_READBACK_NOT_GENUINE'):m.plan(x)
    def test_missing_pkce_denied(self):
        x=sample();x['tenants']['brisa']['web']['codeAndPkceS256Verified']=False
        with self.assertRaisesRegex(m.Refused,'CLIENT_POLICY_VERIFICATION_DRIFT'):m.plan(x)
if __name__=='__main__':unittest.main()
