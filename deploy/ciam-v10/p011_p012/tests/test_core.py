import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import core
import cli

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.sha='a'*40
        self.runtime='is:0123:image:5678:bffpid:17'
    def item(self,kind='UNIT',refs=None):
        return core.evidence('TEST_A','Verification',self.sha,'lab',self.runtime,kind,'PASS','OK','OK',references=refs)
    def test_valid_digest_and_provenance(self):
        self.assertIsNone(core.verify_evidence(self.item(),self.sha,self.runtime))
    def test_detect_tampering(self):
        row=self.item();row['observed']='tampered'
        self.assertEqual(core.verify_evidence(row,self.sha,self.runtime),'EVIDENCE_TAMPERED')
    def test_detect_wrong_commit(self):
        self.assertEqual(core.verify_evidence(self.item(),'b'*40,self.runtime),'SOURCE_SHA_MISMATCH')
    def test_detect_wrong_runtime(self):
        self.assertEqual(core.verify_evidence(self.item(),self.sha,'other'),'RUNTIME_IDENTITY_MISMATCH')
    def test_detect_staleness(self):
        row=self.item(); now=core.utc_now()+dt.timedelta(days=1)
        self.assertEqual(core.verify_evidence(row,self.sha,self.runtime,now=now),'EVIDENCE_STALE')
    def test_missing_reference_cannot_prove_browser(self):
        self.assertEqual(core.verify_evidence(self.item('BROWSER_E2E'),self.sha,self.runtime),'LIVE_ARTIFACT_REFERENCE_MISSING')
    def test_missing_reference_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cli,'INSPECTION',Path(tmp)):
                verified=cli.external_live_reference(self.item('BROWSER_E2E',[{'artifact':'p010-live-browser-x.json','sha256':'aa'}]))
        self.assertFalse(verified[0])
    def test_status_precedence(self):
        self.assertEqual(core.combine([{'status':'PASS'},{'status':'BLOCKED'}]),'BLOCKED')
        self.assertEqual(core.combine([{'status':'FAIL'},{'status':'BLOCKED'}]),'NOT_READY')
    def test_real_p010_shape_rejects_mock(self):
        self.assertFalse(core.assess_p010({'schema':'ciam-p010.live-acceptance.v1','status':'PASS_REAL_WSO2_FOUR_CLIENTS_AND_TOTP_APPROVAL'}))
    def test_real_p010_shape_requires_all_clients_and_case_reads(self):
        clients={k:{'issuerTenant':v,'loginVerified':True,'userInfoVerified':True,'userInfoHttp':200,'subjectFingerprint':'customer_fingerprint' if k=='aurora-web' else 'client_'+k}
                 for k,v in {'aurora-web':'aurora','aurora-app':'aurora','brisa-web':'brisa','brisa-app':'brisa'}.items()}
        sample={'schema':'ciam-p010.live-acceptance.v1','status':'PASS_REAL_WSO2_FOUR_CLIENTS_AND_TOTP_APPROVAL',
                'browserDriven':True,'credentialsSaved':False,'tokenOrCookieDataSaved':False,'mfaOperatorInteractionRequired':True,
                'clients':clients,'seller':{'loginVerified':True,'userInfoVerified':True,'userInfoHttp':200,
                  'subjectFingerprint':'separate_seller_fingerprint'},
                'cases':{'createHttp':201,'ownerReadHttp':200,'sellerReviewHttp':200,'stepUpStartHttp':202,
                         'sellerAfterHttp':200,'customerAfterHttp':200},'denials':{'crossTenantHttp':403}}
        self.assertTrue(core.assess_p010(sample))
        sample['seller']['subjectFingerprint']=sample['clients']['aurora-web']['subjectFingerprint']
        self.assertFalse(core.assess_p010(sample))
        sample['seller']['subjectFingerprint']='separate_seller_fingerprint'
        sample['cases']['customerAfterHttp']=401
        self.assertFalse(core.assess_p010(sample))

class RedactionTests(unittest.TestCase):
    def test_private_key_in_log(self):
        token='-----BEGIN '+'PRIVATE KEY-----'
        self.assertEqual(core.issues_in_text('before\n'+token+'\n','server.log')[0]['classification'],'PRIVATE_KEY')
    def test_bearer_in_browser_trace(self):
        token='Bearer '+('X'*45)
        self.assertTrue(any(x['classification']=='OAUTH_BEARER' for x in core.issues_in_text(token,'browser-trace.json')))
    def test_totp_uri_in_trace(self):
        token='otpauth://totp/'+'fixture?secret='+('A'*32)
        self.assertTrue(any(x['classification']=='TOTP_SEED' for x in core.issues_in_text(token,'browser-trace.json')))
    def test_cookie_evidence(self):
        token='"cookie":"session='+('X'*42)+'"'
        results=core.issues_in_text(token,'evidence.json')
        self.assertTrue(any(x['classification'] in ('COOKIE','SENSITIVE_EVIDENCE_FIELD') for x in results))
    def test_cookie_expression_not_a_secret(self):
        text='const options = { cookie: request.headers.getSessionCookieFromTemporaryState() };'
        self.assertFalse(any(x['classification']=='COOKIE' for x in core.issues_in_text(text,'server.test.js')))
    def test_literal_cookie_still_detected_in_test_source(self):
        text='const opts={cookie: "session=' + 'Q'*48 + '"};'
        self.assertTrue(any(x['classification']=='COOKIE' for x in core.issues_in_text(text,'server.test.js')))
    def test_literal_set_cookie_header_detected(self):
        text='Set-Cookie: identity_session=' + 'Z'*45 + '; HttpOnly; Secure'
        self.assertTrue(any(x['classification']=='COOKIE' for x in core.issues_in_text(text,'response.log')))
    def test_long_opaque_literal_cookie_detected(self):
        text='const options={cookie: "' + 'S'*48 + '"};'
        self.assertTrue(any(x['classification']=='COOKIE' for x in core.issues_in_text(text,'tracked.js')))
    def test_quoted_cookie_json_detected(self):
        text='{"cookie":"session=' + 'T'*48 + '"}'
        self.assertTrue(any(x['classification']=='COOKIE' for x in core.issues_in_text(text,'tracked.json')))
    def test_regular_status_safe(self):
        self.assertEqual(core.issues_in_text('HTTP=401; client=aurora-web; reason=DENIED','evidence.json'),[])
    def test_tracked_git_index_separate_from_untracked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)
            subprocess.run(['git','init','-q',tmp],check=True)
            (repo/'safe.txt').write_text('No private values')
            (repo/'untracked.env').write_text('PASSWORD='+'Q'*60)
            subprocess.run(['git','add','--','safe.txt'],cwd=repo,check=True)
            self.assertEqual(core.audit_tracked(repo),[])
            (repo/'.env').write_text('hello')
            subprocess.run(['git','add','-f','--','.env'],cwd=repo,check=True)
            self.assertTrue(any(x['classification']=='PRIVATE_TRACKED_PATH' for x in core.audit_tracked(repo)))
    def test_private_files_mode_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)/'inspection';core.private_directory(d)
            f=core.private_write(d,'evidence',{'x':1})
            self.assertEqual(f.stat().st_mode & 0o777,0o600)
            self.assertIn(b'"x":1',core.read_private(f))
            os.chmod(f,0o644)
            with self.assertRaises(ValueError):core.read_private(f)
            symlink=d/'bad.json';symlink.symlink_to(f)
            with self.assertRaises(ValueError):core.read_private(symlink)
    def test_scan_evidence_untrusted_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'evidence.json';p.write_text('"id_token":"'+'Q'*50+'"')
            # Deliberately mark this fixture unsafe; a 077 umask otherwise makes it 0600.
            os.chmod(p,0o644)
            issues,available=core.audit_inspection(tmp)
            self.assertTrue(available)
            self.assertTrue(any(i['classification']=='UNSAFE_EVIDENCE_ARTIFACT' for i in issues))
            os.chmod(p,0o600)
            issues,_=core.audit_inspection(tmp)
            self.assertTrue(any(i['classification']=='SENSITIVE_EVIDENCE_FIELD' for i in issues))

class ProvisionTests(unittest.TestCase):
    def make_plan(self):
        p={'schema':'ciam-p012.authorization-plan.v1','createdUtc':core.iso_now(),'sourceGitSha':'a'*40,'roleApiVersion':'v3','state':'PLANNED','safeToApply':True}
        p['planSha256']=core.digest(p)
        return p
    def test_approval_requires_exact_sha(self):
        with self.assertRaisesRegex(ValueError,'PLAN_SOURCE'):
            core.validate_approval(self.make_plan(),'b'*40)
    def test_plan_tampering_rejected(self):
        p=self.make_plan();p['scope']='modified'
        with self.assertRaisesRegex(ValueError,'PLAN_TAMPERED'):
            core.validate_approval(p,'a'*40)
    def test_plan_expired_rejected(self):
        p=self.make_plan();p['createdUtc']=(core.utc_now()-dt.timedelta(hours=1)).isoformat()
        p['planSha256']=core.digest({k:v for k,v in p.items() if k!='planSha256'})
        with self.assertRaisesRegex(ValueError,'PLAN_EXPIRED'):
            core.validate_approval(p,'a'*40)
    def test_role_v2_rejected(self):
        p=self.make_plan();p['roleApiVersion']='v2'
        p['planSha256']=core.digest({k:v for k,v in p.items() if k!='planSha256'})
        with self.assertRaisesRegex(ValueError,'PLAN_SOURCE_OR_ROLE_API'):
            core.validate_approval(p,'a'*40)
    def test_provision_apply_requires_separate_approval(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(cli.Refuse,'EXPLICIT_P012'):
                cli.provision_apply()
    def test_live_acceptance_requires_explicit_business_write_approval(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(cli.Refuse,'OPERATOR_APPROVAL'):
                cli.live_acceptance()

if __name__=='__main__':unittest.main()
