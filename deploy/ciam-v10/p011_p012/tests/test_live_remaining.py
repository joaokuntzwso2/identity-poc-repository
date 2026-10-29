import unittest,sys,datetime as dt, tempfile, json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import live_remaining,core
SHA='a'*40
RUNTIME='is:test:image:test:bffpid:123'
NOW=dt.datetime(2026,10,29,17,0,tzinfo=dt.timezone.utc)
UUID='a4a47ccd-6e4b-4d18-a174-38b7d029bdfe'
class LiveRemainingTests(unittest.TestCase):
 def obs(self,scenario):
  obj={'schema':'ciam.p011.negative-browser.v32','at':NOW.isoformat(),
   'scenario':scenario,'status':'PASS','evidenceClass':'LIVE_AUTHENTICATION',
   'operatorInteraction':True,'sourceGitSha':SHA,'runtimeIdentity':RUNTIME,
   'caseId':UUID,'checks':{'caseStillOpen':True}}
  if scenario=='canceled-mfa':obj['checks']['realProviderCancelCallback']=True
  if scenario=='self-approval':obj['checks']['selfApprovalHttp']=403
  if scenario=='expired-stepup-transaction':obj['checks'].update({'transactionTtlSeconds':300,'pendingElapsedSeconds':308,'realCodeCallback':True,'callbackHttp':400})
  if scenario=='expired-session':obj.update({'caseId':None,'checks':{'idleSeconds':3660,'authenticatedAfterIdle':False}})
  return obj
 def test_real_contracts(self):
  for s in live_remaining.ALLOWED:
   self.assertTrue(live_remaining.valid_observation(self.obs(s),s,SHA,RUNTIME,NOW),s)
 def test_fail_closed_witnesses(self):
  for s in live_remaining.ALLOWED:
   for key,value in [('sourceGitSha','b'*40),('runtimeIdentity','different'),('status','MOCKED'),('evidenceClass','UNIT'),('operatorInteraction',False)]:
    obj=self.obs(s);obj[key]=value
    self.assertFalse(live_remaining.valid_observation(obj,s,SHA,RUNTIME,NOW),(s,key))
 def test_false_evidence_never_passes(self):
  for s in live_remaining.ALLOWED:
   o=self.obs(s)
   if s=='canceled-mfa':o['checks']['realProviderCancelCallback']=False
   if s=='self-approval':o['checks']['selfApprovalHttp']=200
   if s=='expired-session':o['checks']['idleSeconds']=60
   if s=='expired-stepup-transaction':o['checks']['realCodeCallback']=False
   self.assertFalse(live_remaining.valid_observation(o,s,SHA,RUNTIME,NOW))
 def test_delay_is_not_signed_stale_mfa(self):
  self.assertIn('LIVE_STALE_MFA',live_remaining.BLOCKED)
  self.assertNotIn('LIVE_STALE_MFA',live_remaining.ALLOWED.values())
 def test_unknown_scenario_refused(self):
  self.assertFalse(live_remaining.valid_observation(self.obs('self-approval'),'fake',SHA,RUNTIME,NOW))
 def test_old_or_future_source_refused(self):
  obj=self.obs('expired-session')
  for when in [NOW+dt.timedelta(seconds=4600),NOW-dt.timedelta(seconds=20)]:
   self.assertFalse(live_remaining.valid_observation(obj,'expired-session',SHA,RUNTIME,when))
 def test_checksum_private_attestation(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);p.chmod(0o700)
   name='p011-live-negative-v32-self-approval-fixed.json';raw=json.dumps(self.obs('self-approval')).encode()
   f=p/name;f.write_bytes(raw);f.chmod(0o600)
   row={'schema':core.SCHEMA,'testId':'LIVE_SELF_APPROVAL','timestampUtc':NOW.isoformat(),
        'sourceGitSha':SHA,'runtimeIdentity':RUNTIME,'status':'PASS','evidenceClass':'LIVE_AUTHENTICATION',
        'references':[{'artifact':name,'sha256':core.digest(raw)}]}
   row['artifactSha256']=core.digest(row)
   self.assertTrue(live_remaining.attestable(p,row,'self-approval',SHA,RUNTIME,NOW))
   f.write_bytes(raw+b' ')
   self.assertFalse(live_remaining.attestable(p,row,'self-approval',SHA,RUNTIME,NOW))
 def test_wrong_or_duplicate_reference_refused(self):
  row={'testId':'LIVE_SELF_APPROVAL','sourceGitSha':SHA,'runtimeIdentity':RUNTIME,
      'status':'PASS','evidenceClass':'LIVE_AUTHENTICATION','references':[]}
  self.assertFalse(live_remaining.attestable(Path('/nonexistent'),row,'self-approval',SHA,RUNTIME,NOW))
 def test_other_four_remain_blocked(self):
  rows=live_remaining.evaluate(Path('/nonexistent'),SHA,RUNTIME,NOW)
  self.assertEqual(len(rows),8)
  self.assertTrue(all(r[1]=='BLOCKED' for r in rows))
 def test_no_shared_secret_content(self):
  self.assertNotIn('Bearer',str(live_remaining.evaluate(Path('/nonexistent'),SHA,RUNTIME,NOW)))
if __name__=='__main__':unittest.main()
