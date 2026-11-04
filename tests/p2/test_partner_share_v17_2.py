from __future__ import annotations
import importlib.util, tempfile, unittest, uuid, json, hashlib, re
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('v172',ROOT/'scripts/p2/partner_share_v17_2.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
spec=importlib.util.spec_from_file_location('v17_under_v172',ROOT/'scripts/p2/partner_share_v17.py')
v17=importlib.util.module_from_spec(spec);spec.loader.exec_module(v17)
APP=str(uuid.uuid4());CONTROL=str(uuid.uuid4());ORG=str(uuid.uuid4());OTHER=str(uuid.uuid4());ROOTORG=str(uuid.uuid4())
class HTTP:
 def __init__(self,valid=True,portal=None,control=None,sharing=None):
  self.paths=[];self.portal=portal;self.control=control;self.sharing=sharing;self.valid=valid
 def call(self,method,path,basic=None):
  assert method=='GET'
  self.paths.append(path)
  if self.portal is not None and f'/{APP}/' in path:return 200,self.portal,{}
  if path.endswith('/'+APP):return 200,{'id':APP,'name':v17.APP_NAME,'isManagementApp':False},{}
  if path.endswith('/'+CONTROL):return 200,{'id':CONTROL,'isManagementApp':False},{}
  if path.endswith('/'+OTHER):return 200,{'id':OTHER,'isManagementApp':True},{}
  if path.endswith('/shared-apps') and f'/{CONTROL}/' in path:
   return 200,self.control if self.control is not None else {'sharedApplications':[{'applicationId':str(uuid.uuid4()),'organizationId':ORG}]},{}
  if path.endswith('/shared-apps') and f'/{APP}/' in path:return 200,self.portal if self.portal is not None else {},{}
  raise AssertionError(path)
class ModuleM:
 UUID=re.compile(r'[0-9a-f-]{36}')
 def inventory(self,http,base,collection,admin):return [{'id':APP},{'id':CONTROL},{'id':OTHER}]
 def safe_private_file(self,file,required=False):return file in self.records
 def exclusive_json(self,file,rec):
  assert file not in self.records
  self.records[file]=rec.copy()
 def replace_json(self,file,rec):self.records[file]=rec.copy()
 def read_json_private(self,file):return self.records[file]
 def __init__(self):self.records={}
class V14:
 def read_shares(self,m,http,admin,app_id):
  if app_id==CONTROL:
   return [{'id':ORG,'sharingMode':{'policy':'SELECTED_ORG_ONLY'}}],None
  raise AssertionError(app_id)
class Tests(unittest.TestCase):
 def test_source_is_pinned_and_original_file_unchanged(self):
  self.assertEqual(hashlib.sha256((ROOT/v.V17).read_bytes()).hexdigest(),v.V17_SHA)
  self.assertEqual(v17.body_for(APP,ORG)['organizations'],[{'orgId':ORG,'policy':'SELECTED_ORG_ONLY','roleSharing':{'mode':'NONE'}}])
 def test_empty_shapes_all_four_must_be_exact_objects(self):
  for x in ({},{'organizations':None},{'sharedApplications':[]},{'sharingMode':None},[],None):
   with self.subTest(x=x):
    h=HTTP(portal=x)
    self.assertEqual(v.empty_portal_views(h,('admin','pass'),APP,ORG,v17.BASE),x=={})
 def test_positive_control_requires_both_views_matching_orgs(self):
  m=ModuleM();h=HTTP()
  self.assertEqual(v.positive_control(m,h,('a','b'),V14(),APP,ORG,v17.BASE),1)
  self.assertTrue(all('/t/aurora.identity.test/' in p for p in h.paths))
  bad=HTTP(control={'sharedApplications':[{'applicationId':CONTROL,'organizationId':str(uuid.uuid4())}]})
  self.assertEqual(v.positive_control(m,bad,('a','b'),V14(),APP,ORG,v17.BASE),0)
 def test_positive_control_ignores_management_apps_and_new_portal(self):
  h=HTTP();v.positive_control(ModuleM(),h,('a','b'),V14(),APP,ORG,v17.BASE)
  self.assertFalse(any(f'/{OTHER}/share' in p for p in h.paths))
  self.assertFalse(any(f'/{APP}/shared-apps' in p for p in h.paths))
 def test_positive_control_rejects_mapping_duplicate(self):
  doc={'sharedApplications':[{'applicationId':str(uuid.uuid4()),'organizationId':ORG}]*2}
  with self.assertRaisesRegex(v.Refuse,'DUPLICATE'):
   v.positive_control(ModuleM(),HTTP(control=doc),None,V14(),APP,ORG,v17.BASE)
 def test_positive_control_requires_complete_inventory(self):
  class M(ModuleM):
   def inventory(self,*_):return [{'id':CONTROL}]
  with self.assertRaisesRegex(v.Refuse,'PORTAL_NOT_IN_INVENTORY'):
   v.positive_control(M(),HTTP(),None,V14(),APP,ORG,v17.BASE)
 def test_calibration_never_claims_when_control_missing(self):
  with mock.patch.object(v17,'reconcile_snapshot',return_value='PENDING'):
   with mock.patch.object(v,'positive_control',return_value=0):
    state,ok,count=v.calibrate(v17,None,None,None,None,APP,ORG,ROOTORG)
  self.assertEqual((state,ok,count),('PENDING',False,0))
 def test_calibration_exact_or_broad_block_not_overwritten(self):
  with mock.patch.object(v17,'reconcile_snapshot',return_value='EXACT'):
   with mock.patch.object(v,'positive_control',side_effect=AssertionError('should never reach')):
    self.assertEqual(v.calibrate(v17,None,None,None,None,APP,ORG,ROOTORG),('EXACT',False,0))
 def test_double_empty_and_positive_control_allow_only_empty_prewrite(self):
  with mock.patch.object(v17,'reconcile_snapshot',return_value='PENDING'), \
       mock.patch.object(v,'positive_control',return_value=1), \
       mock.patch.object(v,'empty_portal_views',return_value=True) as empty:
   self.assertEqual(v.calibrate(v17,None,None,None,None,APP,ORG,ROOTORG),('EMPTY',True,1))
  self.assertEqual(empty.call_count,2)
 def test_one_bad_empty_probe_does_not_authorize(self):
  with mock.patch.object(v17,'reconcile_snapshot',return_value='PENDING'), \
       mock.patch.object(v,'positive_control',return_value=1), \
       mock.patch.object(v,'empty_portal_views',side_effect=[True,False]):
   self.assertEqual(v.calibrate(v17,None,None,None,None,APP,ORG,ROOTORG),('PENDING',False,1))
 def test_post_safe_happens_only_after_double_calibration_and_intent(self):
  m=ModuleM();c=[]
  def cb(*_):
   c.append('POST');self.assertEqual(m.records[Path('/private')/v17.JOURNAL]['state'],'INTENT')
  with mock.patch.object(v17,'reconcile_snapshot',return_value='EXACT'):
   out=v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
     poster=cb,sleeper=lambda _:None,calibrator=lambda *_:('EMPTY',True,1))
  self.assertEqual(c,['POST']);self.assertEqual(out['status'],'VERIFIED')
  self.assertEqual(out['managementWritesAttempted'],1)
  self.assertEqual(m.records[Path('/private')/v17.JOURNAL]['state'],'VERIFIED')
 def test_no_post_if_positive_control_not_proven(self):
  m=ModuleM();out=v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
    poster=lambda *_:self.fail('POST'),calibrator=lambda *_:('PENDING',False,0))
  self.assertEqual(out['status'],'PENDING');self.assertEqual(m.records,{})
 def test_read_only_status_never_journals(self):
  m=ModuleM();out=v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'status',
    poster=lambda *_:self.fail('POST'),calibrator=lambda *_:('EMPTY',True,1))
  self.assertEqual(out['status'],'PLAN_ONLY');self.assertEqual(m.records,{})
 def test_uncertain_post_intent_prevents_auto_retry(self):
  m=ModuleM();calls=[];path=Path('/private')/v17.JOURNAL
  def cb(*_):calls.append('POST');raise OSError('timeout')
  with self.assertRaisesRegex(v.Refuse,'UNKNOWN_NEVER_RETRY'):
   v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
     poster=cb,calibrator=lambda *_:('EMPTY',True,1))
  self.assertEqual(m.records[path]['state'],'INTENT')
  with mock.patch.object(v17,'reconcile_snapshot',return_value='PENDING'):
   out=v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',poster=cb,
     calibrator=lambda *_:self.fail('must not calibrate after intent'))
  self.assertEqual(out['status'],'PENDING');self.assertEqual(calls,['POST'])
 def test_nonempty_unowned_share_fails_before_post(self):
  with self.assertRaisesRegex(v.Refuse,'UNOWNED'):
   v.apply(v17,ModuleM(),None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
       poster=lambda *_:self.fail('POST'),calibrator=lambda *_:('EXACT',False,0))
 def test_race_at_second_calibration_prevents_journal(self):
  m=ModuleM();it=iter([('EMPTY',True,1),('PENDING',False,1)])
  out=v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
      poster=lambda *_:self.fail('POST'),calibrator=lambda *_:next(it))
  self.assertEqual(out['status'],'PENDING');self.assertEqual(m.records,{})
 def test_async_post_accepted_is_pending_and_never_repeated(self):
  m=ModuleM();calls=[]
  with mock.patch.object(v17,'reconcile_snapshot',return_value='PENDING'):
   out=v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
    poster=lambda *_:calls.append('POST'),sleeper=lambda _:None,
    calibrator=lambda *_:('EMPTY',True,1))
   again=v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
    poster=lambda *_:self.fail('second POST'),sleeper=lambda _:None,
    calibrator=lambda *_:self.fail('second calibrate'))
  self.assertEqual(out['status'],'PENDING');self.assertEqual(again['status'],'PENDING')
  self.assertEqual(calls,['POST'])
 def test_existing_verified_journal_drift_refuses(self):
  m=ModuleM();path=Path('/private')/v17.JOURNAL
  m.records[path]={**v17.journal_template(APP,ORG,v17.body_for(APP,ORG)),'state':'VERIFIED','postAcknowledged':True}
  with mock.patch.object(v17,'reconcile_snapshot',return_value='PENDING'):
   with self.assertRaisesRegex(v17.Refuse,'REMOTE_DRIFT'):
    v.apply(v17,m,None,None,None,Path('/private'),APP,ORG,ROOTORG,'bootstrap',
      poster=lambda *_:self.fail('POST'))

if __name__=='__main__':unittest.main()
