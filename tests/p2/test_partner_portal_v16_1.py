import importlib.util,tempfile,types,unittest
from pathlib import Path
from unittest.mock import Mock
source=Path(__file__).resolve().parents[2]/'scripts/p2/partner_portal_v16_1.py'
spec=importlib.util.spec_from_file_location('v161',source)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class CustomStop(Exception):pass
class Cases(unittest.TestCase):
  def setUp(self):
    self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    self.private=self.root/'private';self.private.mkdir()
    self.repo=self.root/'repo';self.repo.mkdir()
    self.v16=types.SimpleNamespace(JOURNAL='journal.private.json',APPROVAL='EXACT',Stop=CustomStop)
    self.v16.main=Mock()
    self._old_lookup=v.existing_callback_info
    v.existing_callback_info=lambda *args:(('source-id','http://localhost:4000/callback'),7)
  def tearDown(self):
    v.existing_callback_info=self._old_lookup
    self.temp.cleanup()
  def test_initial_callback_missing_is_pending_without_any_write(self):
    self.v16.main.side_effect=CustomStop('V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF')
    r=v.bootstrap(self.repo,self.private,self.v16)
    self.assertEqual(r['code'],'V16_1_CALLBACK_SOURCE_PROOF_PENDING_STARTUP_SAFE')
    self.assertEqual(r['managementWrites'],0)
    self.v16.main.assert_called_once_with(['ensure','--approve=EXACT'])
  def test_verified_registration_passes_through(self):
    self.v16.main.return_value={'status':'VERIFIED','managementWrites':1}
    self.assertEqual(v.bootstrap(self.repo,self.private,self.v16)['status'],'VERIFIED')
  def test_unowned_name_collision_cannot_be_hidden_as_pending(self):
    self.v16.main.side_effect=CustomStop('V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF')
    def collision(*args):raise v.Block('V16_1_UNOWNED_PORTAL_APP_NAME_COLLISION')
    v.existing_callback_info=collision
    with self.assertRaisesRegex(v.Block,'UNOWNED_PORTAL'):v.bootstrap(self.repo,self.private,self.v16)
  def test_all_other_errors_fail_closed(self):
    for reason in ('V16_CREATE_POST_OUTCOME_UNKNOWN_NO_RETRY','V16_CREATE_INTENT_EXISTS_RECONCILE_NO_RETRY','V16_APP_ID_INVALID'):
      self.v16.main.side_effect=CustomStop(reason)
      with self.subTest(reason=reason),self.assertRaises(CustomStop):v.bootstrap(self.repo,self.private,self.v16)
  def test_callback_failure_with_journal_fails_closed(self):
    self.v16.main.side_effect=CustomStop('V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF')
    (self.private/self.v16.JOURNAL).write_text('{}')
    with self.assertRaisesRegex(v.Block,'EXISTING_JOURNAL'):v.bootstrap(self.repo,self.private,self.v16)
  def test_callback_failure_with_symlink_fails_closed(self):
    self.v16.main.side_effect=CustomStop('V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF')
    (self.private/self.v16.JOURNAL).symlink_to(self.root/'missing')
    with self.assertRaisesRegex(v.Block,'EXISTING_JOURNAL'):v.bootstrap(self.repo,self.private,self.v16)
  def test_callback_failure_with_missing_private_fails_closed(self):
    self.v16.main.side_effect=CustomStop('V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF')
    with self.assertRaisesRegex(v.Block,'PRIVATE_DIRECTORY'):v.bootstrap(self.repo,self.root/'missing',self.v16)
  def test_existing_literal_is_diagnostic_only(self):
    src=self.repo/'services/identity-bff/src/server.js';src.parent.mkdir(parents=True)
    src.write_text("const path='/api/auth/aurora/callback';")
    x=v.scan_sources(self.repo,'/api/auth/aurora/callback')
    self.assertTrue(x['exactCallbackPathLiteralPresent'])
    self.assertFalse(x['dynamicCallbackConstructionCandidate'])
  def test_dynamic_route_never_counts_as_exact(self):
    src=self.repo/'services/identity-bff/src/server.js';src.parent.mkdir(parents=True)
    src.write_text('const callback = `/api/auth/${channel}/callback`;')
    x=v.scan_sources(self.repo,'/api/auth/aurora/callback')
    self.assertTrue(x['dynamicCallbackConstructionCandidate'])
    self.assertFalse(x['exactCallbackPathLiteralPresent'])
  def test_no_test_files_as_proof(self):
    src=self.repo/'services/identity-bff/test/test.js';src.parent.mkdir(parents=True)
    src.write_text("const callback='/api/auth/aurora/callback';")
    x=v.scan_sources(self.repo,'/api/auth/aurora/callback')
    self.assertEqual(x['sourceFilesScanned'],0)
  def test_symlink_skipped(self):
    src=self.repo/'services/identity-bff/src/server.js';src.parent.mkdir(parents=True)
    src.symlink_to(self.root/'secret')
    self.assertEqual(v.scan_sources(self.repo,'/api/auth/aurora/callback')['sourceFilesScanned'],0)
  def test_scan_bounded(self):
    src=self.repo/'services/identity-bff/src';src.mkdir(parents=True)
    for i in range(v.PROBE_FILES_MAX+1):(src/f'{i}.js').write_text('')
    with self.assertRaisesRegex(v.Block,'SCAN_OVERSIZE'):v.scan_sources(self.repo,'/callback')
if __name__=='__main__':unittest.main()
