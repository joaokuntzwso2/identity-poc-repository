import importlib.util, json, os, stat, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
P=Path(__file__).resolve().parents[2]/'scripts/p2/partner_v13.py'
spec=importlib.util.spec_from_file_location('p2_v13_under_test',P)
v13=importlib.util.module_from_spec(spec);spec.loader.exec_module(v13)

class FakeModule:
    def __init__(self, journal): self.journal=journal
    def read_json_private(self,path): return self.journal
    @staticmethod
    def UUID(): return None

class Tests(unittest.TestCase):
    def test_exact_actor_scope_is_only_create(self):
        self.assertEqual(v13.SCOPE,'internal_org_organization_create')
        self.assertEqual(v13.TENANT,'aurora.identity.test')
        self.assertNotEqual(v13.CREATOR_FP,v13.ROOT_FP)
    def test_sanitizer_refuses_unstructured_errors(self):
        self.assertEqual(v13.safe_code(Exception('Bearer secret')),
                         'V13_UNEXPECTED_FAILURE_CHECK_PRIVATE_JOURNAL')
        self.assertEqual(v13.safe_code(v13.Stop('V13_X_BLOCKED')),'V13_X_BLOCKED')
    def test_journal_missing_does_not_implicitly_approve_an_existing_org(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertIsNone(v13.inspect_journal(None,Path(t)))
    def test_journal_wrong_tenant_owner_fingerprint_denied(self):
        with tempfile.TemporaryDirectory() as t:
            doc={'schema':v13.SCHEMA,'state':'VERIFIED','details':{'parentFingerprint':'brisa',
                'name':v13.PARTNER_NAME,'orgHandle':v13.PARTNER_HANDLE,
                'creatorAppFingerprint':v13.CREATOR_FP}}
            m=FakeModule(doc)
            (Path(t)/v13.PARTNER_JOURNAL).write_text('{}')
            with self.assertRaisesRegex(v13.Stop,'V13_PARTNER_JOURNAL_IDENTITY_DRIFT'):
                v13.inspect_journal(m,Path(t))
    def test_exact_verified_journal_is_accepted_for_readback(self):
        with tempfile.TemporaryDirectory() as t:
            doc={'schema':v13.SCHEMA,'state':'VERIFIED','details':{
                'parentFingerprint':v13.ROOT_FP,'name':v13.PARTNER_NAME,
                'orgHandle':v13.PARTNER_HANDLE,'creatorAppFingerprint':v13.CREATOR_FP}}
            (Path(t)/v13.PARTNER_JOURNAL).write_text('{}')
            self.assertEqual(v13.inspect_journal(FakeModule(doc),Path(t)),doc)
    def test_private_lock_rejects_open_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/v13.LOCK;p.write_text('');p.chmod(0o644)
            with self.assertRaisesRegex(v13.Stop,'V13_LOCK_UNSAFE'):
                with v13.lock(Path(t)): pass
    def test_private_lock_uses_mode_0600(self):
        with tempfile.TemporaryDirectory() as t:
            with v13.lock(Path(t)):
                self.assertEqual(stat.S_IMODE((Path(t)/v13.LOCK).stat().st_mode),0o600)
    def test_node_subprocess_keeps_bearer_out_of_arguments(self):
        class R:
            returncode=0
            stdout=json.dumps({'action':'CREATE','parentFingerprint':v13.ROOT_FP})
            stderr=''
        with tempfile.TemporaryDirectory() as t:
            with patch.object(v13.subprocess,'run',return_value=R()) as run:
                value=v13.node_call(Path(t),Path(t),'plan','r'*36,'VIEW_TOKEN_SECRET'+'x'*20)
                self.assertEqual(value['action'],'CREATE')
                args=run.call_args
                self.assertNotIn('VIEW_TOKEN_SECRET',str(args.args))
                self.assertNotIn('VIEW_TOKEN_SECRET',str(args.kwargs['env']))
                self.assertIn('VIEW_TOKEN_SECRET',args.kwargs['input'])
    def test_node_errors_do_not_echo_tokens(self):
        class R:
            returncode=2
            stdout=''
            stderr=json.dumps({'status':'BLOCKED','code':'V13_CHILD_MISMATCH'})
        with tempfile.TemporaryDirectory() as t:
            with patch.object(v13.subprocess,'run',return_value=R()):
                with self.assertRaisesRegex(v13.Stop,'V13_CHILD_MISMATCH'):
                    v13.node_call(Path(t),Path(t),'verify','r'*36,'x'*30)
    def test_only_supported_modes(self):
        with self.assertRaisesRegex(v13.Stop,'V13_COMMAND_REQUIRED'):
            v13.main(['delete'])
    def test_token_response_exact_scope_no_extra(self):
        # Validate by static contract: only exact singleton scope is accepted.
        import inspect
        src=inspect.getsource(v13.tokens)
        self.assertIn("doc['scope'].split()==[SCOPE]",src)
        self.assertIn("method='POST'",src)
    def test_creator_journal_is_not_replaced_when_intent_present(self):
        import inspect
        src=inspect.getsource(v13.main)
        self.assertIn('V13_UNCERTAIN_PARTNER_WRITE_RECONCILE_NO_RETRY',src)
        self.assertIn("m.exclusive_json(private/PARTNER_JOURNAL",src)
        self.assertEqual(src.count("node_call(repo,private,'create'"),1)
    def test_main_has_no_broad_api_mutation(self):
        import inspect
        src=inspect.getsource(v13)
        self.assertNotIn('/scim2/Groups',src)
        self.assertNotIn('/t/brisa.identity.test/',src)
        self.assertNotIn('authorization-apply',src)

if __name__=='__main__': unittest.main()
