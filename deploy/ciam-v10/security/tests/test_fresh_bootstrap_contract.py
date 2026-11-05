"""Offline contract for first-installation security provisioning (no WSO2 calls)."""
import ast
from copy import deepcopy
import hashlib
import inspect
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import cli as native

class FreshBootstrapContract(unittest.TestCase):
    def test_bootstrap_invokes_initial_native_security_before_starting_bff(self):
        orchestration = (HERE.parent / 'cli.py').read_text(encoding='utf-8')
        tree = ast.parse(orchestration)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == 'bootstrap_all')
        src = ast.get_source_segment(orchestration, fn)
        milestones = ("MAGALU_SECURITY, 'plan'", "MAGALU_SECURITY, 'apply'",
                      "MAGALU_SECURITY, 'verify'", "OIDC,'start-bff'")
        offsets = [src.index(m) for m in milestones]
        self.assertEqual(offsets, sorted(offsets))
        self.assertNotIn("MAGALU_SECURITY, 'repair-apply'", src)
        self.assertIn('MAGALU_SECURITY_PLAN_SHA256', src)

    def test_approved_repaired_script_is_pinned(self):
        text = (HERE / 'scripts/magalu-adaptive.js').read_text(encoding='utf-8')
        self.assertEqual(hashlib.sha256(text.encode('utf-8')).hexdigest(),
                         native.APPROVED_GRAAL_TEMPLATE_SHA256)
        self.assertIn('context.steps[1].subject', text)
        self.assertIn('context.selectedAcr = MAGALU_APPROVAL_ACR;', text)
        self.assertNotIn('if (approval || attemptStepUp)', text)

    def test_unreviewed_template_change_is_refused_before_provisioning(self):
        text = (HERE / 'scripts/magalu-adaptive.js').read_text(encoding='utf-8')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts').mkdir()
            (root / 'scripts/magalu-adaptive.js').write_text(
                text.replace('doLogin(context);', 'doLogin(context); // altered', 1),
                encoding='utf-8')
            with patch.object(native, 'HERE', root):
                with self.assertRaisesRegex(native.Refused, 'UNAPPROVED_GRAAL_TEMPLATE_REFUSED'):
                    native.script_for('aurora', {'loginAttempts': {'stepUpAfterFailures': 3}})

    def test_fresh_application_patch_installs_repaired_script_for_four_clients(self):
        policies = native.policies()
        initial = {'type': 'DEFAULT',
                   'steps': [{'id': 1, 'options': [
                       {'idp': 'LOCAL', 'authenticator': 'BasicAuthenticator'}]}]}
        installed = {}
        for brand in native.DOMAINS:
            for channel in native.CHANNELS:
                with self.subTest(brand=brand, channel=channel):
                    state = {'seq': deepcopy(initial)}
                    wanted = native.script_for(brand, policies[brand])
                    target = native.desired_seq(initial, wanted)
                    def apps(_api, _brand, _owner):
                        return {channel: {
                            'seq': deepcopy(state['seq']),
                            'etag': '"offline-strong-etag"',
                            'path': f'/t/{native.DOMAINS[brand]}/api/server/v1/applications/demo',
                            'proto': {'clientId': 'offline-only'},
                            'app': {'id': 'offline-only', 'name': 'offline-test'}}}
                    class OfflineAppAPI:
                        def __init__(self): self.calls = []
                        def call(self, brand_, auth, method, path, data=None, etag=None):
                            self.calls.append((brand_, method, path, deepcopy(data), etag))
                            if method != 'PATCH': raise AssertionError('unexpected method')
                            state['seq'] = deepcopy(data['authenticationSequence'])
                    api = OfflineAppAPI()
                    op = {'brand': brand, 'channel': channel, 'kind': 'default',
                          'before': native.sha(initial), 'want': native.sha(target)}
                    with patch.object(native, 'read_apps', side_effect=apps):
                        native.app_patch(api, {'auth': 'Basic offline-only'}, op, policies[brand])
                    self.assertEqual(len(api.calls), 1)
                    self.assertEqual(api.calls[0][1], 'PATCH')
                    self.assertEqual(state['seq']['script'], wanted)
                    self.assertEqual(native.sequence_kind(state['seq'], wanted), 'desired')
                    installed[f'{brand}-{channel}'] = state['seq']['script']
        self.assertEqual(len(installed), 4)
        self.assertEqual(installed['aurora-web'], installed['aurora-app'])
        self.assertEqual(installed['brisa-web'], installed['brisa-app'])
        self.assertNotEqual(installed['aurora-web'], installed['brisa-web'])
        self.assertIn('MAGALU_APPROVAL_ENABLED = true', installed['aurora-web'])
        self.assertIn('MAGALU_APPROVAL_ENABLED = false', installed['brisa-web'])

if __name__ == '__main__':
    unittest.main()
