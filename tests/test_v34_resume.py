#!/usr/bin/env python3
"""Offline tests: skip insecure Basic window after management success."""
import importlib.util
import json
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parent.parent/'scripts/wso2/temporary-basic-bootstrap.py'
spec=importlib.util.spec_from_file_location('v34_basic', SOURCE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class SafeResume(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.start=os.getcwd();os.chdir(self.tmp.name);self.addCleanup(os.chdir,self.start)
        d=Path('var/wso2');d.mkdir(parents=True)
        (d/'tenant-management.private.json').write_text(json.dumps({'schemaVersion':1,'management':{
            'aurora':{'state':'verified','domain':'aurora.identity.test'},
            'brisa':{'state':'verified','domain':'brisa.identity.test'}}}))
        (d/'tenant-brand.private.json').write_text(json.dumps({'tenants':{
            'aurora':{'state':'created','domain':'aurora.identity.test'},
            'brisa':{'state':'created','domain':'brisa.identity.test'}}}))

    def test_matching_management_states_true(self):
        self.assertTrue(module.management_journal_verified())

    def test_unsupported_journal_stops(self):
        p=Path('var/wso2/tenant-management.private.json')
        p.write_text('{}')
        with self.assertRaisesRegex(module.Stop,'MANAGEMENT_JOURNAL_INVALID'):
            module.management_journal_verified()

    def test_wrong_domain_never_skips_bootstrap(self):
        p=Path('var/wso2/tenant-management.private.json');data=json.loads(p.read_text())
        data['management']['brisa']['domain']='wrong.example.test'
        p.write_text(json.dumps(data))
        self.assertFalse(module.management_journal_verified())

    def test_missing_sector_never_restarts_or_writes(self):
        with patch.object(module,'verify_env'),patch.object(module,'inspect'),\
             patch.object(module,'latest_backup'),patch.object(module,'node_mode',return_value=1) as node,\
             patch.object(module,'config_copy_from_container') as copy,\
             patch.object(module,'prepare_marker') as marker,\
             patch.object(module,'restart_and_wait') as restart:
            with self.assertRaisesRegex(module.Stop,'PAIRWISE_SECTOR_PREFLIGHT_FAILED'):
                module.run()
        node.assert_called_once_with('sector-preflight')
        copy.assert_not_called();marker.assert_not_called();restart.assert_not_called()

    def test_verified_management_uses_bearer_only_no_restart(self):
        with patch.object(module,'verify_env'),patch.object(module,'inspect'),\
             patch.object(module,'latest_backup'),patch.object(module,'node_mode',side_effect=[0,0,0]) as node,\
             patch.object(module,'config_copy_from_container') as copy,\
             patch.object(module,'prepare_marker') as marker,\
             patch.object(module,'restart_and_wait') as restart:
            module.run()
        self.assertEqual([c.args[0] for c in node.call_args_list],['sector-preflight','verify','clients'])
        copy.assert_not_called();marker.assert_not_called();restart.assert_not_called()

    def test_bearer_check_failure_does_not_open_basic_window(self):
        with patch.object(module,'verify_env'),patch.object(module,'inspect'),\
             patch.object(module,'latest_backup'),patch.object(module,'node_mode',side_effect=[0,1]) as node,\
             patch.object(module,'config_copy_from_container') as copy,\
             patch.object(module,'prepare_marker') as marker:
            with self.assertRaisesRegex(module.Stop,'BEARER_RECHECK_FAILED'):
                module.run()
        self.assertEqual([c.args[0] for c in node.call_args_list],['sector-preflight','verify'])
        copy.assert_not_called();marker.assert_not_called()

if __name__=='__main__':unittest.main()
