import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE=Path(__file__).resolve().parents[1]/'scripts/wso2/sector-sidecar-bootstrap.py'
spec=importlib.util.spec_from_file_location('sector_sidecar',MODULE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class SidecarOfflineTests(unittest.TestCase):
    def test_two_distinct_hostname_vhosts(self):
        config=mod.nginx_config().decode()
        self.assertIn('server_name aurora-sector.identity.test;',config)
        self.assertIn('server_name brisa-sector.identity.test;',config)
        self.assertIn('alias /etc/nginx/sector-data/aurora.json;',config)
        self.assertIn('alias /etc/nginx/sector-data/brisa.json;',config)
        self.assertNotIn('127.0.0.1',config)
    def test_immutable_callback_file_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'sector.json'
            self.assertTrue(mod.exclusive_bytes(dest,b'["a"]'))
            self.assertFalse(mod.exclusive_bytes(dest,b'["a"]'))
            with self.assertRaisesRegex(mod.Stop,'IMMUTABLE_SECTOR_FILE_CHANGED'):
                mod.exclusive_bytes(dest,b'["b"]')
            self.assertEqual(dest.read_bytes(),b'["a"]')
    def test_check_is_readonly_when_running_environment_is_valid(self):
        with patch.object(mod,'inspect_container'),patch.object(mod,'verify_backup'),\
             patch.object(mod,'truststore',return_value=(mod.SECURITY+'/client-truststore.p12','PKCS12')),\
             patch.object(mod,'callbacks',return_value={'aurora':['a','b'],'brisa':['c','d']}),\
             patch.object(mod,'cmd') as cmd,patch.object(mod,'docker') as docker:
            cmd.return_value.returncode=0
            docker.return_value.returncode=0
            docker.return_value.stdout='jdk.compiler@17.0.1'
            result=mod.check()
            self.assertEqual(result['changes'],0)
            self.assertFalse(any(a.args and a.args[0]=='restart' for a in docker.call_args_list))
    def test_requires_explicit_write_consent_before_any_check(self):
        with patch.dict(mod.os.environ,{},clear=True),patch.object(mod,'check') as check:
            with self.assertRaisesRegex(mod.Stop,'WRITE_CONSENT_REQUIRED'):
                mod.ensure()
            check.assert_not_called()
    def test_pending_marker_blocks_before_mutation(self):
        with patch.dict(mod.os.environ,{'WSO2_LAB_CONFIRM':'CREATE_SYNTHETIC_RESOURCES'}), \
             patch.object(mod,'check',side_effect=mod.Stop('TRUST_CHANGE_PENDING_RECOVER_REQUIRED')), \
             patch.object(mod,'sidecar') as sidecar:
            with self.assertRaisesRegex(mod.Stop,'TRUST_CHANGE_PENDING_RECOVER_REQUIRED'):
                mod.ensure()
            sidecar.assert_not_called()
    def test_host_map_matches_same_stable_identity(self):
        self.assertNotEqual(mod.HOSTS['aurora'],mod.HOSTS['brisa'])
        for host in mod.HOSTS.values():
            self.assertTrue(host.endswith('.identity.test'))
            self.assertNotIn('localhost',host)

if __name__=='__main__':unittest.main()
