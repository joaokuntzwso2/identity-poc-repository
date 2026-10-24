"""v3.7: only transient local sidecar startup failures are retried."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'scripts/wso2/sector-sidecar-bootstrap.py'
spec=importlib.util.spec_from_file_location('sector_sidecar_v37',PATH)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class Readiness(unittest.TestCase):
    def files(self, d):
        path=Path(d)
        for brand in mod.HOSTS:
            (path/(brand+'.json')).write_text(json.dumps([brand+'-web',brand+'-mobile']))
        return path
    def reply(self,code,body=''):
        return SimpleNamespace(returncode=code, stdout=body, stderr='not disclosed')
    def test_retry_connection_refused_then_validate_both_brands(self):
        with tempfile.TemporaryDirectory() as d:
            sector=self.files(d); calls=[]
            def c(*parts,**kwargs):
                calls.append((parts,kwargs))
                brand='aurora' if 'aurora-sector.identity.test' in parts[-1] else 'brisa'
                if len(calls)==1:return self.reply(7)
                return self.reply(0,(sector/(brand+'.json')).read_text())
            with patch.object(mod,'SECTOR',sector),patch.object(mod,'cmd',side_effect=c),patch.object(mod.time,'sleep',return_value=None):
                mod.host_https_proof()
            self.assertEqual(len(calls),3)
            self.assertTrue(all(x[1].get('ok') is False for x in calls))
            self.assertTrue(all('--cacert' in x[0] for x in calls))
            self.assertTrue(all('--connect-to' in x[0] for x in calls))
    def test_cert_failure_never_retried(self):
        with tempfile.TemporaryDirectory() as d:
            sector=self.files(d)
            with patch.object(mod,'SECTOR',sector),patch.object(mod,'cmd',return_value=self.reply(60)) as c,patch.object(mod.time,'sleep') as s:
                with self.assertRaisesRegex(mod.Stop,'CURL_EXIT_60'):mod.host_https_proof()
            c.assert_called_once();s.assert_not_called()
    def test_http_404_never_retried(self):
        with tempfile.TemporaryDirectory() as d:
            sector=self.files(d)
            with patch.object(mod,'SECTOR',sector),patch.object(mod,'cmd',return_value=self.reply(22)) as c,patch.object(mod.time,'sleep') as s:
                with self.assertRaisesRegex(mod.Stop,'CURL_EXIT_22'):mod.host_https_proof()
            c.assert_called_once();s.assert_not_called()
    def test_http_200_with_wrong_callback_list_fails(self):
        with tempfile.TemporaryDirectory() as d:
            sector=self.files(d)
            with patch.object(mod,'SECTOR',sector),patch.object(mod,'cmd',return_value=self.reply(0,'["wrong"]')) as c:
                with self.assertRaisesRegex(mod.Stop,'DOCUMENT_MISMATCH_aurora'):mod.host_https_proof()
            c.assert_called_once()
    def test_bound_timeout_does_not_loop_forever(self):
        with tempfile.TemporaryDirectory() as d:
            sector=self.files(d)
            fake_time=SimpleNamespace(monotonic=iter([100,100,102]).__next__,sleep=lambda _:None)
            with patch.object(mod,'SECTOR',sector),patch.object(mod,'cmd',return_value=self.reply(7)) as c,patch.object(mod,'time',fake_time):
                with self.assertRaisesRegex(mod.Stop,'NOT_READY_aurora_CURL_EXIT_7'):mod.host_https_proof(max_wait_seconds=1)
            self.assertEqual(c.call_count,2)
    def test_transport_failure_never_imports_wso2_trust(self):
        with patch.dict(mod.os.environ,{'WSO2_LAB_CONFIRM':'CREATE_SYNTHETIC_RESOURCES'}), \
             patch.object(mod,'check'),patch.object(mod,'callbacks',return_value={}), \
             patch.object(mod,'ensure_files'),patch.object(mod,'sidecar'), \
             patch.object(mod,'host_https_proof',side_effect=mod.Stop('NOT_READY')),              patch.object(mod,'install_trust') as trust:
            with self.assertRaisesRegex(mod.Stop,'NOT_READY'):mod.ensure()
            trust.assert_not_called()
    def test_bad_wait_bounds_rejected(self):
        with self.assertRaisesRegex(mod.Stop,'WAIT_BOUND_INVALID'):mod.host_https_proof(0)
        with self.assertRaisesRegex(mod.Stop,'WAIT_BOUND_INVALID'):mod.host_https_proof(121)

if __name__=='__main__':unittest.main()
