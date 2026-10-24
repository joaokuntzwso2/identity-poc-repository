"""Pure offline regressions for truststore discovery and mutation safety."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

MODULE=Path(__file__).resolve().parents[1]/'scripts/wso2/sector-sidecar-bootstrap.py'
spec=importlib.util.spec_from_file_location('sector_sidecar_v36',MODULE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def result(code=0, stdout=''):
    return SimpleNamespace(returncode=code,stdout=stdout)

class TruststoreFormatTests(unittest.TestCase):
    def mock_docker(self, config, exists):
        calls=[]
        def fake(*args,**kwargs):
            calls.append(args)
            if args[:3]==('exec',mod.CONTAINER,'cat'):
                return result(stdout=config)
            if args[:3]==('exec',mod.CONTAINER,'sh'):
                path=args[-1]
                return result(code=0 if path in exists else 1)
            raise AssertionError('UNEXPECTED_DOCKER_OPERATION:'+repr(args))
        return fake,calls

    def test_configured_pkcs12_selected(self):
        path=mod.SECURITY+'/client-truststore.p12'
        fake,calls=self.mock_docker('[truststore]\nfile_name = "client-truststore.p12"\ntype = "PKCS12"\npassword="hidden"\n', {path})
        with patch.object(mod,'docker',side_effect=fake):
            self.assertEqual(mod.truststore(),(path,'PKCS12'))
        self.assertTrue(all(x[0]=='exec' for x in calls))
        self.assertFalse(any('hidden' in repr(x) for x in calls))
    def test_configured_jks_selected(self):
        path=mod.SECURITY+'/client-truststore.jks'
        fake,calls=self.mock_docker('[truststore]\nfile_name="client-truststore.jks"\ntype="JKS"\n', {path})
        with patch.object(mod,'docker',side_effect=fake):
            self.assertEqual(mod.truststore(),(path,'JKS'))
    def test_7_3_default_p12_without_section(self):
        path=mod.SECURITY+'/client-truststore.p12'
        fake,_=self.mock_docker('[server]\nhostname="localhost"\n', {path})
        with patch.object(mod,'docker',side_effect=fake):
            self.assertEqual(mod.truststore(),(path,'PKCS12'))
    def test_both_store_files_without_configuration_fails_closed(self):
        stores={mod.SECURITY+'/'+name for name in mod.STORES}
        fake,_=self.mock_docker('[server]\n',stores)
        with patch.object(mod,'docker',side_effect=fake):
            with self.assertRaisesRegex(mod.Stop,'CLIENT_TRUSTSTORE_AMBIGUOUS'):
                mod.truststore()
    def test_explicit_missing_file_is_not_automatically_replaced_with_other(self):
        p12=mod.SECURITY+'/client-truststore.p12'
        fake,_=self.mock_docker('[truststore]\nfile_name="client-truststore.jks"\n', {p12})
        with patch.object(mod,'docker',side_effect=fake):
            with self.assertRaisesRegex(mod.Stop,'CONFIGURED_CLIENT_TRUSTSTORE_NOT_FOUND'):
                mod.truststore()
    def test_custom_path_refused_without_any_file_probe(self):
        fake,calls=self.mock_docker('[truststore]\nfile_name="../../primary.p12"\n', set())
        with patch.object(mod,'docker',side_effect=fake):
            with self.assertRaisesRegex(mod.Stop,'CUSTOM_FILENAME_NEEDS_REVIEW'):
                mod.truststore()
        self.assertEqual(len(calls),1)
    def test_type_mismatch_refused(self):
        fake,calls=self.mock_docker('[truststore]\nfile_name="client-truststore.p12"\ntype="JKS"\n',set())
        with patch.object(mod,'docker',side_effect=fake):
            with self.assertRaisesRegex(mod.Stop,'NAME_TYPE_MISMATCH'):
                mod.truststore()
        self.assertEqual(len(calls),1)
    def test_duplicate_truststore_sections_refused(self):
        fake,calls=self.mock_docker('[truststore]\nfile_name="client-truststore.jks"\n[truststore]\nfile_name="client-truststore.p12"\n',set())
        with patch.object(mod,'docker',side_effect=fake):
            with self.assertRaisesRegex(mod.Stop,'DUPLICATE_TRUSTSTORE_SECTIONS'):
                mod.truststore()
        self.assertEqual(len(calls),1)
    def test_check_probes_pkcs12_keystore_without_writes(self):
        path=mod.SECURITY+'/client-truststore.p12'
        calls=[]
        def fake(*args,**kwargs):
            calls.append(args)
            if args[:3]==('exec',mod.CONTAINER,'java'):
                return result(stdout='java.base@17\njdk.compiler@17\n')
            if args[:4]==('exec','-u','0',mod.CONTAINER):
                self.assertIn('-storetype',args)
                self.assertEqual(args[args.index('-storetype')+1],'PKCS12')
                self.assertIn(path,args)
                return result()
            raise AssertionError('UNEXPECTED_DOCKER_CALL:'+repr(args))
        with patch.object(mod,'inspect_container'),patch.object(mod,'verify_backup'),\
             patch.object(mod,'callbacks',return_value={'aurora':['a','b'],'brisa':['c','d']}),\
             patch.object(mod,'truststore',return_value=(path,'PKCS12')),\
             patch.object(mod,'cmd',return_value=result()),\
             patch.object(mod,'docker',side_effect=fake):
            output=mod.check()
        self.assertEqual(output['truststoreFile'],'client-truststore.p12')
        self.assertEqual(output['truststoreType'],'PKCS12')
        self.assertEqual(output['changes'],0)
        self.assertFalse(any(x[0] in ('restart','cp','run') for x in calls))
    def test_existing_marker_blocks_before_truststore_discovery(self):
        with patch.object(mod,'inspect_container'),patch.object(mod,'verify_backup'),\
             patch.object(mod,'TRUST_MARKER',SimpleNamespace(exists=lambda: True)),\
             patch.object(mod,'truststore') as truststore:
            with self.assertRaisesRegex(mod.Stop,'TRUST_CHANGE_PENDING'):
                mod.check()
            truststore.assert_not_called()

if __name__=='__main__':unittest.main()
