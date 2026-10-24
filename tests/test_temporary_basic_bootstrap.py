#!/usr/bin/env python3
"""Offline regression tests for non-destructive repeatable config windows."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
PACKAGE_SOURCE=ROOT/'temporary-basic-bootstrap.py'
INSTALLED_SOURCE=ROOT/'scripts/wso2/temporary-basic-bootstrap.py'
SOURCE=INSTALLED_SOURCE if INSTALLED_SOURCE.is_file() else PACKAGE_SOURCE
spec=importlib.util.spec_from_file_location('temporary_basic_bootstrap_v32',SOURCE)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class RecoverySnapshots(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.private=Path(self.tmp.name)/'private'
        self.patches=[
            patch.object(module,'PRIVATE',self.private),
            patch.object(module,'MARKER',self.private/'recovery.json'),
            patch.object(module,'ORIGINAL',self.private/'original-deployment.toml'),
        ]
        for p in self.patches:
            p.start();self.addCleanup(p.stop)
        self.raw=b'[server]\nhostname = "localhost"\n'

    def test_new_snapshot_is_versioned_private_and_hashed(self):
        module.prepare_marker(self.raw)
        record=json.loads(module.MARKER.read_text())
        self.assertEqual(record['schemaVersion'],2)
        self.assertRegex(record['originalFile'],r'^original-deployment-[0-9a-f]{24}\.toml$')
        path=module.PRIVATE/record['originalFile']
        self.assertEqual(path.read_bytes(),self.raw)
        self.assertEqual(record['originalSha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(module.MARKER.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(module.PRIVATE.stat().st_mode),0o700)

    def test_legacy_v1_backup_remains_untouched(self):
        self.private.mkdir()
        module.ORIGINAL.write_bytes(b'earlier original')
        module.prepare_marker(self.raw)
        self.assertEqual(module.ORIGINAL.read_bytes(),b'earlier original')
        self.assertNotEqual(module.PRIVATE/json.loads(module.MARKER.read_text())['originalFile'],module.ORIGINAL)

    def test_two_sequential_runs_do_not_reuse_same_snapshot(self):
        module.prepare_marker(self.raw)
        first=json.loads(module.MARKER.read_text())['originalFile']
        module.MARKER.unlink()  # successful recovery would do this, never a remote write here
        module.prepare_marker(b'[server]\nmode="new"\n')
        second=json.loads(module.MARKER.read_text())['originalFile']
        self.assertNotEqual(first,second)
        self.assertEqual((self.private/first).read_bytes(),self.raw)
        self.assertEqual((self.private/second).read_bytes(),b'[server]\nmode="new"\n')

    def _offline_recover(self,expected):
        capture=io.StringIO()
        with patch.object(module,'inspect',return_value={}), \
             patch.object(module,'write_container_config') as write, \
             patch.object(module,'restart_and_wait') as restart, \
             patch.object(module,'config_copy_from_container',return_value=expected), \
             contextlib.redirect_stdout(capture):
            module.recover()
        write.assert_called_once_with(expected)
        restart.assert_called_once()
        self.assertIn('ORIGINAL_RESTORED',capture.getvalue())

    def test_recover_v2_and_retain_immutable_backup(self):
        module.prepare_marker(self.raw)
        snapshot=self.private/json.loads(module.MARKER.read_text())['originalFile']
        self._offline_recover(self.raw)
        self.assertFalse(module.MARKER.exists())
        self.assertEqual(snapshot.read_bytes(),self.raw)

    def test_recover_existing_schema_v1(self):
        self.private.mkdir()
        module.ORIGINAL.write_bytes(self.raw)
        module.MARKER.write_text(json.dumps({
            'schemaVersion':1,'container':module.CONTAINER,'config':module.CONFIG,
            'originalSha256':hashlib.sha256(self.raw).hexdigest()
        }))
        self._offline_recover(self.raw)
        self.assertFalse(module.MARKER.exists())
        self.assertEqual(module.ORIGINAL.read_bytes(),self.raw)

    def test_pending_marker_refuses_new_snapshot(self):
        module.prepare_marker(self.raw)
        files=set(p.name for p in self.private.iterdir())
        with self.assertRaisesRegex(module.Stop,'RECOVERY_MARKER_EXISTS'):
            module.prepare_marker(self.raw)
        self.assertEqual(set(p.name for p in self.private.iterdir()),files)

    def test_corrupted_snapshot_stops_before_remote_calls(self):
        module.prepare_marker(self.raw)
        path=self.private/json.loads(module.MARKER.read_text())['originalFile']
        path.write_bytes(b'tampered')
        with patch.object(module,'inspect',return_value={}), \
             patch.object(module,'write_container_config') as write:
            with self.assertRaisesRegex(module.Stop,'RECOVERY_MARKER_INTEGRITY_FAILURE'):
                module.recover()
        write.assert_not_called()
        self.assertTrue(module.MARKER.exists())

    def test_invalid_snapshot_path_stops_without_remote_calls(self):
        module.prepare_marker(self.raw)
        record=json.loads(module.MARKER.read_text())
        record['originalFile']='../../deployment.toml'
        module.MARKER.write_text(json.dumps(record))
        with patch.object(module,'inspect',return_value={}), \
             patch.object(module,'write_container_config') as write:
            with self.assertRaisesRegex(module.Stop,'RECOVERY_SNAPSHOT_FILENAME_INVALID'):
                module.recover()
        write.assert_not_called()

    def test_symlink_snapshot_stops_without_remote_calls(self):
        module.prepare_marker(self.raw)
        path=self.private/json.loads(module.MARKER.read_text())['originalFile']
        other=self.private/'other'
        other.write_bytes(self.raw)
        path.unlink();path.symlink_to(other)
        with patch.object(module,'inspect',return_value={}), \
             patch.object(module,'write_container_config') as write:
            with self.assertRaisesRegex(module.Stop,'RECOVERY_SNAPSHOT_MISSING_OR_SYMLINK'):
                module.recover()
        write.assert_not_called()

    def test_unsupported_schema_does_not_write(self):
        module.prepare_marker(self.raw)
        record=json.loads(module.MARKER.read_text());record['schemaVersion']=999
        module.MARKER.write_text(json.dumps(record))
        with patch.object(module,'inspect',return_value={}), \
             patch.object(module,'write_container_config') as write:
            with self.assertRaisesRegex(module.Stop,'RECOVERY_MARKER_SCHEMA_UNSUPPORTED'):
                module.recover()
        write.assert_not_called()

if __name__=='__main__':unittest.main(verbosity=2)
