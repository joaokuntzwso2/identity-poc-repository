"""Offline supply-chain contract tests (no network, no WSO2 writes)."""
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import importlib.util
spec=importlib.util.spec_from_file_location('iamctl_installer',Path(__file__).with_name('iamctl-install.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class InstallerTests(unittest.TestCase):
    def test_macos_arm64_asset_selection(self):
        assets=[{'name':'iamctl-3.0.0-linux-x64.tar.gz'},{'name':'iamctl-3.0.0-mac-arm64.tar.gz'}]
        self.assertEqual(m.select_asset(assets,'darwin','arm64')[0],assets[1])
    def test_fails_without_arm64_asset_without_optin(self):
        with self.assertRaisesRegex(m.InstallError,'NO_COMPATIBLE'):
            m.select_asset([{'name':'iamctl-3.0.0-macosx-x64.tar.gz'}],'darwin','arm64')
    def test_rosetta_optin_explicit(self):
        a={'name':'iamctl-3.0.0-macosx-x64.tar.gz'}
        self.assertEqual(m.select_asset([a],'darwin','arm64',True),(a,'x64'))
    def test_refuse_unrelated_assets(self):
        with self.assertRaises(m.InstallError):
            m.select_asset([{'name':'iamctl-2.0.0-mac-arm64.tar.gz'}],'darwin','arm64')
    def test_wrong_https_origin(self):
        for url in ('http://api.github.com/test','https://evil.example.net/test',
                    'https://attacker@api.github.com/test'):
            with self.subTest(url=url),self.assertRaises(m.InstallError):
                m.read_https(url,{'api.github.com'})
    def test_sha_required_without_release_digest(self):
        from unittest.mock import patch
        with patch.dict('os.environ',{'IAMCTL_SHA256':''}):
            with self.assertRaisesRegex(m.InstallError,'ASSET_NOT_PINNED'):
                m.expected_digest({'name':'x'})
    def test_digest_conflict_rejected(self):
        from unittest.mock import patch
        with patch.dict('os.environ',{'IAMCTL_SHA256':'a'*64}):
            with self.assertRaisesRegex(m.InstallError,'CONFLICT'):
                m.expected_digest({'name':'iamctl-3.0.0-macosx-x64.tar.gz','digest':'sha256:'+'b'*64})
    def test_reject_tar_link(self):
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w:gz') as t:
            i=tarfile.TarInfo('bin/iamctl');i.type=tarfile.SYMTYPE;i.linkname='/etc/passwd';t.addfile(i)
        with self.assertRaisesRegex(m.InstallError,'UNSAFE'):
            m._archive_entries(buf.getvalue(),'iamctl-3.0.0-mac-arm64.tar.gz')
    def test_published_macos_checksum_is_pinned(self):
        self.assertEqual(m.expected_digest({'name':'iamctl-3.0.0-macosx-x64.tar.gz',
         'digest':'sha256:fce80e096732eb09b7eaab76755b7f85351f33254a3c1dfd7448c2cf8b4d9d54'}),
         'fce80e096732eb09b7eaab76755b7f85351f33254a3c1dfd7448c2cf8b4d9d54')
    def test_published_linux_checksum_is_pinned(self):
        self.assertEqual(m.expected_digest({'name':'iamctl-3.0.0-linux-x64.tar.gz'}),
         '6788de4e5c99cd1daec71555b68e04ac80ebaddc8e86a5e2769e145d0bae3eab')
    def test_reject_release_digest_if_different_from_pinned_hash(self):
        with self.assertRaisesRegex(m.InstallError,'DISAGREES_WITH_PIN'):
            m.expected_digest({'name':'iamctl-3.0.0-linux-x64.tar.gz','digest':'sha256:'+'f'*64})
    def test_extract_executable_only(self):
        buf=io.BytesIO(); body=b'example binary data'
        with tarfile.open(fileobj=buf,mode='w:gz') as t:
            i=tarfile.TarInfo('iamctl-3.0.0/bin/iamctl');i.size=len(body);t.addfile(i,io.BytesIO(body))
            i=tarfile.TarInfo('../private');i.size=2;t.addfile(i,io.BytesIO(b'xx'))
        self.assertEqual(m._archive_entries(buf.getvalue(),'iamctl-3.0.0-mac-arm64.tar.gz'),body)

if __name__ == '__main__': unittest.main()
