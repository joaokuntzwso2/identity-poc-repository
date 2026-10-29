"""Noninteractive read-only identity-verify compatibility pin safety tests."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import cli

GUARD="""
import os

def context():
    version='v2'
    if version == 'v2' and os.getenv('WSO2_CIAM_V10_ROLE_V2_CONFIRM') != 'MATCH_TEST_PIN':
        raise ValueError('confirmation required')
"""

class ReadOnlyIdentityEnvironmentTests(unittest.TestCase):
    def fixture(self,content):
        folder=tempfile.TemporaryDirectory()
        root=Path(folder.name)
        target=root/'deploy/ciam-v10/identities/bootstrap.py'
        target.parent.mkdir(parents=True)
        target.write_text(content)
        return folder,root,target
    def test_single_guard_creates_scoped_copy_only(self):
        folder,root,_=self.fixture(GUARD)
        with folder,patch.object(cli,'REPO',root),patch.dict(os.environ,{'WSO2_CIAM_V10_ROLE_V2_CONFIRM':''}):
            original=dict(os.environ)
            env=cli.read_only_identity_verify_env()
            self.assertEqual(env['WSO2_CIAM_V10_ROLE_V2_CONFIRM'],'MATCH_TEST_PIN')
            self.assertEqual(dict(os.environ),original)
    def test_missing_source_refuses(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(cli,'REPO',Path(tmp)):
            self.assertIsNone(cli.read_only_identity_verify_env())
    def test_inherited_conflict_refuses(self):
        folder,root,_=self.fixture(GUARD)
        with folder,patch.object(cli,'REPO',root),patch.dict(os.environ,{'WSO2_CIAM_V10_ROLE_V2_CONFIRM':'WRONG'}):
            self.assertIsNone(cli.read_only_identity_verify_env())
    def test_no_guard_refuses(self):
        folder,root,_=self.fixture("def context(): return 'v2'\n")
        with folder,patch.object(cli,'REPO',root):
            self.assertIsNone(cli.read_only_identity_verify_env())
    def test_multiple_guards_refuses(self):
        more="""    if version == 'v2' and os.getenv('WSO2_CIAM_V10_ROLE_V2_CONFIRM') != 'DIFFERENT':
        raise ValueError('second')
"""
        folder,root,_=self.fixture(GUARD+more)
        with folder,patch.object(cli,'REPO',root):
            self.assertIsNone(cli.read_only_identity_verify_env())
    def test_symlink_source_refuses(self):
        folder,root,target=self.fixture(GUARD)
        with folder,patch.object(cli,'REPO',root):
            target.unlink()
            real=root/'source.py'; real.write_text(GUARD)
            target.symlink_to(real)
            self.assertIsNone(cli.read_only_identity_verify_env())
    def test_no_write_commands_or_global_flag(self):
        source=Path(cli.__file__).read_text()
        self.assertIn("[sys.executable,script,action],env=verify_env",source)
        self.assertIn("('CASE_RESOURCE_ROLE_READBACK'",source)
        self.assertIn("'verify'",source)

if __name__=='__main__':unittest.main()
