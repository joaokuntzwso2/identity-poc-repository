import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

FILE=Path(__file__).resolve().parents[1]/'restart.py'
spec=importlib.util.spec_from_file_location('restart_v10_bff',FILE)
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class Safety(unittest.TestCase):
    def test_correct_process(self):
        with patch.object(r,'REPO',Path('/repo')):
            self.assertTrue(r.recognized_process(pid=123,pids={123},owner=os.getuid(),
                comm='node',args='node services/identity-bff/src/server.js',cwd='/repo'))
    def test_refuse_other_port_owner(self):
        with patch.object(r,'REPO',Path('/repo')):
            self.assertFalse(r.recognized_process(pid=123,pids={124},owner=os.getuid(),
                comm='node',args='node services/identity-bff/src/server.js',cwd='/repo'))
    def test_refuse_wrong_cwd(self):
        with patch.object(r,'REPO',Path('/repo')):
            self.assertFalse(r.recognized_process(pid=123,pids={123},owner=os.getuid(),
                comm='node',args='node services/identity-bff/src/server.js',cwd='/other'))
    def test_refuse_other_server(self):
        with patch.object(r,'REPO',Path('/repo')):
            self.assertFalse(r.recognized_process(pid=123,pids={123},owner=os.getuid(),
                comm='node',args='node services/identity-bff/src/other.js',cwd='/repo'))
    def test_refuse_other_uid(self):
        with patch.object(r,'REPO',Path('/repo')):
            self.assertFalse(r.recognized_process(pid=123,pids={123},owner=os.getuid()+1,
                comm='node',args='node services/identity-bff/src/server.js',cwd='/repo'))
    def test_refuse_extra_arguments(self):
        with patch.object(r,'REPO',Path('/repo')):
            self.assertFalse(r.recognized_process(pid=123,pids={123},owner=os.getuid(),
                comm='node',args='node services/identity-bff/src/server.js --other',cwd='/repo'))
    def test_refuse_without_confirmation(self):
        with patch.object(r,'inspect',return_value={'ready':True,'pid':123}):
            with patch.dict(os.environ,{'WSO2_CIAM_V10_BFF_RESTART_CONFIRM':''}):
                with patch.object(r.os,'kill') as kill:
                    with self.assertRaisesRegex(r.Refuse,'CONFIRMATION_REQUIRED'):
                        r.run('bff-restart')
                    kill.assert_not_called()
    def test_plan_never_signals(self):
        with patch.object(r,'inspect',return_value={'ready':False,'pid':None,'port4400Listening':True}):
            with patch.object(r.os,'kill') as kill:
                r.run('bff-runtime-plan')
                kill.assert_not_called()

if __name__=='__main__':unittest.main()
