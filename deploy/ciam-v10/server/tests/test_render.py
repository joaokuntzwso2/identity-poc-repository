from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
import unittest
import os
import json
import tomllib

R = SourceFileLoader('render', str(Path(__file__).resolve().parents[1] / 'render.py')).load_module()
STOCK='''[server]
hostname="localhost"
node_ip="127.0.0.1"
base_path="https://$ref{server.hostname}:${carbon.management.port}"
[super_admin]
username="admin"
password="admin"
create_admin_account=true
[user_store]
type="database_unique_id"
[database.identity_db]
type="h2"
url="jdbc:h2:x"
username="x"
password="x"
[database.shared_db]
type="h2"
url="jdbc:h2:y"
username="x"
password="x"
[datasource.AgentIdentity]
id="AgentIdentity"
url="jdbc:h2:z"
username="x"
password="x"
driver="org.h2.Driver"
[keystore.primary]
file_name="wso2carbon.p12"
'''
class TestRender(unittest.TestCase):
 def test_toml(self):
  s=R.render(STOCK,'a'*64,'new-super-secret')
  data=tomllib.loads(s)
  self.assertEqual(data['server']['offset'],1)
  self.assertEqual(data['database']['identity_db']['name'],'ciam_identity')
  self.assertEqual(data['datasource']['AgentIdentity']['driver'],'org.postgresql.Driver')
  self.assertEqual(data['keystore']['primary']['file_name'],'wso2carbon.p12')
  self.assertNotIn('jdbc:h2:',s)
 def test_stock_drift_refused(self):
  with self.assertRaises(ValueError): R.render(STOCK.replace('type="h2"','type="postgre"',1),'a'*64,'secret')
 def test_private_env(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'.env';p.write_text('POSTGRES_PASSWORD='+'f'*64+'\n');os.chmod(p,0o600)
   self.assertEqual(R.env_password(p),'f'*64)
   os.chmod(p,0o644)
   with self.assertRaises(ValueError): R.env_password(p)
 def test_generate_private_mode(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a';R.create_exclusive(p,'test')
   self.assertEqual(p.stat().st_mode&0o777,0o600)
   with self.assertRaises(ValueError):R.create_exclusive(p,'repeat')
if __name__=='__main__':unittest.main()
