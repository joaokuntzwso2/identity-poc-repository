"""Offline tests for the read-only CIAM v10 inspection module."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SRC=Path(__file__).resolve().parents[1]/'scripts'/'ciam-v10-inspect.py'
spec=importlib.util.spec_from_file_location('ciam_v10_inspect',SRC)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class FakeAPI:
    def __init__(self, pages):
        self.pages=pages
        self.calls=[]
    def get(self,path,auth=None):
        self.calls.append(('GET',path))
        return self.pages.get(path,(404,{}))

class InspectionTests(unittest.TestCase):
    def test_safe_report_file_mode(self):
        with tempfile.TemporaryDirectory() as d:
            file=m.write_json(Path(d),'report.json',{'state':'OK'})
            self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
            self.assertEqual(json.loads(file.read_text())['state'],'OK')

    def test_journal_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'secret.json'
            path.write_text('{"password":"do-not-publish"}')
            os.chmod(path,0o644)
            with self.assertRaises(m.InspectionError):
                m.safe_file(path,True)

    def test_collection_pagination_scim(self):
        pages={
            '/scim2/Users?count=100&startIndex=1':(200,{'Resources':[{'id':'a'}], 'totalResults':2}),
            '/scim2/Users?count=100&startIndex=2':(200,{'Resources':[{'id':'b'}], 'totalResults':2})}
        api=FakeAPI(pages)
        result=m.list_all(api,'/scim2/Users',None,'scim')
        self.assertEqual([v['id'] for v in result],['a','b'])
        self.assertEqual(len(api.calls),2)
        self.assertTrue(all(method=='GET' for method,path in api.calls))

    def test_collection_pagination_rejects_partial(self):
        api=FakeAPI({'/api/server/v1/applications?limit=100&offset=0':
                    (200,{'applications':[],'totalResults':3})})
        with self.assertRaises(m.InspectionError):
            m.list_all(api,'/api/server/v1/applications',None,'apps')

    def test_api_cursor_rejects_external_host(self):
        api=FakeAPI({'/api/server/v1/api-resources?limit=100':(200,{
          'APIResources':[{'id':'a'}], 'totalResults':2,
          'links':[{'rel':'next','href':'https://attacker.example/api/server/v1/api-resources?after=evil'}]})})
        with self.assertRaises(m.InspectionError):
            m.list_all(api,'/api/server/v1/api-resources',None,'apis')

    def test_oidc_reduction_does_not_export_client_secret(self):
        o=m.reduced_oidc({'clientId':'public-client-id','clientSecret':'DO_NOT_LEAK',
                          'pkce':{'mandatory':True},'subject':{'subjectType':'pairwise'},
                          'grantTypes':['authorization_code']})
        self.assertNotIn('DO_NOT_LEAK',json.dumps(o))
        self.assertEqual(o['pkceMandatory'],True)

    def test_git_dirty_becomes_issue_without_runtime(self):
        sample={'git':{'sha':'a'*40,'dirty':True},'canonicalFiles':{},'legacyFiles':[]}
        with patch.object(m,'inspect_git',return_value=sample), patch.object(m,'baseline_commands',return_value={}):
            report,sha=m.build_report('source',False,False)
        self.assertEqual(sha,'a'*40)
        self.assertIn('SOURCE_WORKTREE_DIRTY',[x['code'] for x in report['issues']])
        self.assertEqual(report['safety']['remoteWrites'],0)

    def test_pinned_connection_rejects_bad_cert_before_request(self):
        # Unit test TLS pin verification without touching network.
        class StubSocket:
            def getpeercert(self,binary_form=False):return b'bad-certificate'
            def close(self): pass
        with patch('http.client.HTTPSConnection.connect',lambda conn: setattr(conn,'sock',StubSocket())):
            conn=m.PinnedConnection(b'\x00'*32)
            with self.assertRaises(m.InspectionError):
                conn.connect()

if __name__=='__main__':
    unittest.main()
