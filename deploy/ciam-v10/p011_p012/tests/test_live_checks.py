import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import live_checks as live

CASE_ID='12ab3456-1234-4123-8123-123456789abc'

class RoleAndResourceTests(unittest.TestCase):
    def test_valid_role(self):
        role={'id':'role1','displayName':'Customer', 'audience':{'type':'application','value':'app1'},
              'users':[{'value':'user1'}], 'permissions':[{'value':'ciam:cases:read'}]}
        self.assertTrue(live.verify_role_detail(role,role_id='role1',name='Customer',app_id='app1',
                          expected_users=['user1'],expected_scopes=['ciam:cases:read']))
    def test_cross_client_audience_denied(self):
        role={'id':'role1','displayName':'Customer','audience':{'type':'application','value':'app2'},
              'users':[{'value':'user1'}],'permissions':[{'value':'ciam:cases:read'}]}
        with self.assertRaisesRegex(live.Blocked,'AUDIENCE'):
            live.verify_role_detail(role,role_id='role1',name='Customer',app_id='app1',
                                    expected_users=['user1'],expected_scopes=['ciam:cases:read'])
    def test_missing_role_permissions_denied(self):
        role={'id':'role1','displayName':'Customer','audience':{'type':'application','value':'app1'},
              'users':[{'value':'user1'}],'permissions':[]}
        with self.assertRaisesRegex(live.Blocked,'PERMISSIONS_MISMATCH'):
            live.verify_role_detail(role,role_id='role1',name='Customer',app_id='app1',
                                    expected_users=['user1'],expected_scopes=['ciam:cases:read'])
    def test_duplicate_members_denied(self):
        role={'id':'role1','displayName':'Customer','audience':{'type':'application','value':'app1'},
              'users':[{'value':'user1'},{'value':'user1'}],'permissions':[]}
        with self.assertRaisesRegex(live.Blocked,'USERS_MISMATCH'):
            live.verify_role_detail(role,role_id='role1',name='Customer',app_id='app1',
                                    expected_users=['user1'],expected_scopes=[])
    def test_resource_owner_marker_is_not_provenance(self):
        item={'id':'resource1'}
        detail={'id':'resource1','identifier':live.PINNED_IDENTIFIER,'name':'CIAM v10 Cases API',
                'requiresAuthorization':True,'description':'ciam-v10-cases-'+'a'*32}
        import re
        self.assertEqual(live.verify_resource_detail(item,detail,['ciam:cases:read'],
               identifier=live.PINNED_IDENTIFIER,name='CIAM v10 Cases API',resource_id_validator=re.compile('.+')),'resource1')
        detail['description']='arbitrary'
        with self.assertRaisesRegex(live.Blocked,'OWNER_MARKER'):
            live.verify_resource_detail(item,detail,['ciam:cases:read'],identifier=live.PINNED_IDENTIFIER,
                                        name='CIAM v10 Cases API',resource_id_validator=re.compile('.+'))
    def test_unverified_source_blocks(self):
        with self.assertRaisesRegex(live.Blocked,'SOURCE_UNAVAILABLE'):
            live.load_cases_module('/nonexistent-ciam-repo')

class AuditLedgerTests(unittest.TestCase):
    def row(self):
        return [{'brand':'aurora','id':CASE_ID,'action':'created','actor':'a'*64,
                 'at':'2026-10-29T12:00:00Z','title':'acceptance'},
                {'brand':'aurora','id':CASE_ID,'action':'approved','actor':'b'*64,
                 'at':'2026-10-29T12:02:00Z','authTime':1793275200,
                 'assurance':'WSO2_SIGNED_TOTP_STEP_UP'}]
    def test_valid_persisted_two_actor_transition(self):
        self.assertEqual(live.verify_case_events(self.row(),CASE_ID)['transition'],'OPEN_TO_APPROVED')
    def test_missing_approval_denied(self):
        with self.assertRaisesRegex(live.Blocked,'INCOMPLETE'):
            live.verify_case_events(self.row()[:1],CASE_ID)
    def test_self_approval_denied(self):
        rows=self.row();rows[1]['actor']=rows[0]['actor']
        with self.assertRaisesRegex(live.Blocked,'ACTOR_BINDING'):
            live.verify_case_events(rows,CASE_ID)
    def test_fake_mfa_denied(self):
        rows=self.row();rows[1]['assurance']='LOCAL_FAKE_MFA'
        with self.assertRaisesRegex(live.Blocked,'ASSURANCE'):
            live.verify_case_events(rows,CASE_ID)
    def test_boolean_auth_time_denied(self):
        rows=self.row();rows[1]['authTime']=True
        with self.assertRaisesRegex(live.Blocked,'ASSURANCE'):
            live.verify_case_events(rows,CASE_ID)
    def test_event_order_denied(self):
        with self.assertRaisesRegex(live.Blocked,'ORDER'):
            live.verify_case_events(self.row()[::-1],CASE_ID)
    def test_cross_tenant_record_denied(self):
        rows=self.row();rows[0]['brand']='brisa'
        with self.assertRaisesRegex(live.Blocked,'CROSSTENANT'):
            live.verify_case_events(rows,CASE_ID)
    def test_extra_event_denied(self):
        rows=self.row();rows.append(rows[-1])
        with self.assertRaisesRegex(live.Blocked,'INCOMPLETE'):
            live.verify_case_events(rows,CASE_ID)
    def test_ledger_file_safety_and_read(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'requests-aurora.jsonl'
            p.write_text('\n'.join(json.dumps(x) for x in self.row())+'\n')
            os.chmod(p,0o600)
            self.assertEqual(len(live.read_ledger(temp)),2)
            os.chmod(p,0o644)
            with self.assertRaisesRegex(live.Blocked,'UNSAFE'):
                live.read_ledger(temp)
            os.chmod(p,0o600)
            link=Path(temp)/'requests-brisa.jsonl'
            link.symlink_to(p)
            with self.assertRaisesRegex(live.Blocked,'UNAVAILABLE'):
                live.read_ledger(temp,'brisa')
    def test_unique_directory_discovery(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp); (home/'business').mkdir()
            (home/'business'/'requests-aurora.jsonl').write_text('')
            self.assertEqual(live.discover_ledger(home),home/'business')
            (home/'business2').mkdir()
            (home/'business2'/'requests-aurora.jsonl').write_text('')
            with self.assertRaisesRegex(live.Blocked,'NOT_UNAMBIGUOUS'):
                live.discover_ledger(home)

if __name__=='__main__':unittest.main()

class MockedConfigurationTests(unittest.TestCase):
    """Controlled doubles: these tests NEVER attest real WSO2 acceptance."""
    def fixture(self, *, missing_grant=False, wrong_scope=False):
        from types import SimpleNamespace
        import re
        scopes=('ciam:cases:create','ciam:cases:read','ciam:cases:review','ciam:cases:approve')
        domains={'aurora':'aurora.identity.test','brisa':'brisa.identity.test'}
        fake=SimpleNamespace(DOMAINS=domains, API_NAME='CIAM v10 Cases API', SCOPES=scopes,
                             resources=SimpleNamespace(OWNER='labtenantadmin',ID=re.compile('^[a-z0-9]+$'),basic=lambda *x:'test-auth'))
        fake.path=lambda brand,p:'/'+brand+p
        fake.exact_resource=lambda *a: {'id':'resource1','identifier':live.PINNED_IDENTIFIER}
        fake.list_items=lambda body,*names:body
        fake.read_authorization=lambda *a: None if missing_grant else {'authorizedScopes':list(scopes)}
        fake.permission_list=lambda r:set(r['authorizedScopes'])
        fake.role_specs=lambda oidc,ids,seed,brand:iter([('web','customer','app1','Customer',['user1'],['ciam:cases:read'])])
        fake.exact_role=lambda *a:{'id':'role1'}
        def read(client,path,auth):
            if '/api-resources/resource1/scopes' in path:return list(scopes)
            if '/api-resources/resource1' in path:
                return {'id':'resource1','identifier':live.PINNED_IDENTIFIER,'name':fake.API_NAME,
                         'description':'ciam-v10-cases-'+'b'*32,'requiresAuthorization':True}
            if '/applications/' in path:
                return {'id':'app1','name':'App 1','associatedRoles':{'allowedAudience':'APPLICATION'}}
            if '/scim2/Users/' in path:return {'id':'user1','active':True}
            if '/scim2/v3/Roles/' in path:
                return {'id':'role1','displayName':'Customer','audience':{'type':'application','value':'app1'},
                        'users':[{'value':'user1'}],'permissions':[{'value': 'wrong' if wrong_scope else 'ciam:cases:read'}]}
            raise AssertionError('Unexpected mocked GET')
        fake.read=read
        t={'tenants':{k:{'owner':{'password':'FAKE_FOR_TEST_ONLY'}} for k in domains}}
        o={'tenants':{k:{'clients':{c:{'id':'app1','name':'App 1'} for c in ('web','app')}} for k in domains}}
        return fake,(t,o,{}, {}, {},'v3')
    def test_mocked_readback_positive_is_only_mocked(self):
        fake,context=self.fixture()
        row=live.independent_rbac_readback(fake,object(),context)
        self.assertEqual(row['outcome'],'PASS')
        self.assertEqual(row['runtimeAuthorization'],'NOT_TESTED_BY_MANAGEMENT_READBACK')
        self.assertEqual(row['historicalOwnership'],'BLOCKED_MISSING_JOURNAL')
    def test_missing_grant_must_block(self):
        fake,context=self.fixture(missing_grant=True)
        with self.assertRaisesRegex(live.Blocked,'AUTHORIZATION_MISSING'):
            live.independent_rbac_readback(fake,object(),context)
    def test_wrong_scim_scope_must_block(self):
        fake,context=self.fixture(wrong_scope=True)
        with self.assertRaisesRegex(live.Blocked,'PERMISSIONS_MISMATCH'):
            live.independent_rbac_readback(fake,object(),context)
