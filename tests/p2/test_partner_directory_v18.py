import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

MODULE=pathlib.Path(__file__).resolve().parents[2]/'scripts/p2/partner_directory_v18.py'
spec=importlib.util.spec_from_file_location('p2_partner_dir_v18_test',MODULE)
x=importlib.util.module_from_spec(spec)
spec.loader.exec_module(x)
U='c0acbaaf-33d0-4894-abbe-00f7669a0183'
P='bb62d208-bc8d-49e9-a924-f679cb45d117'
APP='aa62d208-bc8d-49e9-a924-f679cb45d117'

class FakeM:
    def safe_private_file(self,path,required=False):
        if required and not path.is_file():raise ValueError('absent')
        if path.is_symlink():raise ValueError('unsafe')
        return path.is_file()
    def read_json_private(self,path):return json.loads(path.read_text())
    def exclusive_json(self,path,doc):
        with path.open('x') as f:json.dump(doc,f)
        os.chmod(path,0o600)
    def replace_json(self,path,doc):
        with path.open('w') as f:json.dump(doc,f)

class FakeScim:
    def __init__(self):self.users={};self.groups={};self.writes=[];self.fail_after=None
    def request(self,method,res,body=None):
        kind='users' if res.startswith('Users') else 'groups'
        stored=getattr(self,kind)
        if method=='POST':
            self.writes.append((res,body))
            if self.fail_after == len(self.writes):raise x.Stop('V18_SCIM_POST_OUTCOME_UNCERTAIN_NO_RETRY')
            num=len(self.writes)
            uid=f'00000000-0000-4000-8000-{num:012d}'
            data=dict(body,id=uid);data.pop('password',None)
            stored[uid]=data
            return 201,{'id':uid}
        if '?' in res:
            return 200,{'totalResults':len(stored),'Resources':list(stored.values())}
        uid=res.split('/')[-1]
        return 200,stored[uid]

class TestDirectory(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.private=pathlib.Path(self.tmp.name)
        self.m=FakeM();self.scim=FakeScim()
    def test_scope_exact_set(self):
        self.assertEqual(len(x.SCOPES),6)
        self.assertEqual(len(set(x.SCOPES)),6)
        self.assertFalse(any('delete' in s or 'update' in s or 'role' in s for s in x.SCOPES))
    def test_member_templates_are_not_people(self):
        self.assertEqual(len(x.MEMBERS),2)
        self.assertTrue(all(name.startswith('p2-aurora-returns-') and '@' not in name for name,_,_ in x.MEMBERS))
    def test_user_first_post_and_readback(self):
        uid,created=x.seed_one(self.m,self.scim,self.private,'USER',x.MEMBERS[0][0],P)
        self.assertTrue(created);self.assertEqual(len(self.scim.writes),1)
        self.assertEqual(self.scim.writes[0][0],'Users')
        self.assertFalse(self.scim.writes[0][1]['active'])
        self.assertNotIn('roles',self.scim.writes[0][1]);self.assertNotIn('emails',self.scim.writes[0][1])
        record=next(self.private.glob('*.private.json'))
        self.assertEqual(json.loads(record.read_text())['state'],'VERIFIED')
        self.assertIn('initialPassword',json.loads(record.read_text()))
        self.assertNotIn('initialPassword',str((uid,created)))
    def test_user_second_run_get_only(self):
        name=x.MEMBERS[0][0]
        a=x.seed_one(self.m,self.scim,self.private,'USER',name,P)
        b=x.seed_one(self.m,self.scim,self.private,'USER',name,P)
        self.assertEqual(a[0],b[0]);self.assertFalse(b[1]);self.assertEqual(len(self.scim.writes),1)
    def test_group_first_post_and_readback(self):
        uid='00000000-0000-4000-8000-000000000053'
        result=x.seed_one(self.m,self.scim,self.private,'GROUP','AuroraReturnsOperators',P,uid)
        self.assertTrue(result[1]);self.assertEqual(len(self.scim.writes),1)
        self.assertEqual(self.scim.writes[0][1]['members'],[{'value':uid}])
    def test_group_second_run_get_only(self):
        uid='00000000-0000-4000-8000-000000000053'
        x.seed_one(self.m,self.scim,self.private,'GROUP','AuroraReturnsOperators',P,uid)
        result=x.seed_one(self.m,self.scim,self.private,'GROUP','AuroraReturnsOperators',P,uid)
        self.assertFalse(result[1]);self.assertEqual(len(self.scim.writes),1)
    def test_group_membership_drift_blocks(self):
        uid='00000000-0000-4000-8000-000000000053'
        a=x.seed_one(self.m,self.scim,self.private,'GROUP','AuroraReturnsOperators',P,uid)
        self.scim.groups[a[0]]['members']=[]
        with self.assertRaisesRegex(x.Stop,'V18_EXISTING_GROUP_MEMBERSHIP_DRIFT'):
            x.seed_one(self.m,self.scim,self.private,'GROUP','AuroraReturnsOperators',P,uid)
    def test_existing_unowned_resource_blocks(self):
        self.scim.users['00000000-0000-4000-8000-000000000098']={
            'id':'00000000-0000-4000-8000-000000000098','userName':'p2-aurora-returns-operator'}
        with self.assertRaisesRegex(x.Stop,'V18_UNOWNED_EXISTING_DIRECTORY_OBJECT'):
            x.seed_one(self.m,self.scim,self.private,'USER','p2-aurora-returns-operator',P)
        self.assertFalse(self.scim.writes)
    def test_post_exception_leaves_intent_and_never_retries(self):
        self.scim.fail_after=1
        with self.assertRaisesRegex(x.Stop,'V18_POST_OUTCOME_UNCERTAIN_NO_RETRY'):
            x.seed_one(self.m,self.scim,self.private,'USER',x.MEMBERS[0][0],P)
        self.assertEqual(len(self.scim.writes),1)
        rec=next(self.private.glob('*.json'))
        self.assertEqual(json.loads(rec.read_text())['state'],'INTENT')
        self.scim.fail_after=None
        with self.assertRaisesRegex(x.Stop,'V18_JOURNAL_REMOTE_DRIFT_OR_PENDING_NO_RETRY'):
            x.seed_one(self.m,self.scim,self.private,'USER',x.MEMBERS[0][0],P)
        self.assertEqual(len(self.scim.writes),1)
    def test_uncertain_success_does_not_auto_adopt(self):
        self.scim.fail_after=None
        uid,_=x.seed_one(self.m,self.scim,self.private,'USER',x.MEMBERS[0][0],P)
        rec=next(self.private.glob('*.json'))
        r=json.loads(rec.read_text());r['state']='INTENT';rec.write_text(json.dumps(r))
        with self.assertRaisesRegex(x.Stop,'V18_UNCERTAIN_WRITE_READBACK_ONLY_NO_RETRY'):
            x.seed_one(self.m,self.scim,self.private,'USER',x.MEMBERS[0][0],P)
        self.assertEqual(len(self.scim.writes),1)
    def test_duplicate_inventory_refused(self):
        row={'id':'00000000-0000-4000-8000-000000000098','userName':'dup'}
        self.scim.users[row['id']]=row
        class B(FakeScim):
            def request(self,method,res,body=None):
                return 200,{'totalResults':2,'Resources':[row,row]}
        with self.assertRaisesRegex(x.Stop,'V18_SCIM_ROWS_AMBIGUOUS'):
            x.full_list(B(),'Users')
    def test_incomplete_inventory_refused(self):
        class B(FakeScim):
            def request(self,method,res,body=None):
                return 200,{'totalResults':3,'Resources':[]}
        with self.assertRaisesRegex(x.Stop,'V18_SCIM_PAGINATION_INCOMPLETE'):
            x.full_list(B(),'Groups')
    def test_token_and_method_endpoint_scope_boundaries(self):
        self.assertFalse(any('shared' in s for s in x.SCOPES))
        # No live transport required for rejecting a foreign path.
        scim=x.Scim('unused',P,'x'*30,opener=object())
        for bad in ('../Brisa/Users','Users/../../scim2','Groups?role=admin','Users/%2e%2e'):
            with self.subTest(bad=bad),self.assertRaisesRegex(x.Stop,'V18_SCIM_ENDPOINT_INVALID'):
                scim.request('GET',bad)
        with self.assertRaisesRegex(x.Stop,'V18_SCIM_WRITE_BOUNDARY_INVALID'):
            scim.request('POST','Users/00000000-0000-4000-8000-000000000098',{})
    def test_no_shared_application_no_directory_write(self):
        v17=mock.Mock();v17.JOURNAL=x.V17_JOURNAL
        v17.journal_template.return_value={'state':'INTENT'}
        v17.body_for.return_value={}
        v17.reconcile_snapshot.return_value='PENDING'
        r=self.private/x.V17_JOURNAL;r.write_text(json.dumps({'state':'INTENT'}))
        result=x.bootstrap_directory(v17,self.m,None,None,None,self.private,APP,P,U)
        self.assertEqual(result['status'],'PENDING');self.assertEqual(result['managementWritesAttempted'],0)
    def test_actor_missing_no_directory_write(self):
        v17=mock.Mock();v17.JOURNAL=x.V17_JOURNAL
        v17.journal_template.return_value={'state':'VERIFIED'}
        v17.body_for.return_value={}
        v17.reconcile_snapshot.return_value='EXACT'
        (self.private/x.V17_JOURNAL).write_text(json.dumps({'state':'VERIFIED'}))
        result=x.bootstrap_directory(v17,self.m,None,None,None,self.private,APP,P,U)
        self.assertEqual(result['code'],'V18_PARTNER_SCOPED_SCIM_ACTOR_REQUIRED')
        self.assertEqual(result['managementWritesAttempted'],0)
    def test_actor_spec_blocks_wrong_tenant_before_http(self):
        record={'schema':x.ACTOR_SCHEMA,'tenant':'brisa.identity.test'}
        with self.assertRaisesRegex(x.Stop,'V18_ACTOR_SPEC_INVALID'):
            x.actor_check(self.m,None,None,record,P)
    def test_report_override_is_safe(self):
        r=x.report('VERIFIED','TEST',managementWritesAttempted=4)
        self.assertEqual(r['managementWritesAttempted'],4)
    def test_no_preapproved_role_or_person_information(self):
        source=MODULE.read_text()
        self.assertNotIn('Carbon Super',x.TENANT)
        self.assertNotIn("'internal_org_user_mgt_update'",source)
        self.assertNotIn("'internal_org_group_mgt_update'",source)
        self.assertNotIn("'email':'",source)

if __name__=='__main__':unittest.main()
