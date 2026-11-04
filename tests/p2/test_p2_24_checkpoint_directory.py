import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[2] / 'scripts/p2/p2_24_checkpoint/verify.py'
spec = importlib.util.spec_from_file_location('v46', MODULE)
v46 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v46)

U1='aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
U2='bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb'
G1='cccccccc-cccc-4ccc-cccc-cccccccccccc'
G2='dddddddd-dddd-4ddd-dddd-dddddddddddd'
MEMBERS=(('operator','x','Operators'),('reviewer','x','Reviewers'))

def fixtures():
    users=[{'id':U1,'userName':'operator'}, {'id':U2,'userName':'reviewer'}]
    groups=[{'id':G1,'displayName':'Operators'}, {'id':G2,'displayName':'Reviewers'}]
    details={('Users',U1):{'id':U1,'userName':'operator','active':False,'roles':[]},
             ('Users',U2):{'id':U2,'userName':'reviewer','active':False,'roles':[]},
             ('Groups',G1):{'id':G1,'displayName':'Operators','members':[{'value':U1}]},
             ('Groups',G2):{'id':G2,'displayName':'Reviewers','members':[{'value':U2}]}}
    return users,groups,details

class Tests(unittest.TestCase):
    def run_audit(self, edit=None):
        u,g,d=fixtures()
        if edit: edit(u,g,d)
        return v46.check_directory(u,g,lambda k,i:d[(k,i)],MEMBERS)
    def assert_rejected(self, edit):
        with self.assertRaises(v46.AuditBlocked):self.run_audit(edit)
    def test_exact(self):
        result=self.run_audit()
        self.assertEqual(result['disabledUsersVerified'],2)
        self.assertEqual(result['exactMembershipsVerified'],2)
    def test_extra_unrelated_accounts_allowed(self):
        self.run_audit(lambda u,g,d: u.append({'id':'eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee','userName':'other'}))
    def test_missing_user_blocked(self):
        self.assert_rejected(lambda u,g,d:u.pop())
    def test_duplicate_group_blocked(self):
        self.assert_rejected(lambda u,g,d:g.append(dict(g[0])))
    def test_enabled_user_blocked(self):
        self.assert_rejected(lambda u,g,d:d[('Users',U1)].update(active=True))
    def test_roles_blocked(self):
        self.assert_rejected(lambda u,g,d:d[('Users',U1)].update(roles=[{'value':'admin'}]))
    def test_wrong_group_membership_blocked(self):
        self.assert_rejected(lambda u,g,d:d[('Groups',G1)]['members'][0].update(value=U2))
    def test_extra_group_member_blocked(self):
        self.assert_rejected(lambda u,g,d:d[('Groups',G1)]['members'].append({'value':U2}))
    def test_user_detail_drift_blocked(self):
        self.assert_rejected(lambda u,g,d:d[('Users',U1)].update(userName='different'))
    def test_group_detail_drift_blocked(self):
        self.assert_rejected(lambda u,g,d:d[('Groups',G1)].update(displayName='different'))
    def test_management_get_only_adapter(self):
        class API:
            def call(self,method,path):return 200, {'ok':True}, {}
        adapter=v46.OnlyGet(API())
        with self.assertRaises(v46.AuditBlocked):adapter.call('POST','/foo')
    def test_scim_get_only_adapter(self):
        class S:
            def request(self,method,path):return 200,{}
        adapter=v46.OnlyGetScim(S())
        with self.assertRaises(v46.AuditBlocked):adapter.request('POST','Users',{'x':1})
        self.assertEqual(adapter.request('GET','Users?startIndex=1&count=100')[0],200)

if __name__=='__main__':unittest.main(verbosity=2)
