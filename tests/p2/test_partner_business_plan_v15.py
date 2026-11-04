import importlib.util, tempfile, unittest
from pathlib import Path
SRC=Path(__file__).resolve().parents[2]/'scripts/p2/partner_business_plan_v15.py'
spec=importlib.util.spec_from_file_location('v15',SRC)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
P='aaaa0000-0000-4000-8000-000000000001'
R='bbbb0000-0000-4000-8000-000000000002'
A='cccc0000-0000-4000-8000-000000000003'
B='dddd0000-0000-4000-8000-000000000004'
def uid(x):
 import re
 return type(x) is str and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',x) is not None
class TestV15(unittest.TestCase):
 def shape(self,doc):return v.shape(doc,uid,P,R)
 def test_omitted(self):self.assertEqual(self.shape({}),'COLLECTION_OMITTED_UNVERIFIED')
 def test_null(self):self.assertEqual(self.shape({'sharedApplications':None}),'COLLECTION_OMITTED_UNVERIFIED')
 def test_empty(self):self.assertEqual(self.shape({'sharedApplications':[]}), 'EXPLICIT_EMPTY_MAPPING_POLICY_UNVERIFIED')
 def test_partner(self):self.assertEqual(self.shape({'sharedApplications':[{'organizationId':P,'applicationId':A}]}),'PARTNER_REFERENCE_POLICY_UNVERIFIED')
 def test_partner_foreign(self):self.assertEqual(self.shape({'sharedApplications':[{'organizationId':P,'applicationId':A},{'organizationId':B,'applicationId':A}]}),'PARTNER_AND_OTHER_ORG_REFERENCE_REVIEW')
 def test_foreign(self):self.assertEqual(self.shape({'sharedApplications':[{'organizationId':B,'applicationId':A}]}),'OTHER_ORG_REFERENCE_NO_PARTNER_PROOF')
 def test_no_root(self):
  with self.assertRaisesRegex(v.Block,'ROOT_REFERENCE_BLOCKED'):self.shape({'sharedApplications':[{'organizationId':R,'applicationId':A}]})
 def test_invalid_doc(self):
  self.assertEqual(self.shape([]),'COLLECTION_SCHEMA_UNVERIFIED')
 def test_invalid_rows(self):
  for x in (False,{},'str'):
   self.assertEqual(self.shape({'sharedApplications':x}),'COLLECTION_SCHEMA_UNVERIFIED')
  for x in ([None],[{'organizationId':'not-id','applicationId':A}],list(range(1001))):
   with self.subTest(x=str(x)[:30]),self.assertRaises(v.Block):self.shape({'sharedApplications':x})
 def test_duplicate(self):
  r={'organizationId':P,'applicationId':A}
  with self.assertRaisesRegex(v.Block,'DUPLICATE'):self.shape({'sharedApplications':[r,r]})
 def test_distinct_apps_valid(self):
  self.assertEqual(self.shape({'sharedApplications':[{'organizationId':P,'applicationId':A},{'organizationId':P,'applicationId':B}]}),'PARTNER_REFERENCE_POLICY_UNVERIFIED')
 def test_report_never_grants(self):
  rep=v.report({'candidateApplicationCount':4},['PARTNER_REFERENCE_POLICY_UNVERIFIED','COLLECTION_OMITTED_UNVERIFIED'],False)
  self.assertEqual(rep['managementWrites'],0)
  self.assertIs(rep['businessAuthorizationVerified'],False)
  self.assertIs(rep['delegatedAdministrationVerified'],False)
  self.assertEqual(rep['status'],'PENDING')
  self.assertEqual(rep['candidateApplicationCount'],4)
 def test_collision_is_not_adoption(self):
  rep=v.report({'candidateApplicationCount':4},[],True)
  self.assertTrue(rep['dedicatedAppNameAlreadyExists'])
  self.assertEqual(rep['status'],'PENDING')
 def test_command_refuses_other(self):
  for args in (['apply'],['share'],['audit'],[],['status','apply']):
   with self.assertRaises(v.Block):v.main(args)
 def test_safe_error(self):
  self.assertEqual(v.safe_code(Exception('Authorization: secret')),'V15_READBACK_UNAVAILABLE')
  self.assertEqual(v.safe_code(v.Block('V15_UNVERIFIED')),'V15_UNVERIFIED')
if __name__=='__main__':unittest.main()
