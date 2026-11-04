import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

HERE = Path(__file__).resolve()
SRC = next((p / 'scripts/p2-bootstrap-share.py' for p in HERE.parents if (p / 'scripts/p2-bootstrap-share.py').is_file()), None)
if SRC is None:
    raise RuntimeError('P224_SHARE_SOURCE_NOT_FOUND')
spec = importlib.util.spec_from_file_location('p224_share_readback_under_test', SRC)
share = importlib.util.module_from_spec(spec)
spec.loader.exec_module(share)
PARTNER = '629e590a-9072-406d-95a8-71f0cfc52cbe'
FOREIGN = '33333333-3333-4333-8333-333333333333'
ROOT = '5252717e-1024-40f0-89ee-016b513d36f3'
APP = '1b4be256-ee33-4e76-ada6-6cb3ac62fdac'
SHARED_APP = '88888888-8888-4888-8888-888888888888'

class Wire:
    def __init__(self,primary=None,secondary=None,*,secondary_status=200,post_status=200):
        self.primary = {} if primary is None else primary
        self.secondary = {'sharedApplications':[]} if secondary is None else secondary
        self.secondary_status=secondary_status
        self.post_status=post_status
        self.calls=[]
    def call(self,method,path,*,auth,payload=None,form=None):
        self.calls.append((method,path,payload))
        if method=='GET' and path.endswith('/shared-apps'):
            return self.secondary_status,self.secondary,None
        if method=='GET' and path.endswith('/share'):
            return 200,self.primary,None
        if method=='POST' and path.endswith('/share'):
            if self.post_status==200:
                self.primary = {'organizations':[{'id':PARTNER}]}
            return self.post_status,{},None
        raise AssertionError((method,path))

class ReadbackTests(unittest.TestCase):
    def inspect(self,wire):
        return share.inspect_share(wire,'Basic authorized-owner',APP,PARTNER)
    def test_primary_existing_organization_uses_single_read(self):
        w=Wire({'organizations':[{'id':PARTNER}]})
        self.assertEqual(self.inspect(w),'VERIFIED')
        self.assertEqual(len(w.calls),1)
    def test_primary_empty_array_uses_single_read(self):
        w=Wire({'organizations':[]})
        self.assertEqual(self.inspect(w),'MISSING')
        self.assertEqual(len(w.calls),1)
    def test_empty_body_requires_documented_secondary_readback(self):
        w=Wire({}, {'sharedApplications':[]})
        self.assertEqual(self.inspect(w),'MISSING')
        self.assertEqual([x[1].split('/')[-1] for x in w.calls],['share','shared-apps'])
    def test_missing_primary_orgs_but_secondary_verified(self):
        w=Wire({'links':[], 'totalResults':0}, {'sharedApplications':[{'applicationId':SHARED_APP,'organizationId':PARTNER}]})
        self.assertEqual(self.inspect(w),'VERIFIED')
    def test_secondary_two_empty_collections_are_unverified_not_success(self):
        w=Wire({}, {})
        self.assertEqual(self.inspect(w),'EMPTY_UNVERIFIED')
    def test_secondary_http_failure_never_allows_write(self):
        w=Wire({}, {}, secondary_status=403)
        with self.assertRaisesRegex(share.Stop,'SECONDARY_HTTP_403'):
            self.inspect(w)
    def test_null_primary_array_not_silently_accepted(self):
        w=Wire({'organizations':None})
        with self.assertRaisesRegex(share.Stop,'ORGANIZATIONS_SHAPE_INVALID'):
            self.inspect(w)
        self.assertEqual(len(w.calls),1)
    def test_primary_unknown_metadata_rejected(self):
        w=Wire({'unrecognized':'unexpected'})
        with self.assertRaisesRegex(share.Stop,'PRIMARY_EMPTY_SHAPE_UNVERIFIED'):
            self.inspect(w)
        self.assertEqual(len(w.calls),1)
    def test_primary_count_nonzero_rejected(self):
        w=Wire({'totalResults':1})
        with self.assertRaisesRegex(share.Stop,'PRIMARY_EMPTY_COUNT_CONFLICT'):
            self.inspect(w)
        self.assertEqual(len(w.calls),1)
    def test_global_sharing_mode_denied_even_if_secondary_empty(self):
        w=Wire({'sharingMode':{'policy':'ALL_EXISTING_AND_FUTURE_ORGS'}})
        with self.assertRaisesRegex(share.Stop,'ALL_ORGS'):
            self.inspect(w)
        self.assertEqual(len(w.calls),1)
    def test_next_page_never_interpreted_as_absent(self):
        w=Wire({'links':[{'rel':'next','href':'?after=X'}]})
        with self.assertRaisesRegex(share.Stop,'INVENTORY_INCOMPLETE'):
            self.inspect(w)
    def test_second_foreign_org_refuses_bounded_share(self):
        w=Wire({}, {'sharedApplications':[{'applicationId':SHARED_APP,'organizationId':FOREIGN}]})
        with self.assertRaisesRegex(share.Stop,'FOREIGN_ORGANIZATION'):
            self.inspect(w)
    def test_second_duplicate_refuses_bounded_share(self):
        w=Wire({}, {'sharedApplications':[{'applicationId':SHARED_APP,'organizationId':PARTNER},{'applicationId':'99999999-9999-4999-8999-999999999999','organizationId':PARTNER}]})
        with self.assertRaisesRegex(share.Stop,'SECONDARY_DUPLICATES'):
            self.inspect(w)
    def test_secondary_pagination_rejected(self):
        w=Wire({}, {'sharedApplications':[], 'links':[{'rel':'next','href':'?after=X'}]})
        with self.assertRaisesRegex(share.Stop,'SECONDARY_PAGINATION_UNVERIFIED'):
            self.inspect(w)
    def test_second_missing_identifiers_rejected(self):
        w=Wire({}, {'sharedApplications':[{'organizationId':PARTNER}]})
        with self.assertRaisesRegex(share.Stop,'SECONDARY_ENTRY_INVALID'):
            self.inspect(w)
    def test_second_count_mismatch_rejected(self):
        w=Wire({}, {'sharedApplications':[],'totalResults':1})
        with self.assertRaisesRegex(share.Stop,'SECONDARY_COUNT_MISMATCH'):
            self.inspect(w)
    def test_primary_only_foreign_rejected(self):
        w=Wire({'organizations':[{'id':FOREIGN}]})
        with self.assertRaisesRegex(share.Stop,'FOREIGN_ORGANIZATION'):
            self.inspect(w)
    def test_check_never_posts_when_both_ga_endpoints_are_empty_objects(self):
        with TemporaryDirectory() as tmp:
            private=Path(tmp)
            share.authority.private_write(private/'p2-bootstrap-authority.private.json',{
                'schema':'identity.wso2.p224.authority.v1','state':'verified',
                'domain':share.DOMAIN,'sourceAppId':'source_app_12345678',
                'appId':APP,'rootOrganizationId':ROOT,'marker':'p2-bootstrap-'+'a'*32
            })
            w=Wire({}, {})
            with patch.object(share.authority,'verify_app',return_value={'clientId':'c'*24,'clientSecret':'s'*24}),patch.object(share,'read_partner',return_value=None):
                result=share.reconcile(w,private,'Basic owner','source_app_12345678',PARTNER,False)
            self.assertEqual(result['state'],'EMPTY_UNVERIFIED')
            self.assertEqual(result['remoteWrites'],0)
            self.assertTrue(all(method=='GET' for method,_,_ in w.calls))
            self.assertFalse((private/'p2-bootstrap-share.private.json').exists())
    def test_automatic_reconcile_uses_secondary_for_safe_empty_then_readback(self):
        with TemporaryDirectory() as tmp:
            private=Path(tmp)
            share.authority.private_write(private/'p2-bootstrap-authority.private.json',{
                'schema':'identity.wso2.p224.authority.v1','state':'verified',
                'domain':share.DOMAIN,'sourceAppId':'source_app_12345678',
                'appId':APP,'rootOrganizationId':ROOT,'marker':'p2-bootstrap-'+'a'*32
            })
            w=Wire({}, {'sharedApplications':[]})
            with patch.object(share.authority,'verify_app',return_value={'clientId':'c'*24,'clientSecret':'s'*24}),patch.object(share,'read_partner',return_value=None):
                result=share.reconcile(w,private,'Basic owner','source_app_12345678',PARTNER,True,sleep=lambda _:None)
            self.assertEqual(result['state'],'VERIFIED')
            self.assertEqual(sum(m=='POST' for m,_,_ in w.calls),1)
            self.assertEqual(share.authority.private_read(private/'p2-bootstrap-share.private.json')['state'],'verified')

if __name__=='__main__':unittest.main()
