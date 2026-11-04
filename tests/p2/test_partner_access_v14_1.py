"""V14.1 regression: missing sharing data stays PENDING, never access."""
from __future__ import annotations
import importlib.util
import pathlib
import re
import unittest

p = pathlib.Path(__file__).resolve().parents[2] / 'scripts/p2/partner_access_v14.py'
spec = importlib.util.spec_from_file_location('partner_access_v14_1_under_test', p)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
ROOT='10000000-0000-4000-8000-000000000001'
PARTNER='10000000-0000-4000-8000-000000000002'
APP='10000000-0000-4000-8000-000000000003'

class IDs:
    UUID=re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',re.I)
class GetOnly:
    def __init__(self,pages): self.pages=pages; self.requests=[]
    def call(self,method,path,basic=None):
        assert method=='GET'
        assert path.startswith('/t/aurora.identity.test/api/server/v1/applications/')
        self.requests.append((method,path))
        return 200,self.pages[len(self.requests)-1],None

class StartupPendingTest(unittest.TestCase):
    def test_ga_omitted_empty_envelope_cannot_be_marked_unshared(self):
        h=GetOnly([{'links':[]}])
        with self.assertRaisesRegex(v.Block,'COLLECTION_OMITTED_UNVERIFIED'):
            v.read_shares(IDs,h,None,APP)
        self.assertEqual(len(h.requests),1)
    def test_ga_omitted_collection_positive_count_cannot_be_marked_empty(self):
        with self.assertRaisesRegex(v.Block,'COLLECTION_OMITTED_UNVERIFIED'):
            v.read_shares(IDs,GetOnly([{'totalResults':2,'links':[]}]),None,APP)
    def test_explicit_total_zero_only_is_valid_empty(self):
        rows,_=v.read_shares(IDs,GetOnly([{'totalResults':0,'links':[]}]),None,APP)
        self.assertEqual(rows,[])
    def test_missing_collection_with_next_does_not_validate(self):
        nxt=f'/api/server/v1/applications/{APP}/share?limit=100&after=MTA%3D'
        with self.assertRaisesRegex(v.Block,'COLLECTION_OMITTED_UNVERIFIED'):
            v.read_shares(IDs,GetOnly([{'links':[{'rel':'next','href':nxt}]}]),None,APP)
    def test_malformed_response_remains_fatal(self):
        with self.assertRaisesRegex(v.Block,'LINKS_INVALID'):
            v.read_shares(IDs,GetOnly([{'organizations':[],'links':{}}]),None,APP)
    def test_pending_evidence_never_proves_business_auth(self):
        report=v.sharing_report(['COLLECTION_OMITTED_UNVERIFIED','NOT_SHARED'],2)
        self.assertEqual(report['status'],'PENDING')
        self.assertEqual(report['code'],'V14_SHARE_COLLECTION_UNVERIFIED_STARTUP_PENDING')
        self.assertFalse(report['businessAuthorizationVerified'])
        self.assertFalse(report['delegatedAdministrationVerified'])
        self.assertFalse(v.audit_ready(report))
        self.assertEqual(report['shareEvidenceCounts']['COLLECTION_OMITTED_UNVERIFIED'],1)
    def test_pending_even_if_one_targeted_share_is_observed(self):
        report=v.sharing_report(['TARGETED_APP_SHARE_POLICY_OBSERVED_BUSINESS_AUTH_UNTESTED',
                                 'COLLECTION_OMITTED_UNVERIFIED'],2)
        self.assertEqual(report['status'],'PENDING')
        self.assertFalse(v.audit_ready(report))
    def test_explicit_complete_no_share_is_inspected_but_not_authorized(self):
        report=v.sharing_report(['NOT_SHARED'],1)
        self.assertEqual(report['status'],'INSPECTED')
        self.assertFalse(report['businessAuthorizationVerified'])
        self.assertFalse(v.audit_ready(report))
    def test_no_apps_never_becomes_a_positive_evidence(self):
        report=v.sharing_report([],0)
        self.assertEqual(report['status'],'INSPECTED')
        self.assertEqual(report['candidateApplicationCount'],0)
        self.assertFalse(v.audit_ready(report))
    def test_broad_global_policy_with_zero_rows_is_not_unshared(self):
        self.assertEqual(v.interpret_shares([],
            {'policy':'ALL_EXISTING_AND_FUTURE_ORGS'},PARTNER,ROOT),
            'BROAD_OR_GLOBAL_SHARING_REVIEW')
    def test_global_policy_requires_valid_object(self):
        with self.assertRaisesRegex(v.Block,'GLOBAL_MODE_INVALID'):
            v.interpret_shares([],['ALL_EXISTING_AND_FUTURE_ORGS'],PARTNER,ROOT)
    def test_broad_policy_prevents_audit_even_with_targeted_other_app(self):
        report=v.sharing_report(['BROAD_OR_GLOBAL_SHARING_REVIEW',
                                 'TARGETED_APP_SHARE_POLICY_OBSERVED_BUSINESS_AUTH_UNTESTED'],2)
        self.assertFalse(v.audit_ready(report))
        self.assertFalse(report['businessAuthorizationVerified'])
    def test_targeted_readback_only_does_not_certify_business_authorization(self):
        report=v.sharing_report(['TARGETED_APP_SHARE_POLICY_OBSERVED_BUSINESS_AUTH_UNTESTED'],1)
        self.assertTrue(v.audit_ready(report))
        self.assertFalse(report['businessAuthorizationVerified'])
    def test_script_has_no_post_call(self):
        source=p.read_text()
        self.assertNotIn("http.call('POST'",source)
        self.assertNotIn("http.call('PATCH'",source)
        self.assertNotIn("http.call('DELETE'",source)
    def test_other_tenant_pagination_remains_denied(self):
        with self.assertRaisesRegex(v.Block,'FOREIGN_PATH'):
            v.next_page_href(f'/t/brisa.identity.test/api/server/v1/applications/{APP}/share?next=ABC',APP,set())

if __name__=='__main__': unittest.main()
