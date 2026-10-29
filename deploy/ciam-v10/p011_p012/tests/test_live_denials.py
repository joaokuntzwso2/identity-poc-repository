import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import live_denials

class LiveNegativeGateTests(unittest.TestCase):
    def test_complete_real_status_matrix(self):
        values={field: status for _,field,status in live_denials.REQUIRED}
        rows=live_denials.assess(values, True)
        self.assertEqual(len(rows),11)
        self.assertTrue(all(r[1]=='PASS' for r in rows))
    def test_mock_or_stale_evidence_never_passes(self):
        values={field: status for _,field,status in live_denials.REQUIRED}
        self.assertTrue(all(r[1]=='BLOCKED' for r in live_denials.assess(values, False)))
    def test_wrong_status_is_fail_but_missing_is_blocked(self):
        rows=live_denials.assess({'duplicateApprovalHttp':202}, True)
        self.assertIn(('LIVE_DUPLICATE_APPROVAL_DENIAL','FAIL',409,'LIVE_DENIAL_HTTP_MISMATCH'),rows)
        self.assertTrue(any(r[1]=='BLOCKED' for r in rows))
    def test_integer_not_boolean_and_not_text(self):
        self.assertIn(('LIVE_CUSTOMER_APPROVAL_DENIAL','FAIL',403,'LIVE_DENIAL_HTTP_MISMATCH'),
            live_denials.assess({'customerApprovalHttp':True},True))
        self.assertIn(('LIVE_CUSTOMER_APPROVAL_DENIAL','FAIL',403,'LIVE_DENIAL_HTTP_MISMATCH'),
            live_denials.assess({'customerApprovalHttp':'403'},True))
    def test_sensitive_untrusted_values_never_echoed(self):
        row=live_denials.assess({'customerApprovalHttp':'Bearer '+'X'*90},True)
        self.assertNotIn('Bearer',str(row))
        self.assertNotIn('X'*90,str(row))
    def test_immutable_approved_scope(self):
        self.assertEqual({x[0] for x in live_denials.REQUIRED}.__len__(),11)
        self.assertEqual(len({x[1] for x in live_denials.REQUIRED}),11)
