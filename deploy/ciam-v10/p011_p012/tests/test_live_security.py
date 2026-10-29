import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import live_security

class SecurityMatrixTests(unittest.TestCase):
    def setUp(self):
        self.valid={field:expected for _,field,expected,_ in live_security.OBSERVED}
    def test_complete_attested_browser_security_observations_pass(self):
        rows=live_security.assess(self.valid,True)
        self.assertEqual(len(rows),6)
        self.assertTrue(all(x[1]=='PASS' for x in rows))
    def test_unattested_values_cannot_pass_even_if_true(self):
        self.assertTrue(all(x[1]=='BLOCKED' for x in live_security.assess(self.valid,False)))
    def test_missing_is_blocked_not_success(self):
        self.assertEqual(live_security.assess({},True)[0][1],'BLOCKED')
    def test_wrong_http_status_fails(self):
        self.valid['callbackReplayHttp']=200
        self.assertEqual(live_security.assess(self.valid,True)[0][1],'FAIL')
    def test_boolean_does_not_pass_http_status(self):
        self.valid['logoutHttp']=True
        self.assertEqual(live_security.assess(self.valid,True)[2][1],'FAIL')
    def test_string_status_does_not_pass(self):
        self.valid['callbackReplayHttp']='400'
        self.assertEqual(live_security.assess(self.valid,True)[0][1],'FAIL')
    def test_mocked_probes_do_not_substitute_for_attestation(self):
        self.assertTrue(all(r[1]=='BLOCKED' for r in live_security.assess({'mock':True},True)))
    def test_bad_values_not_echoed_in_reasons(self):
        value={'callbackReplayHttp':'Bearer '+('X'*90)}
        self.assertNotIn('Bearer',str(live_security.assess(value,True)))
        self.assertNotIn('X'*90,str(live_security.assess(value,True)))
    def test_full_negative_matrix_cannot_be_claimed_from_subset(self):
        self.assertTrue(all(g[1]=='BLOCKED' for g in live_security.deferred()))
        self.assertGreaterEqual(len(live_security.deferred()),7)
    def test_duplicate_gate_names_refused_by_contract(self):
        ids=[r[0] for r in live_security.OBSERVED]+[r[0] for r in live_security.deferred()]
        self.assertEqual(len(ids),len(set(ids)))

if __name__=='__main__':unittest.main()
