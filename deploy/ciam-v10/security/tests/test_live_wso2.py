"""LIVE management integration gate: explicitly opt in, never substitutes for sign-in tests.

Run ONLY on an operator's real GA v10 Docker host with private journals and
Google credentials: MAGALU_LIVE_WSO2=YES_REAL_GA ... python3 -m unittest ...
"""
import os
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'cli.py'

@unittest.skipUnless(os.environ.get('MAGALU_LIVE_WSO2') == 'YES_REAL_GA',
                     'LIVE_WSO2_NOT_CONNECTED_OR_NOT_EXPLICITLY_APPROVED')
class RealManagementReadback(unittest.TestCase):
    def test_real_7_3_tenants_and_four_sequences(self):
        # This is a real HTTPS+Docker readback, not a fake transport.
        p = subprocess.run([sys.executable, str(SCRIPT), 'verify'],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, 'WSO2 management readback failed; see private operator logs')
        self.assertIn('MANAGEMENT_READBACK', p.stdout)
        self.assertIn('FOUR_SEQUENCE_READBACK', p.stdout)
        self.assertIn('NOT_LIVE_CHALLENGE_TESTED', p.stdout)

if __name__ == '__main__': unittest.main()
