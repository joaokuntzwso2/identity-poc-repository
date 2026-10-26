import importlib.util
import io
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[2] / 'scripts' / 'ciam-v10-acceptance.py'
spec = importlib.util.spec_from_file_location('ciam_v10_acceptance', MODULE)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceEvidenceTests(unittest.TestCase):
    def sample(self):
        return {
            'identitySource': 'WSO2_SIGNED_ID_TOKEN',
            'authenticated': True,
            'evidence': 'BFF_VALIDATED_SIGNED_ID_TOKEN',
            'csrf': 'must never be printed',
            'clients': {
                key: {
                    'configured': True, 'authenticated': True,
                    'issuer': f'https://localhost:9444/t/{domain}/oauth2/token',
                    'verifiedAt': '2026-10-26T14:30:29.159Z',
                    'subjectFingerprint': 'fingerprint-123456789',
                    'permissions': ['session:read']
                }
                for key, domain in acceptance.CLIENTS.items()
            }
        }

    def test_full_four_channel_evidence(self):
        result = acceptance.check(self.sample())
        self.assertTrue(result['passed'])
        self.assertNotIn('csrf', str(result))
        self.assertNotIn('fingerprint-123456789', str(result))

    def test_partial_aurora_only(self):
        sample = self.sample()
        for key in ('aurora-app', 'brisa-web', 'brisa-app'):
            sample['clients'][key]['authenticated'] = False
        result = acceptance.check(sample)
        self.assertFalse(result['passed'])
        self.assertTrue(result['channels']['aurora-web']['passed'])
        self.assertFalse(result['channels']['brisa-web']['passed'])

    def test_different_issuer_rejected(self):
        sample = self.sample()
        sample['clients']['brisa-app']['issuer'] = 'https://localhost:9443/t/brisa.identity.test/oauth2/token'
        self.assertFalse(acceptance.check(sample)['passed'])

    def test_missing_verified_at_rejected(self):
        sample = self.sample()
        sample['clients']['aurora-web']['verifiedAt'] = None
        self.assertFalse(acceptance.check(sample)['passed'])

    def test_non_object_rejected(self):
        with self.assertRaises(ValueError):
            acceptance.check([])


if __name__ == '__main__':
    unittest.main()
