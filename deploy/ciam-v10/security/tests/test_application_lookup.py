"""Regression: journal identity, not internal short-name application searches."""
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bootstrap as b


class JournalLookupContract(unittest.TestCase):
    def test_four_known_tenant_channel_pairs(self):
        expected = {(t, name) for t, names in b.BRANDS.items() for name in names}
        self.assertEqual(expected, set(b._DISPLAY_NAMES))
        self.assertEqual(len(expected), 4)

    def test_no_untrusted_catalog_search_or_creation(self):
        with patch.object(b, 'home', return_value=pathlib.Path('/unused-test-home')):
            with patch.object(b, '_existing_oidc_clients', side_effect=b.GuardError('missing journal')):
                with patch.object(b, 'request') as req:
                    with self.assertRaisesRegex(b.GuardError, 'missing journal'):
                        b.apps()
                    req.assert_not_called()

    def test_unknown_visitor_cannot_select_application_by_name(self):
        self.assertNotIn('carbon.super', b.BRANDS)
        self.assertNotIn('brisa-web', b.BRANDS['aurora.identity.test'])
        self.assertNotIn('aurora-app', b.BRANDS['brisa.identity.test'])


if __name__ == '__main__':
    unittest.main()
