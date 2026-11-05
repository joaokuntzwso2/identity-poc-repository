import importlib.util
from pathlib import Path
import tempfile
import unittest

REVIEW = Path(__file__).resolve().parents[4] / 'scripts/magalu-integration-review.py'
spec = importlib.util.spec_from_file_location('integration_review', REVIEW)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReviewTests(unittest.TestCase):
    def apps(self, script='executeStep(1, {onSuccess: function(context){ executeStep(2,{onSuccess:function(){}}); }});'):
        return {(tenant,alias): {'authenticationSequence': {'script': script}}
                for tenant, names in [('aurora.identity.test', ['aurora-web','aurora-app']),
                                      ('brisa.identity.test', ['brisa-web','brisa-app'])]
                for alias in names}

    def test_four_apps_exact(self):
        self.assertEqual(len(m.valid_review_scripts(self.apps())), 4)

    def test_no_secrets_exported(self):
        with self.assertRaisesRegex(ValueError, 'SECRET'):
            m.valid_review_scripts(self.apps('password = "example"; '+('x'*80)))

    def test_per_tenant_script_must_match(self):
        apps=self.apps()
        apps['aurora.identity.test','aurora-app']={'authenticationSequence':{'script':'x'*90}}
        with self.assertRaisesRegex(ValueError, 'CHANNEL_SCRIPTS_DIFFER'):
            m.valid_review_scripts(apps)

    def test_deny_unexpected_tenant(self):
        apps=self.apps()
        apps['carbon.super', 'aurora-web'] = {'authenticationSequence': {'script': 'y'*70}}
        with self.assertRaisesRegex(ValueError, 'FOUR_JOURNAL'):
            m.valid_review_scripts(apps)

    def test_archived_script_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'secure.zip'
            m.write_review_zip(p, m.valid_review_scripts(self.apps()), 'var previous = true;')
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                m.write_review_zip(p, m.valid_review_scripts(self.apps()), None)

if __name__ == '__main__':unittest.main()
