from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SRC=Path(__file__).resolve().parents[1]/'scripts/p117-auto-rehearsal.py'
spec=importlib.util.spec_from_file_location('auto_rehearsal',SRC)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

A='https://localhost:9444/t/aurora.identity.test/oauth2/token'
B='https://localhost:9444/t/brisa.identity.test/oauth2/token'

class DiscoveryTests(unittest.TestCase):
    def test_registered_web_and_mobile_issuers(self):
        obj={'clients':{'aurora-web':{'issuer':A, 'clientId':'a-web'},'aurora-mobile':{'issuer':A},
                        'brisa-web':{'issuer':B},'brisa-mobile':{'issuer':B}}}
        assert sorted(mod.find_issuers_in_tree(obj))==sorted([('aurora',A)]*2+[('brisa',B)]*2)
    def test_array_records_with_brand(self):
        obj={'registrations':[{'brand':'aurora','issuer':A,'clientId':'a'},
                              {'brand':'brisa','issuer':B,'clientId':'b'}]}
        assert dict(mod.find_issuers_in_tree(obj))=={'aurora':A,'brisa':B}
    def test_fake_issuer_not_accepted_without_brand_context(self):
        assert mod.find_issuers_in_tree({'other':{'issuer':A}})==[]
    def test_non_https_and_unrelated_paths_not_accepted(self):
        for s in ('http://localhost:9444/t/aurora/oauth2/token','https://bad.test/x',
                  'https://bad.test/t/foo/oauth2/token?x=1',
                  'https://name:password@idp.test/t/foo/oauth2/token'):
            self.assertIsNone(mod.issuer_url(s))
    def _bff_repo(self, root, first=None, second=None, status=None):
        import json
        root=Path(root)
        (root/'scripts').mkdir()
        (root/'scripts/ciam-live-start.mjs').write_text('process.env.WSO2_BFF_PRIVATE_MANIFEST')
        d=root/'var/wso2'; d.mkdir(parents=True)
        default={'clients':{'aurora-web':{'issuer':A},'aurora-mobile':{'issuer':A},
                            'brisa-web':{'issuer':B},'brisa-mobile':{'issuer':B}}}
        for name,obj in [('identity-bff-v10.private.json', first or default),
                         ('identity-bff-wso2.private.json', second or default)]:
            (d/name).write_text(json.dumps(obj))
        if status:
            (d/'lab-wso2-linked-status.private.json').write_text(json.dumps(status))
        return d

    def test_bff_private_manifests_agree_and_status_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            d=self._bff_repo(root, status={'clients':{
                'aurora-web':{'issuer':'https://stale.test/t/aurora/oauth2/token'},
                'brisa-web':{'issuer':'https://stale.test/t/brisa/oauth2/token'}}})
            issuers, sources=mod.discover_issuers(root,{})
            self.assertEqual(issuers,{'aurora':A,'brisa':B})
            self.assertEqual(len(sources['aurora']),2)
            self.assertNotIn('lab-wso2-linked-status.private.json',str(sources))

    def test_bff_manifests_disagree_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            d=self._bff_repo(root)
            import json
            p=d/'identity-bff-wso2.private.json'
            obj=json.loads(p.read_text())
            obj['clients']['aurora-web']['issuer']='https://other.test/t/aurora/oauth2/token'
            obj['clients']['aurora-mobile']['issuer']='https://other.test/t/aurora/oauth2/token'
            p.write_text(json.dumps(obj))
            with self.assertRaisesRegex(mod.RehearsalError,'manifests disagree'):
                mod.discover_issuers(root,{})

    def test_bff_manifest_internal_ambiguity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); d=self._bff_repo(root)
            import json
            p=d/'identity-bff-v10.private.json'
            obj=json.loads(p.read_text())
            obj['clients']['aurora-mobile']['issuer']='https://other.test/t/aurora/oauth2/token'
            p.write_text(json.dumps(obj))
            with self.assertRaisesRegex(mod.RehearsalError,'contains 2 issuer candidates'):
                mod.discover_issuers(root,{})

    def test_explicit_runtime_manifest_used_even_if_default_status_differs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);d=self._bff_repo(root)
            selected=d/'identity-bff-v10.private.json'
            issuers,sources=mod.discover_issuers(root,{'WSO2_BFF_PRIVATE_MANIFEST':str(selected)})
            self.assertEqual(issuers,{'aurora':A,'brisa':B})
            self.assertEqual(len(sources['brisa']),1)

    def test_explicit_override_conflicts_and_missing_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self._bff_repo(root)
            with self.assertRaisesRegex(mod.RehearsalError,'pre-set issuer conflicts'):
                mod.discover_issuers(root,{'CIAM_AURORA_ISSUER':'https://wrong.test/t/aurora/oauth2/token'})
            with self.assertRaisesRegex(mod.RehearsalError,'missing or symlink'):
                mod.discover_issuers(root,{'WSO2_BFF_PRIVATE_MANIFEST':str(root/'missing.json')})

    def test_runtime_launcher_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self._bff_repo(root)
            (root/'scripts/ciam-live-start.mjs').write_text('console.log("not a BFF launcher")')
            with self.assertRaisesRegex(mod.RehearsalError,'launcher manifest contract'):
                mod.discover_issuers(root,{})

    def test_target_is_exact_and_nonidentity(self):
        good='postgresql://p117_migration_owner:secret@127.0.0.1:55434/ciam_migration_rehearsal_test'
        mod.validate_target(good)
        for other in ('postgresql://p117_migration_owner:secret@127.0.0.1:5432/ciam_migration_rehearsal_test',
            'postgresql://p117_migration_owner:secret@127.0.0.1:55434/identitydb',
            'postgresql://postgres:secret@127.0.0.1:55434/ciam_migration_rehearsal_test',
            'postgresql://p117_migration_owner:secret@localhost:55434/ciam_migration_rehearsal_test'):
            with self.assertRaises(mod.RehearsalError): mod.validate_target(other)
    def test_rejects_changed_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);src=p/'source';snap=p/'snapshot';src.mkdir();snap.mkdir()
            for b in ('aurora','brisa'):
                (src/f'requests-{b}.jsonl').write_bytes(b'original')
                (snap/f'requests-{b}.jsonl').write_bytes(b'original')
            mod.compare_snapshot(src,snap)
            (src/'requests-aurora.jsonl').write_bytes(b'changed')
            with self.assertRaisesRegex(mod.RehearsalError,'source changed'):
                mod.compare_snapshot(src,snap)

if __name__=='__main__': unittest.main()
