"""Run with: python3 -m unittest discover -s deploy/ciam-v10/oidc/tests -v"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

BOOTSTRAP=Path(__file__).resolve().parents[1]/'bootstrap.py'
spec=importlib.util.spec_from_file_location('v10_oidc_bootstrap_for_authority_v4',BOOTSTRAP)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class VerifiedAuthorityStartup(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'authority.private.json'
        self.oidc={'tenants':{}}
        self.authority={
            'schema':'identity.wso2.ciam.v10.authority.v1',
            'base':'https://localhost:9444',
            'apiIdentifier':'https://api.ciam-v10.test/profile',
            'scope':'ciam:profile:read',
            'acceptance':'API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED',
            'tenants':{},
        }
        for brand in ('aurora','brisa'):
            clients={}
            apps={}
            for channel in ('web','app'):
                app_id=f'test-owned-{brand}-{channel}'
                clients[channel]={'id':app_id}
                apps[channel]=app_id
            self.oidc['tenants'][brand]={'clients':clients}
            self.authority['tenants'][brand]={
                'apps':apps,
                'resource':{'state':'verified'},
                'authorizations':{ch:{'state':'verified'} for ch in ('web','app')},
                'role_web':{'state':'verified'},
                'role_app':{'state':'verified'},
            }
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.authority),encoding='utf-8')
        self.path.chmod(0o600)

    def verify(self):
        return module.verified_authority_env(self.oidc,self.path)

    def test_complete_authority_installs_scoped_runtime_values(self):
        self.assertEqual(self.verify(),{
            'WSO2_AUTHORITY_OIDC_SCOPE':'ciam:profile:read',
            'WSO2_BUSINESS_API_AUDIENCE':'https://api.ciam-v10.test/profile',
        })

    def test_missing_authority_is_rejected(self):
        self.path.unlink()
        with self.assertRaisesRegex(module.Refuse,'PRIVATE_FILE_NOT_REGULAR'):
            self.verify()

    def test_drifted_scope_and_audience_are_rejected(self):
        for field,value in (('scope',''),('apiIdentifier','https://untrusted.example/'),
                            ('acceptance','APPROXIMATED'),('base','https://other.example/')):
            with self.subTest(field=field):
                original=self.authority[field]
                self.authority[field]=value
                self.save()
                with self.assertRaisesRegex(module.Refuse,'INVARIANTS_FAILED'):
                    self.verify()
                self.authority[field]=original
        self.save()

    def test_a_different_client_id_cannot_be_adopted(self):
        self.authority['tenants']['aurora']['apps']['web']='different-application'
        self.save()
        with self.assertRaisesRegex(module.Refuse,'AURORA_WEB|aurora_web'):
            self.verify()

    def test_unverified_role_or_authorization_fails(self):
        self.authority['tenants']['brisa']['role_app']['state']='planned'
        self.save()
        with self.assertRaisesRegex(module.Refuse,'brisa_app'):
            self.verify()
        self.authority['tenants']['brisa']['role_app']['state']='verified'
        self.authority['tenants']['brisa']['authorizations']['web']['state']='planned'
        self.save()
        with self.assertRaisesRegex(module.Refuse,'brisa_web'):
            self.verify()

    def test_malformed_journal_has_controlled_refusal(self):
        self.authority['tenants']['aurora']=[]
        self.save()
        with self.assertRaisesRegex(module.Refuse,'TENANT_SHAPE_INVALID'):
            self.verify()

    def test_symlink_or_world_readable_journal_refused(self):
        self.path.chmod(0o644)
        with self.assertRaisesRegex(module.Refuse,'MODE_OR_OWNER'):
            self.verify()
        self.path.chmod(0o600)
        link=self.path.with_name('authority-link.private.json')
        link.symlink_to(self.path)
        with self.assertRaisesRegex(module.Refuse,'NOT_REGULAR'):
            module.verified_authority_env(self.oidc,link)

    def test_conflicting_inherited_authority_is_refused_before_manifest(self):
        verified={
            'WSO2_AUTHORITY_OIDC_SCOPE':'ciam:profile:read',
            'WSO2_BUSINESS_API_AUDIENCE':'https://api.ciam-v10.test/profile',
        }
        for key in verified:
            with self.subTest(key=key):
                with mock.patch.dict(os.environ,{key:'wrong-value'}):
                    with mock.patch.object(module,'verified_authority_env',return_value=verified):
                        with mock.patch.object(module,'publish_bff',side_effect=AssertionError('side effect occurred')):
                            with self.assertRaisesRegex(module.Refuse,'BFF_AUTHORITY_INHERITED_CONFLICT_'):
                                module.start_bff(self.oidc,Path(self.tmp.name))

    def test_startup_refuses_bad_authority_before_manifest_side_effect(self):
        with mock.patch.object(module,'verified_authority_env',side_effect=module.Refuse('UNVERIFIED')):
            with mock.patch.object(module,'publish_bff',side_effect=AssertionError('side effect occurred')):
                with self.assertRaisesRegex(module.Refuse,'UNVERIFIED'):
                    module.start_bff(self.oidc,Path(self.tmp.name))

if __name__=='__main__':
    unittest.main()
