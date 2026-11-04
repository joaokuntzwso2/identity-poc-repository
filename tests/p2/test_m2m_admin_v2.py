"""Source-only P2.24 admin resolver regression tests. No WSO2 network."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE=Path(__file__).resolve().parents[2]/'scripts/p2/m2m_bootstrap.py'
spec=importlib.util.spec_from_file_location('p2_admin_resolver',MODULE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class AdminResolverV2(unittest.TestCase):
    def test_co_located_username_password(self):
        d={'tenants':{'aurora':{'username':'admin','password':'ok'}}}
        self.assertEqual(m.find_tenant_admin(d), [('admin@aurora.identity.test','ok')])
    def test_existing_form_is_still_supported(self):
        d={'tenants':{'aurora':{'owners':[{'username':'admin','password':'ok'}]}}}
        self.assertEqual(m.find_tenant_admin(d), [('admin@aurora.identity.test','ok')])
    def test_admin_only_password_in_known_branch(self):
        d={'tenants':{'aurora':{'admin':{'password':'ok'}}}}
        self.assertEqual(m.find_tenant_admin(d), [('admin@aurora.identity.test','ok')])
    def test_tenant_admin_password_in_known_branch(self):
        d={'tenants':{'aurora':{'tenantAdminPassword':'ok'}}}
        self.assertEqual(m.find_tenant_admin(d), [('admin@aurora.identity.test','ok')])
    def test_explicit_tenant_domain_on_object(self):
        d={'tenants':[{'domain':'aurora.identity.test','admin_password':'ok'}]}
        self.assertEqual(m.find_tenant_admin(d), [('admin@aurora.identity.test','ok')])
    def test_reject_generic_password_and_cross_tenant(self):
        for d in (
            {'tenants':{'brisa':{'admin':{'password':'wrong'}}}},
            {'tenants':{'aurora':{'member':{'password':'wrong'}}}},
            {'tenants':{'aurora':{'apps':{'adminPassword':'wrong'}}}},
            {'tenants':{'aurora':{'users':{'admin':{'password':'wrong'}}}}},
            {'tenants':{'aurora':{'username':'someone-else','password':'wrong'}}},
            {'admin':{'username':'admin','password':'carbon-super'}}):
            self.assertEqual(m.find_tenant_admin(d), [])
    def test_nested_conflicting_creds_do_not_auto_choose(self):
        d={'tenants':{'aurora':{'adminPassword':'first','admin':{'password':'second'}}}}
        with self.assertRaisesRegex(m.Block,'MULTIPLE_AURORA_ADMIN_CREDENTIALS_CONFLICT'):
            m.find_tenant_admin(d)
    def test_authority_document_resolver_deduplicates(self):
        docs=[('one',{'tenants':{'aurora':{'adminPassword':'same'}}}),
              ('two',{'tenants':{'aurora':{'admin':{'password':'same'}}}})]
        with patch.object(m,'_admin_source_documents',return_value=docs):
            self.assertEqual(m.read_admin(Path('/unused'),Path('/unused')),
                             ('admin@aurora.identity.test','same'))
    def test_absent_admin_reports_clear_block(self):
        docs=[('one',{'tenants':{'aurora':{'clientSecret':'not-admin'}}})]
        with patch.object(m,'_admin_source_documents',return_value=docs):
            with self.assertRaisesRegex(m.Block,'AURORA_ADMIN_CREDENTIAL_NOT_LOCATABLE'):
                m.read_admin(Path('/unused'),Path('/unused'))
    def test_conflicting_journals_block(self):
        docs=[('one',{'tenants':{'aurora':{'adminPassword':'one'}}}),
              ('two',{'tenants':{'aurora':{'adminPassword':'two'}}})]
        with patch.object(m,'_admin_source_documents',return_value=docs):
            with self.assertRaisesRegex(m.Block,'MULTIPLE_AURORA_ADMIN_CREDENTIALS_CONFLICT'):
                m.read_admin(Path('/unused'),Path('/unused'))
    def test_diagnostic_has_no_secret_or_credential_in_output(self):
        docs=[('one',{'tenants':{'aurora':{'admin':{'password':'very-secret'}}}})]
        with patch.object(m,'_admin_source_documents',return_value=docs):
            result=m.admin_diagnostic(Path('/unused'))
        self.assertEqual(result['sourcesExamined'],1)
        self.assertEqual(result['uniqueCandidateCount'],1)
        self.assertNotIn('very-secret',str(result))
        self.assertNotIn('password',str(result).lower().replace('namedadminpassword','').replace('explicitadminpassword','').replace('usernamepasswordpair',''))

if __name__=='__main__': unittest.main()
