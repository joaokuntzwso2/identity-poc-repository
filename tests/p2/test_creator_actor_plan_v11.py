import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import re
import os
import stat

src=Path(__file__).parent/'creator_actor_plan_v11.py'
if not src.is_file(): src=Path(__file__).resolve().parents[2]/'scripts/p2/creator_actor_plan_v11.py'
spec=importlib.util.spec_from_file_location('creator_actor_plan_v11',src)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
V='11111111-1111-4111-8111-111111111111'
A='22222222-2222-4222-8222-222222222222'

class TestCreatorPlan(unittest.TestCase):
    def rows(self): return [{'id':V,'name':'P2 Aurora Organization View M2M'}]
    def test_actor_absent(self):
        self.assertEqual(p.classify_actor_inventory(self.rows(),V,uuid_pattern=UUID),'CREATOR_APP_ABSENT_SEPARATE_APPROVAL_REQUIRED')
    def test_existing_creator_never_auto_adopted(self):
        rows=self.rows()+[{'id':A,'name':p.ACTOR_NAME}]
        self.assertEqual(p.classify_actor_inventory(rows,V,uuid_pattern=UUID),'CREATOR_APP_EXISTS_REQUIRES_INDEPENDENT_OWNERSHIP_RECONCILIATION')
    def test_multiple_creator_names_block(self):
        rows=self.rows()+[{'id':A,'name':p.ACTOR_NAME},{'id':'33333333-3333-4333-8333-333333333333','name':p.ACTOR_NAME}]
        with self.assertRaisesRegex(p.Block,'MULTIPLE_CREATOR_APPLICATIONS'):p.classify_actor_inventory(rows,V,uuid_pattern=UUID)
    def test_view_app_must_remain_separate(self):
        with self.assertRaisesRegex(p.Block,'VIEW_APPLICATION_MUST_NOT_BE_CREATOR'):
            p.classify_actor_inventory([{'id':V,'name':p.ACTOR_NAME}],V,uuid_pattern=UUID)
    def test_duplicate_ids_block(self):
        with self.assertRaisesRegex(p.Block,'APP_INVENTORY_DUPLICATE_ID'):
            p.classify_actor_inventory(self.rows()*2,V,uuid_pattern=UUID)
    def test_missing_view_app_blocks(self):
        with self.assertRaisesRegex(p.Block,'PINNED_VIEW_APPLICATION_NOT_IN_INVENTORY'):
            p.classify_actor_inventory([{'id':A,'name':'Other'}],V,uuid_pattern=UUID)
    def test_invalid_uuid_blocks(self):
        with self.assertRaisesRegex(p.Block,'APP_INVENTORY_ITEM_INVALID'):
            p.classify_actor_inventory(self.rows()+[{'id':'bad','name':'Other'}],V,uuid_pattern=UUID)
    def test_missing_name_blocks(self):
        with self.assertRaisesRegex(p.Block,'APP_INVENTORY_NAME_INVALID'):
            p.classify_actor_inventory(self.rows()+[{'id':A}],V,uuid_pattern=UUID)
    def test_actor_spec_is_create_only(self):
        s=p.intended_actor_spec()
        self.assertEqual(s['authorizedScopes'],['internal_org_organization_create'])
        self.assertNotIn('internal_org_organization_view',s['authorizedScopes'])
        self.assertEqual(s['tenantDomain'],'aurora.identity.test')
        self.assertEqual(s['grantTypes'],['client_credentials'])
    def test_plan_fingerprint_stable(self):
        s=p.intended_actor_spec(); a=p.plan_fingerprint(s,'abc')
        self.assertEqual(a,p.plan_fingerprint(s,'abc'))
        self.assertNotEqual(a,p.plan_fingerprint(s,'def'))
    def test_sensitive_errors_redacted(self):
        self.assertEqual(p.safe_code('Bearer a-secret'),'ACTOR_PLAN_UNEXPECTED_FAILURE')
    def test_existing_journal_blocks(self):
        with TemporaryDirectory() as td:
            path=Path(td)/'p2-aurora-partner-create.private.json'
            path.write_text('do-not-touch')
            with self.assertRaisesRegex(p.Block,'EXISTING_PARTNER_OR_CREATOR_JOURNAL_STOP'):p.check_no_mutation_journals(Path(td))
            self.assertEqual(path.read_text(),'do-not-touch')
    def test_symlink_journal_blocks(self):
        with TemporaryDirectory() as td:
            path=Path(td)/'p2-aurora-partner-creator-bootstrap.private.json'
            path.symlink_to('/tmp/does-not-exist')
            with self.assertRaisesRegex(p.Block,'EXISTING_PARTNER_OR_CREATOR_JOURNAL_STOP'):p.check_no_mutation_journals(Path(td))

if __name__=='__main__':unittest.main()

class TestNoWritePreparation(unittest.TestCase):
    def test_prepare_uses_only_existing_readbacks_and_complete_inventory(self):
        from unittest.mock import Mock
        import types
        record={'appId':V,'rootId':A,'resourceId':'known'}
        class M:
            APP_ROOT='/t/aurora.identity.test/api/server/v1/applications'
            UUID=UUID
            secure_dir=staticmethod(lambda _:None)
            read_json_private=staticmethod(lambda _:record)
            runtime_guard=staticmethod(lambda *_:None)
            read_existing_authority_admin=staticmethod(lambda _:object())
            Http=staticmethod(lambda _:object())
            safe_private_file=staticmethod(lambda *a,**kw:None)
            inventory=staticmethod(lambda http,root,coll,admin:self_apps)
            verified_existing=staticmethod(lambda *a:{'action':'ALREADY_VERIFIED','remoteManagementWrites':0,'tokenFileReady':True,
                        'applicationFingerprint':'837c9f0ac85efca8','rootFingerprint':p.EXPECTED_FP})
        self_apps=[{'id':V,'name':'P2 Aurora Organization View M2M'}]
        def vf(mod, record):pass
        v10=types.SimpleNamespace(JOURNAL='j.json',CERT='c.pem',TOKEN='token.txt',APP_FP='837c9f0ac85efca8',ROOT_FP=p.EXPECTED_FP,
            verify_journal=vf,verify_certificate=lambda *args:None,
            api_scope_catalog=lambda *args:p.EXPECTED_CREATE_RESOURCE_FP,
            plan_cli=lambda *args:{'action':'CREATE'})
        with TemporaryDirectory() as td:
            output=p.prepare(Path(td),Path(td),v10,M())
        self.assertEqual(output['code'],'CREATOR_APP_ABSENT_SEPARATE_APPROVAL_REQUIRED')
        self.assertEqual(output['managementWrites'],0)
        self.assertFalse(output['actorExisting'])

    def test_create_resource_drift_rejected_before_plan(self):
        from unittest.mock import patch
        import types
        class M:
            APP_ROOT='/t/aurora.identity.test/api/server/v1/applications'
            UUID=UUID
            secure_dir=staticmethod(lambda _:None)
            read_json_private=staticmethod(lambda _: {'appId':V, 'rootId':A, 'resourceId':'known'})
            runtime_guard=staticmethod(lambda *args:None)
            read_existing_authority_admin=staticmethod(lambda _:object())
            Http=staticmethod(lambda _:object())
            safe_private_file=staticmethod(lambda *a,**kw:None)
            verified_existing=staticmethod(lambda *args:{'action':'ALREADY_VERIFIED','remoteManagementWrites':0,'tokenFileReady':True,
                        'applicationFingerprint':'837c9f0ac85efca8','rootFingerprint':p.EXPECTED_FP})
            inventory=staticmethod(lambda *a: [_ for _ in ()])
        v10=types.SimpleNamespace(JOURNAL='j.json',CERT='c.pem',TOKEN='t.txt',APP_FP='837c9f0ac85efca8',ROOT_FP=p.EXPECTED_FP,
            verify_journal=lambda *args:None,verify_certificate=lambda *args:None,
            api_scope_catalog=lambda *args:'new_resource',plan_cli=lambda *args:self.fail('SHOULD NOT RUN PLAN'))
        with TemporaryDirectory() as td:
            with self.assertRaisesRegex(p.Block,'CREATOR_SCOPE_RESOURCE_FINGERPRINT_DRIFT'):
                p.prepare(Path(td),Path(td),v10,M())
