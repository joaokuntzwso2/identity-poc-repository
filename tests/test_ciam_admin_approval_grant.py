"""Offline regression tests; no WSO2 connections or private journal access."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
import os
from unittest.mock import patch
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[1] / 'scripts/ciam-admin-approval-grant.py'
spec = importlib.util.spec_from_file_location('admin_approval_grant', SRC)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class AdminApprovalGrantTests(unittest.TestCase):
    def role(self, scopes, name='CIAM Business Administrator WEB', audience='app1', members=('u1',)):
        return {'id':'role1', 'displayName':name,
                'audience':{'value':audience, 'type':'application'},
                'permissions':[{'value':v} for v in scopes],
                'users':[{'value':v} for v in members]}

    def admin(self, obj):
        return a.validate_role(obj,role_id='role1',name='CIAM Business Administrator WEB',
                               app_id='app1',member_ids=['u1'],admin=True)

    def test_payload_contains_only_one_permission_add(self):
        self.assertEqual(a.patch_payload(),{
            'schemas':['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations':[{'op':'add','path':'permissions','value':[{'value':'ciam:cases:approve'}]}]})

    def test_only_exact_pre_and_post_states_accepted(self):
        self.assertEqual(self.admin(self.role(sorted(a.BASE))),'missing')
        self.assertEqual(self.admin(self.role(sorted(a.TARGET))),'granted')
        for scopes in ([],['ciam:cases:read'],['ciam:cases:read','ciam:cases:create'],
                       list(a.BASE)+['ciam:cases:create'],list(a.TARGET)+['extra']):
            with self.subTest(scopes=scopes), self.assertRaises(a.Stop):self.admin(self.role(scopes))

    def test_duplicate_and_malformed_permissions_refused(self):
        for vals in ([{'value':'ciam:cases:read'},{'value':'ciam:cases:read'},
                      {'value':'ciam:cases:review'}],
                     [{'display':'ciam:cases:read'},{'value':'ciam:cases:review'}],
                     ['ciam:cases:read','ciam:cases:review']):
            obj=self.role([]);obj['permissions']=vals
            with self.subTest(vals=vals),self.assertRaises(a.Stop): self.admin(obj)

    def test_role_identity_audience_and_member_integrity(self):
        for obj in (self.role(a.BASE,name='Seller'),self.role(a.BASE,audience='other'),
                    self.role(a.BASE,members=['other'])):
            with self.assertRaises(a.Stop): self.admin(obj)

    def test_nonadmin_must_keep_exact_scope_set(self):
        obj=self.role(['ciam:cases:create','ciam:cases:read'],name='CIAM Business Customer WEB')
        self.assertEqual(a.validate_role(obj,role_id='role1',name='CIAM Business Customer WEB',
                            app_id='app1',member_ids=['u1'],admin=False,
                            expected_set={'ciam:cases:create','ciam:cases:read'}),'match')
        obj['permissions'].append({'value':'ciam:cases:approve'})
        with self.assertRaises(a.Stop):a.validate_role(obj,role_id='role1',name='CIAM Business Customer WEB',
                            app_id='app1',member_ids=['u1'],admin=False,
                            expected_set={'ciam:cases:create','ciam:cases:read'})

    def test_recovery_never_repeats_ambiguous_patch(self):
        self.assertEqual(a.next_action('prepared','missing'),'patch')
        self.assertEqual(a.next_action('patch-started','granted'),'recover')
        self.assertEqual(a.next_action('verified','granted'),'skip')
        for stage,remote in (('patch-started','missing'),('verified','missing'),('prepared','granted')):
            with self.subTest(stage=stage,remote=remote),self.assertRaises(a.Stop):
                a.next_action(stage,remote)

    def test_journal_context_and_target_pinning(self):
        targets={k:{'id':'r_'+str(i),'app':'a_'+str(i)} for i,k in enumerate(a.KEYS)}
        expected=a.build_state('spec_sha','journal_sha',targets)
        a.validate_state(expected,expected)
        for f in [lambda d: d.update(specSha256='changed'),
                  lambda d: d['targets']['aurora:web'].update(roleId='changed'),
                  lambda d: d['targets']['brisa:app'].update(state='invalid')]:
            import copy
            state=copy.deepcopy(expected); f(state)
            with self.assertRaises(a.Stop): a.validate_state(state,expected)

class ReconciliationSimulationTests(unittest.TestCase):
    def run_simulation(self, fail_on=None):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)
            private=home/'private';private.mkdir()
            targets={k:{'id':'role_'+str(i), 'app':'app_'+str(i),
                        'brand':k.split(':')[0], 'channel':k.split(':')[1],
                        'members':['user_'+str(i)], 'cred':'hidden'}
                    for i,k in enumerate(a.KEYS)}
            current={k:'missing' for k in a.KEYS}
            patches=[]
            class FakeResources:
                ROOT=home
                @staticmethod
                def private_read(p, required=True):
                    return json.loads(p.read_text()) if p.exists() else None
                @staticmethod
                def atomic_save(p,state):
                    p.write_text(json.dumps(state))
            class FakePhase4:
                resources=FakeResources()
                SPEC_FILE=home/'desired.json'
                JOURNAL=home/'phase4.json'
                @staticmethod
                def execute(mode):
                    assert mode=='verify'
                    return {'stage':'CIAM_BUSINESS_V4','mode':'VERIFY',
                            'readback':'VERIFIED','businessRuntime':'NOT_TESTED'}
            def snapshot(phase4):
                return {}, {}, targets, current.copy(), object()
            def patch_role(phase4, remote, target):
                key=target['brand']+':'+target['channel'];patches.append(key)
                if key==fail_on:return 403
                current[key]='granted';return 200
            def current_admin(phase4, remote, target):
                return current[target['brand']+':'+target['channel']]
            with patch.object(a,'module_load',return_value=FakePhase4()), \
                 patch.object(a,'take_snapshot',side_effect=snapshot), \
                 patch.object(a,'hash_file',return_value='pinned'), \
                 patch.object(a,'git_clean',return_value=None), \
                 patch.object(a,'patch_role',side_effect=patch_role), \
                 patch.object(a,'read_current_admin',side_effect=current_admin), \
                 patch.dict(os.environ,{a.CONFIRM_ENV:a.CONFIRM}):
                if fail_on is None:
                    result=a.do_run('apply')
                    self.assertEqual(result['targetsVerified'],4)
                    self.assertEqual(len(patches),4)
                    self.assertEqual(set(current.values()),{'granted'})
                    state=FakeResources.private_read(private/'bootstrap-admin-approval-grant-v1.private.json')
                    self.assertEqual({v['state'] for v in state['targets'].values()},{'verified'})
                    a.do_run('apply')
                    self.assertEqual(len(patches),4,'already verified roles must never be patched twice')
                else:
                    with self.assertRaisesRegex(a.Stop,'PATCH_OUTCOME_UNCERTAIN_NO_RETRY'):
                        a.do_run('apply')
                    state=FakeResources.private_read(private/'bootstrap-admin-approval-grant-v1.private.json')
                    self.assertEqual(state['targets'][fail_on]['state'],'patch-started')
                    prior=len(patches)
                    with self.assertRaisesRegex(a.Stop,'UNCERTAIN_PREVIOUS_PATCH_REFUSE_RETRY'):
                        a.do_run('apply')
                    self.assertEqual(len(patches),prior,'ambiguous patch must not be retried')

    def test_full_four_role_recovery_and_idempotence(self):
        self.run_simulation()

    def test_http_failure_marks_uncertain_and_blocks_retry(self):
        self.run_simulation(fail_on='aurora:app')

if __name__=='__main__':unittest.main()
