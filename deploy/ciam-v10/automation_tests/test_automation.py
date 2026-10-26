import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

FILE = Path(__file__).resolve().parents[1] / 'automation.py'
SPEC = importlib.util.spec_from_file_location('v10_auto', FILE)
auto = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auto)


def approved():
    return {auto.DEPLOY_ENV:auto.DEPLOY_APPROVAL,
            auto.FRESH_ENV:auto.FRESH_APPROVAL,
            auto.ROLE_ENV:'v2', auto.V2_ENV:auto.V2_APPROVAL}


def plan():
    return {'stage':'CIAM_V10_AUTHORITY','mode':'GET_ONLY','remoteWrites':0,
            'roleApiVersion':'v2','safeToApply':True,
            'tenants':{b:{'channels':{c:{'apiAuthorization':'ABSENT','role':'ABSENT'}
                                      for c in auto.CHANNELS}}
                       for b in auto.BRANDS}}


def applied():
    return {'stage':'CIAM_V10_AUTHORITY','mode':'APPLY','roleApiVersion':'v2',
            'status':'PROVISIONING_READBACK_VERIFIED_BROWSER_NOT_TESTED',
            'tenants':{b:{c:{'authorizedScope':'READBACK_VERIFIED','roleAndUser':'READBACK_VERIFIED'}
                          for c in auto.CHANNELS} for b in auto.BRANDS}}


def reconciled():
    obj=plan();obj['mode']='READ_ONLY_RECONCILIATION'
    for brand in auto.BRANDS:
        obj['tenants'][brand]['businessAPI']='PRESENT_SCOPE_VERIFIED'
        for channel in auto.CHANNELS:
            obj['tenants'][brand]['channels'][channel]={'apiAuthorization':'SCOPE_VERIFIED','role':'PRESENT'}
    return obj


def status():
    return {'stage':'CIAM_V10_AUTHORITY_STATUS','remoteWrites':0,
            'roleApiVersion':'v2','acceptance':'API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED',
            'tenants':{b:{'resource':'verified','authorizedChannels':{c:'verified' for c in auto.CHANNELS},
                           'roleChannels':{c:'verified' for c in auto.CHANNELS}} for b in auto.BRANDS}}


class TestOrchestration(unittest.TestCase):
    def test_missing_whole_bootstrap_confirmation(self):
        with self.assertRaises(auto.Refuse):auto.verify_intent({auto.ROLE_ENV:'v2',auto.V2_ENV:auto.V2_APPROVAL})
    def test_missing_role_api_selection_no_implicit_fallback(self):
        values=approved();del values[auto.ROLE_ENV]
        with self.assertRaises(auto.Refuse):auto.verify_intent(values)
    def test_no_unapproved_v2(self):
        values=approved();del values[auto.V2_ENV]
        with self.assertRaises(auto.Refuse):auto.verify_intent(values)
    def test_fresh_confirmation_preflight(self):
        values=approved();del values[auto.FRESH_ENV]
        with self.assertRaises(auto.Refuse):auto.verify_intent(values,fresh=True)
    def test_explicit_v3_allowed_no_fallback(self):
        values=approved();values[auto.ROLE_ENV]='v3';del values[auto.V2_ENV]
        self.assertEqual(auto.verify_intent(values),'v3')
    def test_read_only_plan_missing_brand(self):
        obj=plan();del obj['tenants']['brisa']
        with self.assertRaises(auto.Refuse):auto.verify_plan(obj,'v2')
    def test_plan_never_accepts_a_write(self):
        obj=plan();obj['remoteWrites']=1
        with self.assertRaises(auto.Refuse):auto.verify_plan(obj,'v2')
    def test_wrong_role_version_refused(self):
        with self.assertRaises(auto.Refuse):auto.verify_plan(plan(),'v3')
    def test_partial_apply_refused(self):
        obj=applied();obj['tenants']['aurora']['web']['roleAndUser']='NOT_VERIFIED'
        with self.assertRaises(auto.Refuse):auto.verify_apply(obj,'v2')
    def test_removed_authorization_refused(self):
        obj=reconciled();obj['tenants']['brisa']['channels']['app']['apiAuthorization']='ABSENT'
        with self.assertRaises(auto.Refuse):auto.verify_reconcile(obj,'v2')
    def test_journal_missing_user_assignment_refused(self):
        obj=status();obj['tenants']['aurora']['roleChannels']['web']='NOT_VERIFIED'
        with self.assertRaises(auto.Refuse):auto.verify_status(obj,'v2')
    def test_full_sequence_exact_and_readback(self):
        outputs=[plan(),applied(),reconciled(),status()]; seen=[]
        def fake(cmd,**kw):
            seen.append((cmd[-1],kw['env']))
            return subprocess.CompletedProcess(cmd,0,json.dumps(outputs.pop(0)),'')
        result=auto.authorization_pipeline('authority.py','/tmp',approved(),executor=fake)
        self.assertEqual(result['status'],'READBACK_VERIFIED')
        self.assertEqual([v[0] for v in seen],['authorization-plan','authorization-apply','authorization-reconcile','authority-status'])
        self.assertNotIn(auto.AUTH_ENV,seen[0][1])
        self.assertEqual(seen[1][1][auto.AUTH_ENV],auto.AUTH_APPROVAL)
    def test_bad_plan_makes_zero_remote_writes(self):
        seen=[];bad=plan();bad['safeToApply']=False
        def fake(cmd,**kw):
            seen.append(cmd[-1]);return subprocess.CompletedProcess(cmd,0,json.dumps(bad),'')
        with self.assertRaises(auto.Refuse): auto.authorization_pipeline('authority.py','/tmp',approved(),executor=fake)
        self.assertEqual(seen,['authorization-plan'])
    def test_ambiguous_apply_stops_no_retries(self):
        seen=[]
        def fake(cmd,**kw):
            seen.append(cmd[-1]);return subprocess.CompletedProcess(cmd,0,json.dumps(plan()) if len(seen)==1 else '', '') if len(seen)==1 else subprocess.CompletedProcess(cmd,1,'','private')
        with self.assertRaises(auto.Refuse):auto.authorization_pipeline('authority.py','/tmp',approved(),executor=fake)
        self.assertEqual(seen,['authorization-plan','authorization-apply'])
    def test_negative_http_gates(self):
        obj={'stage':'CIAM_V10_ANONYMOUS_NEGATIVE_ACCEPTANCE','remoteWrites':0,
             'credentialsUsed':False,'runtimeEvidence':'LIVE_INTROSPECTION_PER_REQUEST',
             'status':'NEGATIVE_HTTP_GATES_PASSED',
             'results':{k:{'http':v,'pass':True} for k,v in {
                 'anonymousIdentity':200,'auroraWebWithoutSession':401,
                 'auroraAppWithoutSession':401,'brisaWebWithoutSession':401,
                 'brisaAppWithoutSession':401,'syntheticConsentDisabled':503,
                 'syntheticScenarioDisabled':503,'syntheticRetailDisabled':503}.items()}}
        auto.verify_anonymous_acceptance(obj)
        obj['results']['syntheticScenarioDisabled']['http']=200
        with self.assertRaises(auto.Refuse):auto.verify_anonymous_acceptance(obj)
    def test_consent_blocked_not_marked_complete(self):
        def fake(cmd,**kw):
            return subprocess.CompletedProcess(cmd,0,json.dumps({'stage':'CIAM_V10_CONSENT','status':'BLOCKED',
                'remoteWrites':0,'noLocalConsentFallback':True}),'')
        self.assertTrue(auto.consent_capability('authority.py','/tmp',approved(),executor=fake).startswith('BLOCKED'))
    def test_consent_plan_must_never_write(self):
        def fake(cmd,**kw):return subprocess.CompletedProcess(cmd,0,json.dumps({'remoteWrites':1,'status':'BLOCKED'}),'')
        with self.assertRaises(auto.Refuse):auto.consent_capability('authority.py','/tmp',approved(),executor=fake)
    def test_fresh_preflight_refuses_existing_root(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as root:
            with self.assertRaisesRegex(auto.Refuse,'RUNTIME_ALREADY_EXISTS'):
                auto.fresh_destination_preflight(root)

    def test_fresh_preflight_refuses_either_occupied_port(self):
        for blocked in (9444,4400):
            with self.subTest(port=blocked),self.assertRaisesRegex(auto.Refuse,'PORT_'+str(blocked)):
                auto.fresh_destination_preflight('/tmp/v10-fixture-nonexistent',
                    port_probe=lambda p: p==blocked)

    def test_fresh_preflight_refuses_existing_docker_resources(self):
        def containers(cmd,**kw):
            return subprocess.CompletedProcess(cmd,0,'deadbeef\n' if cmd[1]=='ps' else '', '')
        with self.assertRaisesRegex(auto.Refuse,'COMPOSE_CONTAINERS_EXIST'):
            auto.fresh_destination_preflight('/tmp/v10-fixture-nonexistent',executor=containers,port_probe=lambda p:False)
        def volumes(cmd,**kw):
            return subprocess.CompletedProcess(cmd,0,'wso2-ciam-v10_isconf\n' if cmd[1]=='volume' else '', '')
        with self.assertRaisesRegex(auto.Refuse,'DOCKER_VOLUMES_EXIST'):
            auto.fresh_destination_preflight('/tmp/v10-fixture-nonexistent',executor=volumes,port_probe=lambda p:False)

    def test_fresh_preflight_fails_closed_if_docker_unavailable(self):
        def failed(cmd,**kw): return subprocess.CompletedProcess(cmd,1,'','unavailable')
        with self.assertRaisesRegex(auto.Refuse,'NOT_VERIFIABLE'):
            auto.fresh_destination_preflight('/tmp/v10-fixture-nonexistent',executor=failed,port_probe=lambda p:False)

    def test_fresh_preflight_can_prove_empty_resources(self):
        calls=[]
        def empty(cmd,**kw):
            calls.append(cmd[1]);return subprocess.CompletedProcess(cmd,0,'','')
        auto.fresh_destination_preflight('/tmp/v10-fixture-nonexistent',executor=empty,port_probe=lambda p:False)
        self.assertEqual(calls,['ps','volume'])

    def test_readiness_fails_closed(self):
        with self.assertRaises(auto.Refuse):auto.wait_for_https(attempts=2,probe=lambda:False,sleep=lambda n:None)
    def test_readiness_permits_local_probe(self):
        auto.wait_for_https(attempts=1,probe=lambda:True)
    def test_readiness_rejects_other_port(self):
        with self.assertRaises(auto.Refuse):auto.wait_for_https(port=9443,probe=lambda:True)
    def test_cli_orders_authority_before_bff_bridge_and_acceptance(self):
        source=(FILE.parent/'cli.py').read_text()
        block=source.split('def bootstrap_all():',1)[1].split('def prepare():',1)[0]
        markers=('authorization_pipeline(', "'bridge-bff'", "'start-bff'", 'negative_runtime_acceptance(', 'consent_capability(')
        offsets=[block.index(m) for m in markers]
        self.assertEqual(offsets,sorted(offsets))
    def test_fresh_bootstrap_is_guarded_before_prepare(self):
        source=(FILE.parent/'cli.py').read_text()
        start=source.index("elif command=='fresh-bootstrap':")
        block=source[start:source.index("elif command=='bootstrap':",start)]
        self.assertTrue(block.index('verify_intent(os.environ, fresh=True)')<block.index('fresh_destination_preflight(ROOT)'))
        self.assertTrue(block.index('fresh_destination_preflight(ROOT)')<block.index('prepare()'))
        self.assertTrue(block.index('prepare()')<block.index('wait_for_https()'))

if __name__=='__main__':unittest.main()
