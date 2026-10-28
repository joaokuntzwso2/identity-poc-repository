import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FILE=Path(__file__).resolve().parents[1] / 'scripts/recovery/ciam-v4-audience-bootstrap-v4_4.py'
spec=importlib.util.spec_from_file_location('aud44', FILE)
aud=importlib.util.module_from_spec(spec)
spec.loader.exec_module(aud)

PATH='/t/aurora.identity.test/api/server/v1/applications/123e4567-e89b-12d3-a456-426614174000/inbound-protocols/oidc'

class Refuse(Exception): pass

class Helper:
    def __init__(self):
        self.calls=[]
    def call(self, method, path, auth=None, data=None):
        if method not in ('GET', 'POST') or not path.startswith('/') or path.startswith('//') or ('\\' in path) or ('..' in path) or ('#' in path):
            raise Refuse('UNSAFE_HTTP_REQUEST')
        self.calls.append((method, path, auth, data))
        return 200, {'ok':True}, {'h': 1}

class InsecureHelper:
    def call(self, method, path, auth=None, data=None):
        if method not in ('GET','POST'):
            raise Refuse('UNSAFE_HTTP_REQUEST')
        return 200, {}, {}

class SlowGuardHelper:
    def call(self, method, path, auth=None, data=None):
        self.send_network()
        if method not in ('GET', 'POST') or not path.startswith('/'):
            raise Refuse('UNSAFE_HTTP_REQUEST')
        return 200, {}, {}
    def send_network(self): pass

class Resource:
    def __init__(self, helper): self.helper=helper
    def HTTPS(self): return self.helper


def baseline():
    return {'clientId':'aurora-client','clientSecret':'dont-print','state':'ACTIVE',
            'grantTypes':['authorization_code'],'callbackURLs':['http://127.0.0.1:4400/cb'],
            'publicClient':False,'accessToken':{'type':'JWT'},'idToken':{'audience':[aud.PROFILE]},
            'scopeValidators':[]}

class Tests(unittest.TestCase):
    def test_unchanged_helper_rejects_put(self):
        with self.assertRaisesRegex(Refuse,'UNSAFE_HTTP_REQUEST'):
            Helper().call('PUT', PATH, auth='x',data={})
    def test_restricted_patched_method_allows_exact_put(self):
        helper=Helper()
        writer=aud.build_temporary_put_transport(Resource(helper),PATH)
        self.assertEqual(writer('PUT',PATH,auth='credential',data={'x':1})[0],200)
        self.assertEqual(helper.calls, [('PUT',PATH,'credential',{'x':1})])
        self.assertEqual(aud.protected_oidc_put({},Resource(helper),PATH,'c',{'a':2})[0],200)
        with self.assertRaisesRegex(aud.Stop,'PUT_ONLY_EXACT_PATH'):
            writer('PUT',PATH.replace('aurora','brisa'),auth='credential')
        with self.assertRaisesRegex(aud.Stop,'PUT_ONLY_EXACT_PATH'):
            writer('POST',PATH,auth='credential')
        self.assertEqual(Helper().call('GET',PATH)[0],200)
    def test_unrecognized_method_guard_refused(self):
        with self.assertRaisesRegex(aud.Stop,'METHOD_OR_PATH_GUARD_CHANGED'):
            aud.build_temporary_put_transport(Resource(InsecureHelper()),PATH)
    def test_pre_network_side_effect_refused(self):
        with self.assertRaisesRegex(aud.Stop,'GUARD_NOT_FIRST_SIDE_EFFECT'):
            aud.build_temporary_put_transport(Resource(SlowGuardHelper()),PATH)
    def test_non_exact_path_refused(self):
        with self.assertRaisesRegex(aud.Stop,'PUT_PATH_NOT_EXACT_AURORA_OIDC'):
            aud.build_temporary_put_transport(Resource(Helper()),'/t/brisa.identity.test/api/server/v1/application/a')
    def test_recovery_from_two_blocked_attempts_success_and_no_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            journal=root/'private/aurora-web-audience-recovery-v4.private.json'
            backup=root/'private/aurora-web-oidc-before-audience-v4.private.json'
            before=baseline()
            aud.secure_write_exclusive(backup,before)
            aud.write_state(journal, {'schema':'ciampoc.v4.audience-recovery.v1',
                                     'appId':'123e4567-e89b-12d3-a456-426614174000',
                                     'businessAudience':aud.BUSINESS,'originalSha256':aud.sha256(before),
                                     'state':'recovery-started','attempts':2,
                                     'lastAttempt':'recovery','lastResult':None})
            remote=copy.deepcopy(before)
            calls={'GET':0,'PUT':0}
            app={'id':'123e4567-e89b-12d3-a456-426614174000','clientId':'aurora-client'}
            class ResourceFixture:
                ROOT=root
                def HTTPS(self): return Helper()
            resource=ResourceFixture()
            def get(*args):
                calls['GET']+=1
                return PATH,'credential',copy.deepcopy(remote)
            def put(mod, res, path, cred, data):
                calls['PUT']+=1
                remote['idToken']['audience'] = list(data['idToken']['audience'])
                return 200, {}
            local={'server':('already-normal',''), 'authority':('already-normal','')}
            with patch.object(aud,'load_context',return_value=({},resource,{},app)), \
                 patch.object(aud,'verified_business_api'), \
                 patch.object(aud,'local_restore_plan',return_value=local), \
                 patch.object(aud,'remote_get',side_effect=get), \
                 patch.object(aud,'safe_local_restore'), \
                 patch.object(aud,'restart_bff',return_value={'auroraPortal':200}), \
                 patch.object(aud,'protected_oidc_put',side_effect=put), \
                 patch.object(aud,'build_temporary_put_transport',return_value='ready'), \
                 patch.object(aud.time,'sleep',return_value=None):
                plan=aud.execute('plan')
                self.assertTrue(plan['recoveryEligibleByReadback'])
                self.assertEqual(plan['remoteWrites'],0)
                result=aud.execute('run')
                self.assertEqual(result['readback'],'VERIFIED')
                self.assertEqual(calls['PUT'],1)
                self.assertEqual(json.loads(journal.read_text())['attempts'],3)
                self.assertEqual(json.loads(journal.read_text())['state'],'verified')
                result2=aud.execute('run')
                self.assertEqual(result2['remoteWrites'],0)
                self.assertEqual(calls['PUT'],1)
                self.assertEqual(aud.execute('verify')['readback'],'VERIFIED')
    def test_recovery_failed_http_is_no_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); before=baseline(); journal=root/'private/aurora-web-audience-recovery-v4.private.json'
            backup=root/'private/aurora-web-oidc-before-audience-v4.private.json'
            aud.secure_write_exclusive(backup,before)
            aud.write_state(journal, {'schema':'ciampoc.v4.audience-recovery.v1',
                                     'appId':'123e4567-e89b-12d3-a456-426614174000',
                                     'businessAudience':aud.BUSINESS,'originalSha256':aud.sha256(before),
                                     'state':'recovery-started','attempts':2,
                                     'lastAttempt':'recovery','lastResult':None})
            class R:
                ROOT=root
                def HTTPS(self): return Helper()
            app={'id':'123e4567-e89b-12d3-a456-426614174000','clientId':'aurora-client'}
            local={'server':('already-normal',''), 'authority':('already-normal','')}
            writes=[]
            def fail(mod,res,path,auth,data):
                writes.append(1)
                return 400,{}
            with patch.object(aud,'load_context',return_value=({},R(),{},app)), \
                 patch.object(aud,'verified_business_api'), \
                 patch.object(aud,'local_restore_plan',return_value=local), \
                 patch.object(aud,'remote_get',return_value=(PATH,'cred',copy.deepcopy(before))), \
                 patch.object(aud,'protected_oidc_put',side_effect=fail), \
                 patch.object(aud,'build_temporary_put_transport',return_value='ready'), \
                 patch.object(aud.time,'sleep',return_value=None):
                with self.assertRaisesRegex(aud.Stop,'HTTP_400_REMOTE_BASELINE_NO_RETRY'):
                    aud.execute('run')
                self.assertEqual(len(writes),1)
                self.assertEqual(json.loads(journal.read_text())['state'],'transport-remediation-started')
                with self.assertRaisesRegex(aud.Stop,'TRANSPORT_REMEDIATION_NOT_ELIGIBLE'):
                    aud.execute('run')
                self.assertEqual(len(writes),1)
    def test_journal_drift_refused(self):
        # May not overwrite the recovery journal or skip its counter.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); before=baseline(); journal=root/'private/aurora-web-audience-recovery-v4.private.json'
            backup=root/'private/aurora-web-oidc-before-audience-v4.private.json'
            aud.secure_write_exclusive(backup,before)
            aud.write_state(journal, {'schema':'ciampoc.v4.audience-recovery.v1',
                                     'appId':'x','businessAudience':aud.BUSINESS,
                                     'originalSha256':aud.sha256(before),'state':'recovery-started','attempts':2,
                                     'lastAttempt':'recovery','lastResult':None})
            class R: ROOT=root
            app={'id':'123e4567-e89b-12d3-a456-426614174000','clientId':'aurora-client'}
            with patch.object(aud,'load_context',return_value=({},R(),{},app)), \
                 patch.object(aud,'verified_business_api'), \
                 patch.object(aud,'local_restore_plan',return_value={'server':('already-normal',''), 'authority':('already-normal','')}), \
                 patch.object(aud,'remote_get',return_value=(PATH,'cred',before)):
                with self.assertRaisesRegex(aud.Stop,'RECOVERY_JOURNAL_INVALID'):
                    aud.execute('run')
if __name__=='__main__': unittest.main(verbosity=2)
