#!/usr/bin/env python3
"""Offline fail-closed tests. No external WSO2 or business persistence access."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SRC=Path(__file__).with_name('ciam-p010-aurora-adaptive.py')
spec=importlib.util.spec_from_file_location('p010_mfa_stage_test',SRC)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SOURCE=Path(__file__).resolve().parents[1]/'deploy/ciam-v10/p010/aurora-acr-totp-adaptive.js'
SCRIPT=SOURCE.read_text() if SOURCE.is_file() else (Path(__file__).resolve().parents[1]/'deploy/ciam-v10/p010/aurora-acr-totp-adaptive.js').read_text()

SEQ={'type':'DEFAULT','steps':[{'id':1,'options':[{'idp':'LOCAL','authenticator':'BasicAuthenticator'}]}],
     'subjectStepId':1,'attributeStepId':1}
class Oidc:
    TENANTS='tenant';OIDC='oidc'
    def __init__(self):
        self.data={'tenant':{'domains':m.DOMAINS,'tenants':{b:{'domain':d,'owner':{'username':'owner','password':'secret'}} for b,d in m.DOMAINS.items()}},
            'oidc':{'schema':'identity.wso2.ciam.v10.oidc.v1','base':'https://localhost:9444','tenants':{}}}
        for b in m.DOMAINS:
            self.data['oidc']['tenants'][b]={'clients':{}}
            for ch in m.CHANNELS:
                self.data['oidc']['tenants'][b]['clients'][ch]={'id':f'{b}-{ch}-12345', 'state':'verified',
                    'name':f'CIAM {b} {ch}', 'clientId':f'{b}-{ch}-clientid','callback':f'http://127.0.0.1:4400/auth/{b}-{ch}/callback'}
    def read_private(self,key):return copy.deepcopy(self.data[key])
class Resources:
    OWNER='owner'
    def basic(self,name,pw):return 'Basic synthetic-unit-only'
class Cap:
    def probe(self,client,domain,auth):
        s,data,_=client.call('GET',f'/t/{domain}/api/server/v1/authenticators',auth=auth)
        if s!=200:raise m.Refused('CAPABILITY_READBACK_FAILED')
        return {'totpEnabled':data['enabled']}
class FakeClient:
    def __init__(self,oidc, etag=None):
        self.oidc=oidc;self.patch_count=0;self.get_count=0;self.etag=etag
        self.fail_on_patch=None;self.app={};self.protocol={};self.cap_ok=True
        for b,d in m.DOMAINS.items():
            for ch in m.CHANNELS:
                n=oidc.data['oidc']['tenants'][b]['clients'][ch]
                path=f'/t/{d}/api/server/v1/applications/{n["id"]}'
                self.app[path]={'id':n['id'],'name':n['name'],'associatedRoles':{'allowedAudience':'APPLICATION'},
                    'authenticationSequence':copy.deepcopy(SEQ),'claimConfiguration':{'foo':'bar'},
                    'advancedConfigurations':{'flag':True}}
                self.protocol[path+'/inbound-protocols/oidc']={'clientId':n['clientId'],'callbackURLs':[n['callback']],
                    'grantTypes':['authorization_code'],'pkce':{'mandatory':True,'supportPlainTransformAlgorithm':False}}
    def call(self,method,path,*,auth,data=None,form=None,etag=None):
        if method=='PATCH':
            if not path.startswith('/t/aurora.identity.test/'):
                raise m.Refused('BRISA_PATCH_REFUSED')
            self.patch_count+=1
            if self.fail_on_patch==self.patch_count:
                raise ConnectionError('mock transport failure')
            self.app[path]['authenticationSequence']=copy.deepcopy(data['authenticationSequence'])
            return 200,{},self.etag
        self.get_count+=1
        if '/authenticators' in path:return 200,{'enabled':self.cap_ok},None
        if path in self.app:return 200,copy.deepcopy(self.app[path]),self.etag
        if path in self.protocol:return 200,copy.deepcopy(self.protocol[path]),None
        return 404,{},None

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='p010-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.base.chmod(0o700)
        self.patches=[patch.object(m,'PRIVATE',self.base),patch.object(m,'JOURNAL',self.base/'journal.json'),
                      patch.object(m,'LOCK',self.base/'lock')]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        self.oidc=Oidc();self.client=FakeClient(self.oidc);self.resources=Resources();self.cap=Cap()
    def run_stage(self,approved=False,allow_no_etag=False):
        return m.execute(self.client,self.oidc,self.resources,self.cap,SCRIPT,
                         approved=approved,allow_no_etag=allow_no_etag)
    def test_read_only_plan_all_four_clients(self):
        x=self.run_stage()
        self.assertEqual(x['pending'],['aurora:web','aurora:app'])
        self.assertEqual(x['remoteWrites'],0)
        self.assertEqual(self.client.patch_count,0)
        self.assertFalse(m.JOURNAL.exists())
    def test_after_sequence_exact_scope(self):
        after=m.after_sequence(copy.deepcopy(SEQ),SCRIPT)
        m.check_sequence(after,'after',SCRIPT)
        self.assertEqual(after['steps'][0],SEQ['steps'][0])
        self.assertEqual(after['steps'][1]['options'],[{'idp':'LOCAL','authenticator':'totp'}])
        self.assertNotIn('ciam:cases',str(after))
    def test_existing_script_collision_refused(self):
        self.client.app[next(iter(self.client.app))]['authenticationSequence']['script']='operator-existing-script'
        with self.assertRaisesRegex(m.Refused,'UNOWNED_CONDITIONAL_SCRIPT_PRESENT'):
            self.run_stage()
    def test_wrong_audience_refused(self):
        self.client.app[next(iter(self.client.app))]['associatedRoles']['allowedAudience']='ORGANIZATION'
        with self.assertRaisesRegex(m.Refused,'APP_ID_OR_AUDIENCE_DRIFT'):
            self.run_stage()
    def test_brisa_policy_changed_refused(self):
        p=next(p for p in self.client.app if '/brisa.' in p)
        self.client.app[p]['authenticationSequence']=m.after_sequence(SEQ,SCRIPT)
        with self.assertRaisesRegex(m.Refused,'AUTHENTICATION_SEQUENCE_TYPE_DRIFT'):
            self.run_stage()
    def test_totp_not_enabled_refused(self):
        self.client.cap_ok=False
        with self.assertRaisesRegex(m.Refused,'ENABLED_TOTP_NOT_ATTESTED'):
            self.run_stage()
    def test_requires_explicit_etag_risk_ack(self):
        with self.assertRaisesRegex(m.Refused,'NO_ETAG_NEEDS_EXPLICIT_ACK'):
            self.run_stage(approved=True)
        self.assertEqual(self.client.patch_count,0)
        self.assertEqual(m.read_journal()['roles']['web']['state'],'pending')
    def test_two_journaled_writes_verified(self):
        result=self.run_stage(approved=True,allow_no_etag=True)
        self.assertEqual(result['status'],'ALL_TWO_AURORA_POLICY_READBACK_VERIFIED')
        self.assertEqual(self.client.patch_count,2)
        self.assertEqual(sorted(v['state'] for v in m.read_journal()['roles'].values()),['verified','verified'])
        self.assertFalse(result['liveTotpChallengeAttested'])
        again=self.run_stage()
        self.assertEqual(again['pending'],[])
    def test_partial_verified_can_resume_without_repeating(self):
        self.client.fail_on_patch=2
        with self.assertRaisesRegex(m.Refused,'UNCERTAIN_WSO2_PATCH'):
            self.run_stage(approved=True,allow_no_etag=True)
        self.assertEqual(m.read_journal()['roles']['web']['state'],'verified')
        self.assertEqual(m.read_journal()['roles']['app']['state'],'uncertain')
        self.client.fail_on_patch=None
        with self.assertRaisesRegex(m.Refused,'AUTHENTICATION_SEQUENCE_TYPE_DRIFT|UNCERTAIN'):
            self.run_stage(approved=True,allow_no_etag=True)
        self.assertEqual(self.client.patch_count,2)
    def test_patch_payload_restricts_exact_application_path(self):
        # GuardedClient.call validates method/path BEFORE touching the network.
        class Ctx:pass
        client=m.GuardedClient(Ctx())
        with self.assertRaisesRegex(m.Refused,'PATCH_OUT_OF_SCOPE'):
            client.call('PATCH','/t/brisa.identity.test/api/server/v1/applications/brisa-web-12345',
                auth='Basic fake',data={'authenticationSequence':m.after_sequence(SEQ,SCRIPT)})
        with self.assertRaisesRegex(m.Refused,'PATCH_OUT_OF_SCOPE'):
            client.call('PATCH','/t/aurora.identity.test/api/server/v1/users/seller-id',
                auth='Basic fake',data={'authenticationSequence':m.after_sequence(SEQ,SCRIPT)})
    def test_journal_mode_is_owner_only(self):
        self.run_stage(approved=True,allow_no_etag=True)
        self.assertEqual(m.JOURNAL.stat().st_mode & 0o777,0o600)
    def test_signature_and_assurance_not_falsely_claimed(self):
        self.assertEqual(self.run_stage()['signedAmrAndAuthTimeAttested'],False)
        self.assertEqual(self.run_stage()['sellerEnrollmentAttested'],False)

if __name__=='__main__':unittest.main()
