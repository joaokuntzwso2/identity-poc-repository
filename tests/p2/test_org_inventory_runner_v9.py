import importlib.util
import json
import pathlib
import re
import sys
import unittest
from unittest.mock import patch

MODULE=pathlib.Path(__file__).parent/'run-org-inventory-v9.py'
if not MODULE.is_file():
    MODULE=pathlib.Path(__file__).resolve().parents[2]/'scripts/p2/run-org-inventory-v9.py'
spec=importlib.util.spec_from_file_location('runner_p2_v9', MODULE)
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

APP='11111111-1111-4111-8111-111111111111'
ROOT='22222222-2222-4222-8222-222222222222'
class FakeModule:
    UUID=re.compile(r'^[0-9a-f-]{36}$')
    @staticmethod
    def hash_id(v):
        return r.APP_FP if v==APP else r.ROOT_FP if v==ROOT else 'wrong'

class TestV9Runner(unittest.TestCase):
    def base(self):
        return {'schema':'p2.24.aurora.m2m.bootstrap.v1','phase':'COMPLETE',
                'tenant':r.TENANT,'scope':r.SCOPE,
                'appName':'P2 Aurora Organization View M2M',
                'appId':APP,'rootId':ROOT,
                'remoteWritesAttempted':2,
                'reconciledBy':'P2_24_GET_ONLY_AUTHORIZATION_READBACK_V8',
                'originalCreateResponseStillUnverified':True}

    def test_correct_journal_accepted_locally(self):
        r.verify_completed_journal(FakeModule(),self.base())

    def test_wrong_source_rejected(self):
        record=self.base();record['reconciledBy']='P2_FAKE'
        with self.assertRaisesRegex(r.Block,'V8_COMPLETE_JOURNAL_NOT_PINNED'):
            r.verify_completed_journal(FakeModule(),record)

    def test_unverified_root_or_app_rejected(self):
        for key in ('appId','rootId'):
            record=self.base();record[key]='33333333-3333-4333-8333-333333333333'
            with self.assertRaisesRegex(r.Block,'V8_COMPLETE_JOURNAL_NOT_PINNED'):
                r.verify_completed_journal(FakeModule(),record)

    def test_incomplete_or_foreign_journal_rejected(self):
        for key,value in [('phase','AUTHORIZATION_INTENT'),('tenant','brisa.identity.test'),
                          ('scope','internal_org_organization_create'),('remoteWritesAttempted',1)]:
            record=self.base();record[key]=value
            with self.assertRaisesRegex(r.Block,'V8_COMPLETE_JOURNAL_NOT_PINNED'):
                r.verify_completed_journal(FakeModule(),record)

    def test_node_errors_are_sanitized(self):
        class Result:
            returncode=2
            stdout=''
            stderr=json.dumps({'status':'BLOCKED','code':'ORG_INVENTORY_INCOMPLETE','secret':'do-not-show'})
        with patch.object(r.subprocess,'run',return_value=Result()):
            with self.assertRaisesRegex(r.Block,'ORG_INVENTORY_INCOMPLETE'):
                r.node_json(pathlib.Path('/fake'),{},'plan-partner')

    def test_node_accepts_wso2_sanitized_result_only(self):
        class Result:
            returncode=0
            stderr=''
            stdout=json.dumps({'phase':'P2.24-P2.29','source':'WSO2_API_RESPONSE',
                'tenant':'aurora.identity.test','runtimeEvidence':'OPERATOR_EXECUTED',
                'result':{'mode':'GET_ONLY','collection':'array','managementWrites':0}})
        with patch.object(r.subprocess,'run',return_value=Result()):
            self.assertEqual(r.node_json(pathlib.Path('/fake'),{},'inspect-partner-inventory')['collection'],'array')

    def test_node_disallows_wrong_tenant_result(self):
        class Result:
            returncode=0
            stderr=''
            stdout=json.dumps({'phase':'P2.24-P2.29','source':'WSO2_API_RESPONSE',
                'tenant':'brisa.identity.test','runtimeEvidence':'OPERATOR_EXECUTED','result':{}})
        with patch.object(r.subprocess,'run',return_value=Result()):
            with self.assertRaisesRegex(r.Block,'OPERATOR_EVIDENCE_NOT_VERIFIED'):
                r.node_json(pathlib.Path('/fake'),{},'inspect-partner-inventory')

    def test_code_only_rejects_secret_bearing_messages(self):
        self.assertEqual(r.code_only('Authorization: Bearer secret'), 'ORG_INVENTORY_V9_UNEXPECTED_FAILURE')

if __name__=='__main__':unittest.main()
