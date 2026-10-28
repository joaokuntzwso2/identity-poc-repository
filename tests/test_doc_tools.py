import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/ciam-identity-ops.py'
CARBON = Path(__file__).resolve().parents[1]/'scripts/ciam-carbon-super-readback.py'
def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.repo=self.base/'repo';self.repo.mkdir()
        self.root=self.base/'home';p=self.root/'private';p.mkdir(parents=True)
        (self.repo/'deploy/ciam-v10/identities').mkdir(parents=True)
        (self.repo/'deploy/ciam-v10/phase4').mkdir(parents=True)
        self.seed={'schema':'ciampoc.iam.real-identities.v1','people':[
          {'key':'customer-ana','username':'ana.costa','givenName':'Ana','familyName':'Costa','type':'customer','brands':['aurora','brisa']},
          {'key':'seller-marcos','username':'marcos.oliveira','givenName':'Marcos','familyName':'Oliveira','type':'seller','brands':['aurora']},
          {'key':'admin-luiza','username':'luiza.ferreira','givenName':'Luiza','familyName':'Ferreira','type':'administrator','brands':['aurora','brisa']},
          {'key':'auditor-camila','username':'camila.lima','givenName':'Camila','familyName':'Lima','type':'auditor','brands':['aurora','brisa']},
          {'key':'risk-pedro','username':'pedro.reis','givenName':'Pedro','familyName':'Reis','type':'risk','brands':['aurora']},
          {'key':'support-rafael','username':'rafael.nunes','givenName':'Rafael','familyName':'Nunes','type':'support','brands':['aurora']},
        ],'roleLabels':{'customer':'Customer','seller':'Seller','administrator':'Administrator','auditor':'Auditor','risk':'Risk','support':'Support'},'implementedPermissionAssignments':{'customer':['ciam:profile:read']}}
        self.desired={'businessApi':{'identifier':'urn:ciampoc:service-requests:v1','rolePermissions':{
          'customer':['ciam:cases:create','ciam:cases:read'],
          'seller':['ciam:cases:read','ciam:cases:review','ciam:cases:approve'],
          'administrator':['ciam:cases:read','ciam:cases:review','ciam:cases:approve']}}}
        self.write_source('deploy/ciam-v10/identities/seed.json',self.seed)
        self.write_source('deploy/ciam-v10/phase4/desired.json',self.desired)
        brands={'aurora':'aurora.identity.test','brisa':'brisa.identity.test'}
        self.write_private('admin.private.json',{'username':'admin','password':'SuperSecretValueNeverPrint42'})
        self.write_private('bootstrap-tenants-v10.private.json',{'domains':brands,'tenants':{
           b:{'domain':d,'status':'readback-verified','owner':{'username':'labtenantadmin','password':'OwnerSecretDoNotPrint42'}}
           for b,d in brands.items()}})
        self.write_private('bootstrap-resources-v10.private.json',{'tenants':{
           b:{'user':{'state':'verified-browser-not-tested','username':'ciam_'+b,'password':'FoundationSecretDontPrint42'},
              'management':{'name':f'Identity Lab {b.upper()} Management Bootstrap'}} for b in brands}})
        self.write_private('bootstrap-oidc-v10.private.json',{'tenants':{
           b:{'clients':{c:{'state':'verified','name':f'Identity Lab v10 {b.title()} {c.title()}',
              'callback':f'http://127.0.0.1:4400/auth/{b}-{c}/callback'} for c in ('web','app')}} for b in brands}})
        self.write_private('bootstrap-authority-v10.private.json',{'roleApiVersion':'v2'})
        its={};bts={}
        for b in brands:
            users={p['key']:{'state':'verified','username':p['username'],'kind':p['type'],'password':'FixtureSecretNeverPrint42'} for p in self.seed['people'] if b in p['brands']}
            its[b]={'users':users,'roles':{}}
            bts[b]={'roles':{}}
            for c in ('web','app'):
                for kind,label in self.seed['roleLabels'].items():
                    if any(p['type']==kind and b in p['brands'] for p in self.seed['people']):
                       its[b]['roles'][c+':'+kind]={'state':'verified','name':'CIAM Demo '+label+' '+c.upper()}
                for kind in self.desired['businessApi']['rolePermissions']:
                    if any(p['type']==kind and b in p['brands'] for p in self.seed['people']):
                       bts[b]['roles'][c+':'+kind]={'state':'verified'}
        self.write_private('bootstrap-identities-v10.private.json',{'tenants':its})
        self.write_private('bootstrap-business-v4.private.json',{'tenants':bts})
        self.mod=load(SCRIPT,'ops_under_test')
        self.mod.ROOT=self.root;self.mod.PRIVATE=p
        self.mod.SEED=self.repo/'deploy/ciam-v10/identities/seed.json'
        self.mod.DESIRED=self.repo/'deploy/ciam-v10/phase4/desired.json'
    def write_source(self,rel,obj):
        (self.repo/rel).write_text(json.dumps(obj))
    def write_private(self,name,obj):
        p=self.root/'private'/name;p.write_text(json.dumps(obj));p.chmod(0o600)
    def test_inventory_lists_correct_tenants_roles_and_no_secrets(self):
        from argparse import Namespace
        o=self.repo/'inventory.md'
        self.mod.inventory(Namespace(output=str(o)))
        text=o.read_text()
        for s in ['carbon.super','Aurora','Brisa','marcos.oliveira','ciam:cases:approve','CIAM Business Seller WEB']:
            self.assertIn(s,text)
        for s in ['FixtureSecretNeverPrint42','SuperSecretValueNeverPrint42','FoundationSecretDontPrint42','OwnerSecretDoNotPrint42']:
            self.assertNotIn(s,text)
    def test_one_wrong_tenant_refused(self):
        from argparse import Namespace
        self.mod.SEED=self.mod.SEED
        with patch.object(self.mod,'sys') as fake_sys:
            fake_sys.platform='darwin'
            with self.assertRaises(self.mod.Refuse):
                self.mod.copy_password(Namespace(kind='person',tenant='brisa',user='marcos.oliveira'))
    def test_password_only_sent_to_pbcopy_not_printed(self):
        from argparse import Namespace
        with patch.object(self.mod.sys,'platform','darwin'),patch.object(self.mod.subprocess,'run') as run:
            self.mod.copy_password(Namespace(kind='person',tenant='aurora',user='ana.costa'))
            self.assertEqual(run.call_args.args[0],['pbcopy'])
            self.assertEqual(run.call_args.kwargs['input'],'FixtureSecretNeverPrint42')
    def test_invalid_mode_refused(self):
        path=self.root/'private'/'admin.private.json';path.chmod(0o644)
        with self.assertRaises(self.mod.Refuse): self.mod.private('admin.private.json')
    def test_carbon_readback_does_not_claim_missing_http(self):
        m=load(CARBON,'carbon_under_test')
        result=m.compact('superApplications',403,None)
        self.assertEqual(result['status'],'UNVERIFIED_HTTP_403')
    def test_carbon_incomplete_page_not_marked_full(self):
        m=load(CARBON,'carbon2_under_test')
        self.assertEqual(m.compact('superApplications',200,{'applications':[{'name':'X'}],'totalResults':2})['status'],'PARTIAL_OR_UNVERIFIED')
    def test_carbon_secrets_are_never_in_summary(self):
        m=load(CARBON,'carbon3_under_test')
        result=m.compact('superApplications',200,{'applications':[{'name':'X','clientSecret':'SuperSECRET'}],'totalResults':1})
        self.assertNotIn('SuperSECRET',repr(result))

if __name__=='__main__': unittest.main()
