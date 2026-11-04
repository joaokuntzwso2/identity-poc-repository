from __future__ import annotations
import importlib.util,unittest,uuid,tempfile,re,json
from unittest import mock
from pathlib import Path

MOD=Path(__file__).resolve().parents[2]/'scripts/p2/partner_share_v17.py'
spec=importlib.util.spec_from_file_location('test_v17_source',MOD)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
APP=str(uuid.uuid4());PARTNER=str(uuid.uuid4());ROOT=str(uuid.uuid4());CHILD_APP=str(uuid.uuid4())
ROW={'id':PARTNER,'parentId':ROOT,'status':'ACTIVE',
     'sharingMode':{'policy':'SELECTED_ORG_ONLY','roleSharing':{'mode':'NONE'}},'roles':[]}
MAPPING={'organizationId':PARTNER,'applicationId':CHILD_APP}
class Store:
    UUID=re.compile(r'[a-f0-9-]{36}')
    def __init__(self):self.records={}
    def exclusive_json(self,key,value):
        assert key not in self.records
        self.records[key]=value
    def replace_json(self,key,value):
        assert key in self.records
        self.records[key]=value
    def read_json_private(self,key):return self.records[key]
    def safe_private_file(self,key,required=False):return key in self.records
class Http:pass
class V17Tests(unittest.TestCase):
    def test_payload_has_one_org_selected_only_and_no_roles(self):
        d=v.body_for(APP,PARTNER)
        self.assertEqual(d,{'applicationId':APP,'organizations':[{'orgId':PARTNER,
                      'policy':'SELECTED_ORG_ONLY','roleSharing':{'mode':'NONE'}}]})
        self.assertNotIn('shareWithAllChildren',str(d))
    def test_explicit_clean_requires_both_views(self):
        self.assertEqual(v.classify([],None,[],APP,PARTNER,ROOT),'EMPTY')
        self.assertEqual(v.classify(None,None,[],APP,PARTNER,ROOT),'PENDING')
        self.assertEqual(v.classify([],None,None,APP,PARTNER,ROOT),'PENDING')
    def test_exact_requires_policy_and_mapping(self):
        self.assertEqual(v.classify([ROW],None,[MAPPING],APP,PARTNER,ROOT),'EXACT')
        self.assertEqual(v.classify([ROW],None,[],APP,PARTNER,ROOT),'PENDING')
    def test_share_with_other_org_is_refused(self):
        foreign={**ROW,'id':str(uuid.uuid4())}
        with self.assertRaisesRegex(v.Refuse,'OTHER_ORG'):v.classify([ROW,foreign],None,[MAPPING],APP,PARTNER,ROOT)
    def test_shared_app_reference_for_other_org_is_refused(self):
        with self.assertRaisesRegex(v.Refuse,'OTHER_ORG'):
            v.classify([ROW],None,[MAPPING,{**MAPPING,'organizationId':str(uuid.uuid4())}],APP,PARTNER,ROOT)
    def test_broad_inheritance_is_refused(self):
        for policy in ['ALL_EXISTING_AND_FUTURE_ORGS','SELECTED_ORG_WITH_ALL_EXISTING_AND_FUTURE_CHILDREN']:
            with self.subTest(policy=policy),self.assertRaises(v.Refuse):
                v.classify([{**ROW,'sharingMode':{**ROW['sharingMode'],'policy':policy}}],None,[MAPPING],APP,PARTNER,ROOT)
    def test_explicit_roles_cannot_be_granted(self):
        for mode in ['ALL','SELECTED']:
            with self.subTest(mode=mode),self.assertRaisesRegex(v.Refuse,'ROLE_SHARING_NOT_NONE'):
                v.classify([{**ROW,'sharingMode':{'policy':v.POLICY,'roleSharing':{'mode':mode}}}],None,[MAPPING],APP,PARTNER,ROOT)
    def test_missing_role_mode_not_claimed_verified(self):
        self.assertEqual(v.classify([{**ROW,'sharingMode':{'policy':v.POLICY}}],None,[MAPPING],APP,PARTNER,ROOT),'PENDING')
    def test_broad_top_level_mode_refused(self):
        with self.assertRaisesRegex(v.Refuse,'BROAD_GLOBAL'):
            v.classify([],{'policy':'ALL_EXISTING_AND_FUTURE_ORGS'},[],APP,PARTNER,ROOT)
    def test_journal_tamper_refused(self):
        ref=v.journal_template(APP,PARTNER,v.body_for(APP,PARTNER))
        v.verify_journal(ref,ref)
        for key,val in [('partnerId',ROOT),('applicationId',str(uuid.uuid4())),
                        ('policy','ALL_EXISTING_ORGS_ONLY'),('roleMode','ALL'),
                        ('tenant','brisa.identity.test'),('state','FAILED')]:
            with self.subTest(key=key),self.assertRaises(v.Refuse):
                v.verify_journal({**ref,key:val},ref)
    def test_before_post_journal_and_after_post_readback(self):
        m=Store(); observations=iter(['EMPTY','EXACT']);called=[]
        old=v.reconcile_snapshot
        def snap(*_):return next(observations)
        v.reconcile_snapshot=snap
        def submit(*_):
            self.assertEqual(m.records[Path('/p')/v.JOURNAL]['state'],'INTENT')
            called.append(1)
            return 202
        try:
            out=v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'bootstrap',submit=submit,sleeper=lambda _:None)
        finally:v.reconcile_snapshot=old
        self.assertEqual(out['status'],'VERIFIED');self.assertEqual(out['managementWritesAttempted'],1)
        self.assertEqual(m.records[Path('/p')/v.JOURNAL]['state'],'VERIFIED')
        self.assertEqual(called,[1])
    def test_async_pending_readbacks_do_not_repeat_post(self):
        m=Store();calls=[];old=v.reconcile_snapshot
        it=iter(['EMPTY','EMPTY','PENDING','PENDING','PENDING','EXACT'])
        v.reconcile_snapshot=lambda *_:next(it)
        try:
            result=v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'bootstrap',
                     submit=lambda *_:calls.append('POST'),sleeper=lambda _:None)
            self.assertEqual(result['status'],'PENDING')
            second=v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'bootstrap',
                     submit=lambda *_:calls.append('SECOND POST'))
        finally:v.reconcile_snapshot=old
        self.assertEqual(second['status'],'VERIFIED');self.assertEqual(calls,['POST'])
    def test_ambiguous_post_keeps_journal_and_no_retry(self):
        m=Store();calls=[];old=v.reconcile_snapshot
        v.reconcile_snapshot=lambda *_:'EMPTY'
        def ambiguous(*_):calls.append('POST');raise OSError('timeout')
        try:
            with self.assertRaisesRegex(v.Refuse,'UNCERTAIN'):
                v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'bootstrap',submit=ambiguous)
            pending=v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'bootstrap',submit=ambiguous)
        finally:v.reconcile_snapshot=old
        self.assertEqual(pending['status'],'PENDING');self.assertEqual(calls,['POST'])
        self.assertEqual(m.records[Path('/p')/v.JOURNAL]['state'],'INTENT')
    def test_missing_prewrite_evidence_never_writes(self):
        m=Store();old=v.reconcile_snapshot;v.reconcile_snapshot=lambda *_:'PENDING'
        try:out=v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'bootstrap',
                         submit=lambda *_:self.fail('write not permitted'))
        finally:v.reconcile_snapshot=old
        self.assertEqual(out['status'],'PENDING');self.assertEqual(m.records,{})
    def test_verified_journal_remote_drift_is_blocking(self):
        m=Store();key=Path('/p')/v.JOURNAL
        m.records[key]={**v.journal_template(APP,PARTNER,v.body_for(APP,PARTNER)),
                        'state':'VERIFIED','postAcknowledged':True}
        old=v.reconcile_snapshot;v.reconcile_snapshot=lambda *_:'EMPTY'
        try:
            with self.assertRaisesRegex(v.Refuse,'REMOTE_DRIFT'):
                v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'bootstrap')
        finally:v.reconcile_snapshot=old
    def test_plan_never_creates_journal(self):
        m=Store();old=v.reconcile_snapshot;v.reconcile_snapshot=lambda *_:'EMPTY'
        try:out=v.apply_or_check(m,Http(),None,None,Path('/p'),APP,PARTNER,ROOT,'status')
        finally:v.reconcile_snapshot=old
        self.assertEqual(out['status'],'PLAN_ONLY');self.assertEqual(m.records,{})

    def test_exact_https_post_transport_request_is_one_partner_no_roles(self):
        requests=[]
        class Reply:
            status=202
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,_):return b'{"status":"Processing"}'
        class Opener:
            def open(self,request,timeout):
                requests.append((request,timeout))
                return Reply()
        with mock.patch.object(v.ssl,'create_default_context',return_value=object()) as tls, \
             mock.patch.object(v.urllib.request,'build_opener',return_value=Opener()):
            status=v.post_once('/p/ca.pem',(f'admin@{v.TENANT}','non-secret'),APP,PARTNER)
        self.assertEqual(status,202)
        tls.assert_called_once_with(cafile='/p/ca.pem')
        self.assertEqual(len(requests),1)
        req,timeout=requests[0]
        self.assertEqual(timeout,18)
        self.assertEqual(req.full_url,'https://localhost:9444'+v.SHARE_URL)
        self.assertEqual(req.get_method(),'POST')
        self.assertEqual(json.loads(req.data),v.body_for(APP,PARTNER))
        self.assertTrue(req.get_header('Authorization').startswith('Basic '))
        self.assertNotIn('non-secret',req.get_header('Authorization'))

    def test_wrong_actor_blocks_before_network(self):
        for actor in [('admin@brisa.identity.test','password'),('admin@carbon.super','password')]:
            with self.subTest(actor=actor[0]),self.assertRaisesRegex(v.Refuse,'AUTHORITY_UNVERIFIED'):
                v.post_once('/ca',actor,APP,PARTNER)

    def test_post_non_202_and_network_errors_never_accepted(self):
        class Reply:
            status=200
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,_):return b'{}'
        class Opener:
            def open(self,*_args,**_kwargs):return Reply()
        with mock.patch.object(v.ssl,'create_default_context',return_value=object()), \
             mock.patch.object(v.urllib.request,'build_opener',return_value=Opener()):
            with self.assertRaisesRegex(v.Refuse,'POST_NOT_ACCEPTED'):
                v.post_once('/ca',(f'admin@{v.TENANT}','password'),APP,PARTNER)

    def test_no_extra_roles_hidden_by_missing_readback_role_mode(self):
        wrong={**ROW,'sharingMode':{'policy':v.POLICY},'roles':[{'displayName':'Admin'}]}
        with self.assertRaisesRegex(v.Refuse,'SHARED_ROLES_PRESENT'):
            v.classify([wrong],None,[MAPPING],APP,PARTNER,ROOT)

if __name__=='__main__':unittest.main()
