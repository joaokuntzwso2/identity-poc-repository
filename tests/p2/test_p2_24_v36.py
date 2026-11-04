import importlib.util
import pathlib
import tempfile
import unittest

HERE=pathlib.Path(__file__).resolve().parent
SOURCE_DIR = HERE if (HERE/'p2_24_v36_prepare.py').is_file() else HERE.parents[1]/'scripts'/'p2'

def load(name, filename):
    spec=importlib.util.spec_from_file_location(name,SOURCE_DIR/filename)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj)
    return obj

p=load('v36prep','p2_24_v36_prepare.py')
v=load('v36impl','p2_24_v36_full_automatic_directory_bootstrap.py')

ORIGINAL='''V17_SHA='fea42472a4a91d4d04c368131ae4e569b5dc1aa8ce8eb5fe8040ccee344f6a53'
ACTOR_SCHEMA='p2.24.aurora.partner-directory-actor.v18'
SCOPES=tuple(sorted((
  'internal_org_user_mgt_list','internal_org_user_mgt_view','internal_org_user_mgt_create',
  'internal_org_group_mgt_list','internal_org_group_mgt_view','internal_org_group_mgt_create')))
def actor_check():
    for a in authz:
        names=[]
        need(len(names)==3 and len(set(names))==3 and a['id'] not in groups,
             'V18_ACTOR_SCOPE_RESOURCE_AMBIGUOUS')
    need(sorted(allscopes)==list(SCOPES) and len(set(allscopes))==6 and
         all(set(x)==set(SCOPES[:3]) or set(x)==set(SCOPES[3:]) for x in groups.values()),
         'V18_ACTOR_EXCESS_OR_MISSING_PERMISSION')
'''

class Tests(unittest.TestCase):
    def test_five_scopes_exact(self):
        self.assertEqual(set(p.SCOPES),set(v.FIVE_SCOPES))
        self.assertEqual(len(p.SCOPES),5)
        self.assertNotIn('internal_org_group_mgt_list',p.SCOPES)
    def test_patch_v18_idempotent_and_strict(self):
        result,changed=p.convert_v18(ORIGINAL)
        self.assertTrue(changed)
        self.assertNotIn("'internal_org_group_mgt_list'",result)
        self.assertIn('len(names) in (2,3)',result)
        self.assertIn('V18_ORGANIZATION_SCOPE_CONTRACT_V36',result)
        self.assertEqual((result,False),p.convert_v18(result))
    def test_reject_drifted_source(self):
        with self.assertRaises(p.Problem):p.convert_v18(ORIGINAL.replace('len(set(allscopes))==6','len(set(allscopes))==100'))
    def test_group_api_authorization_three_plus_two(self):
        rr={'Users':('11111111-1111-1111-1111-111111111111',sorted(x for x in p.SCOPES if 'user_mgt' in x)),
            'Groups':('22222222-2222-2222-2222-222222222222',sorted(x for x in p.SCOPES if 'group_mgt' in x))}
        rows=[{'id':rid,'policyIdentifier':'RBAC','authorizedScopes':[{'name':s} for s in scopes]} for rid,scopes in rr.values()]
        self.assertTrue(v.authorizations_exact(rows,rr,p.SCOPES))
        for extra in ('internal_org_group_mgt_list','internal_org_user_mgt_delete','internal_group_mgt_view'):
            bad=[dict(x, authorizedScopes=list(x['authorizedScopes'])) for x in rows]
            bad[1]['authorizedScopes'].append({'name':extra})
            self.assertFalse(v.authorizations_exact(bad,rr,p.SCOPES))
    def test_scope_resource_different_family_rejected(self):
        u,g='11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222'
        class API:
            def get(self,path):
                if path.endswith('?limit=100'):
                    return {'totalResults':2,'APIResources':[
                      {'id':u,'identifier':'https://a.example/o/scim2/Users'},
                      {'id':g,'identifier':'https://a.example/scim2/Groups'}]}
                names=[{'name':s} for s in p.SCOPES if ('user_mgt' if u in path else 'group_mgt') in s]
                return names if path.endswith('/scopes') else {'id':u if u in path else g,'scopes':names}
        with self.assertRaises(v.CatalogError):v.resource_discovery(API(),p.SCOPES)
    def test_scope_resource_positive_with_matching_detail(self):
        u,g='11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222'
        class API:
            def get(self,path):
                if path.endswith('?limit=100'):
                    return {'totalResults':2,'APIResources':[
                      {'id':u,'identifier':'https://a.example/o/scim2/Users'},
                      {'id':g,'identifier':'https://a.example/o/scim2/Groups'}]}
                names=[{'name':s} for s in p.SCOPES if ('user_mgt' if u in path else 'group_mgt') in s]
                return names if path.endswith('/scopes') else {'id':u if u in path else g,'scopes':names}
        resources=v.resource_discovery(API(),p.SCOPES)
        self.assertEqual(set(resources),{'Users','Groups'})
        self.assertEqual(len(resources['Users'][1]),3)
        self.assertEqual(len(resources['Groups'][1]),2)
    def test_reject_disagreement_between_scopes_and_detail(self):
        u,g='11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222'
        class API:
            def get(self,path):
                if path.endswith('?limit=100'):
                    return {'totalResults':2,'APIResources':[
                      {'id':u,'identifier':'https://a.example/o/scim2/Users'},
                      {'id':g,'identifier':'https://a.example/o/scim2/Groups'}]}
                names=[{'name':s} for s in p.SCOPES if ('user_mgt' if u in path else 'group_mgt') in s]
                if path.endswith('/scopes'):return names
                return {'id':u if u in path else g,'scopes':names[:-1]}
        with self.assertRaises(v.CatalogError):v.resource_discovery(API(),p.SCOPES)
    def test_one_attempt_lock_persists_after_ack(self):
        class FakeAPI:
            def __init__(self):self.count=0
            def call(self,method,path,body):self.count+=1;return 202,{},{}
        with tempfile.TemporaryDirectory() as d:
            s=v.Store(pathlib.Path(d)/'journal.private.json');s.create('partner')
            api=FakeAPI()
            s.attempt('SHARE_ACTOR','POST',v.APP_PATH+'/share',api,{}, {202})
            with self.assertRaises(v.Block):s.attempt('SHARE_ACTOR','POST',v.APP_PATH+'/share',api,{}, {202})
            self.assertEqual(api.count,1)
            s2=v.Store(pathlib.Path(d)/'journal.private.json')
            with self.assertRaises(v.Block):s2.attempt('SHARE_ACTOR','POST',v.APP_PATH+'/share',api,{}, {202})
            self.assertEqual(api.count,1)
    def test_app_scopes_no_broad_role_or_root(self):
        self.assertTrue(all(x.startswith('internal_org_') for x in p.SCOPES))
        self.assertTrue(all(not any(z in x for z in ('delete','update','role','application')) for x in p.SCOPES))
    def test_existing_journal_never_truncated(self):
        with tempfile.TemporaryDirectory() as d:
            f=pathlib.Path(d)/'existing.private.json'
            a=v.Store(f);a.create('partner')
            b=v.Store(f)
            with self.assertRaises(v.Block):b.create('partner')
            self.assertEqual(b.doc['partnerId'],'partner')

if __name__=='__main__':unittest.main(verbosity=2)
