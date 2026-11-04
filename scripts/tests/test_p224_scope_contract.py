"""Contract tests for WSO2 7.3 P2.24 organization-scoped bootstrap authority."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT=next((p for p in (Path(__file__).resolve().parents[1]/'scripts/p2-bootstrap-authority.py',
                         Path(__file__).resolve().parents[1]/'p2-bootstrap-authority.py') if p.is_file()), None)
if SCRIPT is None:raise RuntimeError('P2 authority script missing')
spec=importlib.util.spec_from_file_location('p224_contract',SCRIPT)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class ContractWire:
    def __init__(self,mode='dedicated'):
        self.mode=mode;self.calls=[]
        self.ids={name:'ID_'+str(i)+'__valid' for i,name in enumerate(a.POLICY)}
    def call(self,method,path,*,auth):
        self.calls.append((method,path,auth))
        assert method=='GET' and auth=='Basic owner'
        if path.startswith(a.CATALOG+'?'):
            return 200,{'APIResources':[{'id':rid,'identifier':name} for name,rid in self.ids.items()],
                        'totalResults':len(self.ids)},None
        for name,rid in self.ids.items():
            if path==a.CATALOG+'/'+rid:
                if self.mode=='embedded': scopes=[{'name':x} for x in a.POLICY[name]]
                elif self.mode=='malformed': scopes=[{'name':None}]
                elif self.mode=='incomplete': scopes=[{'name':'internal_org_organization_view'}]
                else: scopes=[]
                return 200,{'id':rid,'identifier':name,'scopes':scopes},None
            if path==a.CATALOG+'/'+rid+'/scopes':
                if self.mode=='404': return 404,{},None
                if self.mode=='malformed_list': return 200,{'scopeList':[]},None
                if self.mode=='absent' and name==a.GROUPS_ID: return 200,[],None
                return 200,[{'name':x} for x in a.POLICY[name]],None
        raise AssertionError(path)

class ScopeContractTests(unittest.TestCase):
    def test_only_org_context_apis_authorized(self):
        self.assertNotIn(a.ROOT_ID,a.POLICY)
        self.assertEqual(set(a.POLICY), {a.ORG_ID, a.USERS_ID, a.GROUPS_ID,
                                         a.APPS_ID, a.ROLES_ID})
        self.assertEqual(a.POLICY[a.ORG_ID],
                         ('internal_org_organization_view', 'internal_org_organization_create'))
        self.assertEqual(a.POLICY[a.USERS_ID],
                         ('internal_org_user_mgt_list', 'internal_org_user_mgt_view',
                          'internal_org_user_mgt_create', 'internal_org_user_mgt_update'))
        self.assertEqual(a.POLICY[a.GROUPS_ID],
                         ('internal_org_group_mgt_view', 'internal_org_group_mgt_create',
                          'internal_org_group_mgt_update'))
        self.assertEqual(a.POLICY[a.APPS_ID],
                         ('internal_org_application_mgt_view',
                          'internal_org_application_mgt_create',
                          'internal_org_application_mgt_update'))
        self.assertEqual(a.POLICY[a.ROLES_ID],
                         ('internal_org_role_mgt_view', 'internal_org_role_mgt_create',
                          'internal_org_role_mgt_update',
                          'internal_org_role_mgt_permissions_update',
                          'internal_org_role_mgt_users_update'))
        self.assertNotIn('internal_org_application_mgt_list',
                         a.POLICY[a.APPS_ID])
        self.assertTrue(all(identifier.startswith('/o/') for identifier in a.POLICY))
        self.assertEqual(a.ROOT_SCOPES,('internal_org_organization_view','internal_org_organization_create'))
        self.assertNotIn('internal_organization_create',a.ROOT_SCOPES)
    def test_dedicated_scope_endpoint_used_for_missing_embedded_scopes(self):
        w=ContractWire(); got=a.discovery(w,'Basic owner')
        self.assertEqual(set(got),set(a.POLICY))
        self.assertEqual(sum(p.endswith('/scopes') for _,p,_ in w.calls),len(a.POLICY))
        self.assertTrue(all(p.startswith('/t/aurora.identity.test/') for _,p,_ in w.calls))
    def test_complete_embedded_scopes_require_no_fallback(self):
        w=ContractWire('embedded');a.discovery(w,'Basic owner')
        self.assertFalse(any(p.endswith('/scopes') for _,p,_ in w.calls))
    def test_incomplete_embedded_scopes_use_verified_standalone_scopes(self):
        w=ContractWire('incomplete');self.assertEqual(len(a.discovery(w,'Basic owner')),len(a.POLICY))
        self.assertEqual(sum(p.endswith('/scopes') for _,p,_ in w.calls),len(a.POLICY))
    def test_truly_missing_group_scopes_fail_before_any_write(self):
        w=ContractWire('absent')
        with self.assertRaisesRegex(a.Stop,'API_RESOURCE_REQUIRED_SCOPE_UNSUPPORTED_groups_'):
            a.discovery(w,'Basic owner')
        self.assertTrue(all(m=='GET' for m,_,_ in w.calls))
    def test_missing_scopes_endpoint_is_blocked_not_guessed(self):
        w=ContractWire('404')
        with self.assertRaisesRegex(a.Stop,'API_RESOURCE_DEDICATED_SCOPES_READBACK_HTTP_404'):
            a.discovery(w,'Basic owner')
    def test_malformed_scopes_blocked(self):
        for mode,code in [('malformed','API_RESOURCE_SCOPE_LIST_MALFORMED'),
                          ('malformed_list','API_RESOURCE_DEDICATED_SCOPES_SHAPE_UNSUPPORTED')]:
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(a.Stop,code):a.discovery(ContractWire(mode),'Basic owner')

if __name__=='__main__':unittest.main()
