#!/usr/bin/env python3
"""Read-only assessment of case RBAC evidence in an existing private inspection report.
No identity writes or secrets; never prints user IDs or raw role data.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

SCOPES = frozenset({'ciam:cases:create','ciam:cases:read','ciam:cases:review','ciam:cases:approve'})
EXPECTED = {'aurora': {'customer': ('ana.costa','rafael.nunes'), 'seller': ('marcos.oliveira',)},
            'brisa': {'customer': ('ana.costa',), 'seller': ()}}
NEED = {'customer': {'ciam:cases:create', 'ciam:cases:read'},
        'seller': {'ciam:cases:review', 'ciam:cases:approve'}}

def check(data):
    results = {}
    tenants = data.get('runtime', {}).get('tenants', {})
    for brand, personas in EXPECTED.items():
        errors = []
        tenant = tenants.get(brand, {})
        if not isinstance(tenant,dict) or not isinstance(tenant.get('apiResources'),list):
            results[brand] = ['TENANT_INVENTORY_NOT_AVAILABLE']; continue
        apis = [a for a in tenant['apiResources'] if isinstance(a,dict)
                and set(a.get('scopes',[])) & SCOPES]
        if len(apis) != 1 or not SCOPES.issubset(set(apis[0].get('scopes',[]))):
            errors.append('CASES_API_RESOURCE_OR_SCOPES_NOT_PROVEN')
        users = {u.get('userName'):u.get('id') for u in tenant.get('users',[]) if isinstance(u,dict)}
        roles = tenant.get('roles', [])
        apps = tenant.get('applications', [])
        for channel in ('web','app'):
            oidc = tenant.get('expectedClients',{}).get(channel,{})
            appid = oidc.get('journalAppId')
            matching = [a for a in apps if a.get('id') == appid]
            if oidc.get('readback') != 'COMPLETE' or len(matching) != 1:
                errors.append('OIDC_CLIENT_READBACK_INCOMPLETE_'+channel)
                continue
            grants = matching[0].get('authorizedAPIs',[])
            if not apis or not isinstance(grants, list) or not any(a.get('id') == apis[0].get('id') and SCOPES.issubset(set(a.get('authorizedScopes') or [])) for a in grants if isinstance(a, dict)):
                errors.append('CLIENT_API_AUTHORIZATION_NOT_PROVEN_'+channel)
            for role_name, names in personas.items():
                for username in names:
                    userid=users.get(username)
                    if not userid:
                        errors.append('EXPECTED_USER_NOT_PRESENT_'+role_name)
                        continue
                    candidate = [r for r in roles if r.get('detailsState') == 'COMPLETE'
                       and isinstance(r.get('audience'), dict) and r['audience'].get('value') == appid
                       and userid in r.get('users',[]) and NEED[role_name].issubset(set(r.get('permissions',[])))]
                    if not candidate:
                        errors.append('REQUIRED_APP_ROLE_NOT_PROVEN_'+channel+'_'+role_name)
                    if role_name == 'customer':
                        groups = tenant.get('groups', [])
                        if any(g.get('membersState') != 'COMPLETE' for g in groups):
                            errors.append('GROUP_ASSIGNMENTS_NOT_VERIFIED')
                        members = {g.get('id') for g in groups if userid in (g.get('members') or [])}
                        for r in roles:
                            if r.get('detailsState') != 'COMPLETE':
                                errors.append('ROLE_DETAILS_NOT_VERIFIED'); continue
                            audience = r.get('audience')
                            if not isinstance(audience,dict) or audience.get('value') != appid:
                                continue
                            assigned = userid in (r.get('users') or []) or bool(members & set(r.get('groups') or []))
                            if assigned and set(r.get('permissions') or []) & {'ciam:cases:review','ciam:cases:approve'}:
                                errors.append('CUSTOMER_HAS_PRIVILEGED_CASE_SCOPE_'+channel)
        results[brand] = sorted(set(errors)) or ['READBACK_REQUIREMENTS_SATISFIED_NOT_RUNTIME_AUTHENTICATION']
    return results

def main():
    p=argparse.ArgumentParser()
    p.add_argument('report', type=Path,help='PRIVATE existing inspection.json')
    args=p.parse_args()
    data=json.loads(args.report.read_text())
    result=check(data)
    for brand,codes in result.items():
        print(brand.upper()+': '+', '.join(codes))
    return 0 if all(v==['READBACK_REQUIREMENTS_SATISFIED_NOT_RUNTIME_AUTHENTICATION'] for v in result.values()) else 2

if __name__=='__main__': sys.exit(main())
