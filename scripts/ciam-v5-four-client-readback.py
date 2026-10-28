#!/usr/bin/env python3
"""Read-only management API audit across four clients; NO writes, secrets, tokens."""
import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
mod = runpy.run_path(str(ROOT/'deploy/ciam-v10/phase4/business-bootstrap.py'))
resources = mod['resources']
spec, tenants, oidc, _ = mod['context']()
expected = spec['businessApi']['identifier']
expected_scopes = {x['name'] for x in spec['businessApi']['scopes']}
result = {'stage':'CIAM_V5_FOUR_CLIENT_REMOTE_READBACK', 'remoteWrites':0,
          'positiveBrowserAuthentication':'NOT_TESTED','clients':{}}
remote = resources.HTTPS()
for brand in ('aurora','brisa'):
    authorization=mod['auth'](tenants,brand)
    base=mod['api_base'](brand)
    for channel in ('web','app'):
        key=f'{brand}-{channel}'
        client=oidc['tenants'][brand]['clients'][channel]
        app_id=client['id']
        path=f'/applications/{app_id}'
        protocol_status,protocol=mod['call'](remote,'GET',base+path+'/inbound-protocols/oidc',authorization)
        resource_status,resources_list=mod['call'](remote,'GET',base+path+'/authorized-apis',authorization)
        if protocol_status!=200 or resource_status!=200 or not isinstance(protocol,dict) or not isinstance(resources_list,list):
            raise SystemExit(f'REFUSED: {key} OIDC/APIs readback HTTP {protocol_status}/{resource_status}')
        audience=(protocol.get('idToken') or {}).get('audience') or []
        if isinstance(audience,str):audience=[audience]
        if not isinstance(audience,list) or not all(isinstance(x,str) for x in audience):
            raise SystemExit(f'REFUSED: {key} unexpected audience schema')
        matches=[x for x in resources_list if isinstance(x,dict) and x.get('identifier')==expected]
        if len(matches)!=1:
            raise SystemExit(f'REFUSED: {key} expected exactly one business API authorization, found {len(matches)}')
        scopes={x.get('name') for x in matches[0].get('authorizedScopes',[]) if isinstance(x,dict)}
        result['clients'][key]={
            'oidcJwtConfigured':(protocol.get('accessToken') or {}).get('type')=='JWT',
            'businessApiAuthorizedRBAC':matches[0].get('policyId')=='RBAC',
            'businessScopesExact':scopes==expected_scopes,
            'profileAudienceConfigured':'https://api.ciam-v10.test/profile' in audience,
            'businessAudienceConfigured':expected in audience,
            'requestedClientReadback':'VERIFIED',
            'positiveRuntime':'NOT_TESTED'
        }
print(json.dumps(result,indent=2))
if not all(v['oidcJwtConfigured'] and v['businessApiAuthorizedRBAC'] and v['businessScopesExact'] for v in result['clients'].values()):
    raise SystemExit('REFUSED: SECURITY_CONFIGURATION_DRIFT')
