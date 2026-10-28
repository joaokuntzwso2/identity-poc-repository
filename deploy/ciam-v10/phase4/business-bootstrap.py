#!/usr/bin/env python3
"""Journaled WSO2 IS 7.3 business authorization provisioner.

Reuses existing resources HTTPS/auth and tenant/oidc/identity journals.
Creates NEW application-scoped roles, never modifies v10 seed roles.
Does not run as part of fresh-bootstrap until independently verified.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import urllib.parse

HERE = Path(__file__).resolve().parent
V10 = HERE.parent
SPEC = importlib.util.spec_from_file_location('ciam_resources', V10/'resources/bootstrap.py')
resources = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resources)
Refuse = resources.Refuse
SPEC_FILE = HERE/'desired.json'
JOURNAL = resources.ROOT/'private/bootstrap-business-v4.private.json'
ROLE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:2.0:Role'
CONFIRM = 'CREATE_CIAM_BUSINESS_API_AND_ROLES_V4'


def read_private(p):
    result = resources.private_read(p)
    if not isinstance(result, dict): raise Refuse('JOURNAL_INVALID')
    return result


def context():
    desired = json.loads(SPEC_FILE.read_text())
    if desired.get('schema') != 'ciampoc.real-iam.phase4.v1': raise Refuse('SPEC_SCHEMA_INVALID')
    t = read_private(resources.TENANT_FILE)
    o = read_private(resources.ROOT/'private/bootstrap-oidc-v10.private.json')
    a = read_private(resources.ROOT/'private/bootstrap-authority-v10.private.json')
    i = read_private(resources.ROOT/'private/bootstrap-identities-v10.private.json')
    if a.get('acceptance') != 'API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED':
        raise Refuse('FOUNDATION_NOT_VERIFIED')
    if a.get('roleApiVersion') != 'v2':
        raise Refuse('ROLE_API_PIN_NOT_V2_REFUSE_MIGRATION')
    for brand in resources.DOMAINS:
        if i['tenants'][brand]['tenantId'] != t['tenants'][brand]['tenantId']:
            raise Refuse('TENANT_DRIFT')
        for channel in ('web', 'app'):
            if o['tenants'][brand]['clients'][channel]['state'] != 'verified':
                raise Refuse('OIDC_CLIENT_NOT_VERIFIED')
    api = desired['businessApi']
    if sorted(s['name'] for s in api['scopes']) != sorted(set(s['name'] for s in api['scopes'])):
        raise Refuse('DUPLICATE_SCOPES')
    if not all(set(v).issubset({s['name'] for s in api['scopes']}) for v in api['rolePermissions'].values()):
        raise Refuse('UNKNOWN_ROLE_PERMISSION')
    return desired, t, o, i


def auth(t, brand):
    return resources.basic(resources.OWNER+'@'+resources.DOMAINS[brand], t['tenants'][brand]['owner']['password'])


def call(client, method, path, credential, data=None):
    code, body, headers = client.call(method, path, auth=credential, data=data)
    return code, body


def read(client, path, credential):
    code, body = call(client, 'GET', path, credential)
    if code != 200: raise Refuse(f'GET_FAILED_{code}_{path.split("?")[0]}')
    return body


def api_base(brand):
    return '/t/'+resources.DOMAINS[brand]+'/api/server/v1'


def role_base(brand):
    return '/t/'+resources.DOMAINS[brand]+'/scim2/v2/Roles'


def api_record(client, cred, brand, identifier):
    query = urllib.parse.urlencode({'filter':f'identifier eq {identifier}', 'limit':20})
    body = read(client, api_base(brand)+'/api-resources?'+query, cred)
    # Accept an omitted collection only for an explicit zero-result response.
    if not isinstance(body, dict):
        raise Refuse('API_RESOURCE_LIST_UNEXPECTED_SCHEMA_TYPE_' + type(body).__name__)

    count = body.get('totalResults')
    if 'APIResources' in body and 'apiResources' in body:
        raise Refuse('API_RESOURCE_LIST_AMBIGUOUS_COLLECTION_KEYS')
    items = body.get('apiResources', body.get('APIResources'))

    if (
        items is None
        and type(count) is int
        and count == 0
        and set(body) <= {'totalResults', 'links', 'APIResources'}
    ):
        items = []

    if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
        keys = ','.join(sorted(map(str, body.keys())))
        raise Refuse('API_RESOURCE_LIST_UNEXPECTED_SCHEMA_KEYS_' + keys)

    if type(count) is not int or count != len(items):
        raise Refuse('API_RESOURCE_PAGINATION_UNVERIFIED')

    links = body.get('links') or []
    if not isinstance(links, list) or any(not isinstance(x, dict) for x in links):
        raise Refuse('API_RESOURCE_LINKS_UNEXPECTED_SCHEMA')

    if any(x.get('rel') == 'next' for x in links):
        raise Refuse('API_RESOURCE_PAGINATION_REFUSED')

    matches = [x for x in items if x.get('identifier') == identifier]

    if len(matches) > 1:
        raise Refuse('DUPLICATE_API_RESOURCE')

    return matches[0] if matches else None


def role_record(client, cred, brand, name, app_id):
    params = urllib.parse.urlencode({'filter':f'displayName eq "{name}"', 'count':100})
    body = read(client, role_base(brand)+'?'+params, cred)
    if not isinstance(body, dict): raise Refuse('SCIM_ROLE_RESPONSE_UNEXPECTED')
    rs = body.get('Resources') or []
    if body.get('totalResults', len(rs)) > len(rs): raise Refuse('ROLE_PAGINATION_REFUSED')
    matches = [x for x in rs if x.get('displayName') == name]
    if len(matches) > 1: raise Refuse('ROLE_NAME_COLLISION')
    if matches and matches[0].get('audience') != {'value':app_id,'type':'application'}:
        # Some responses add audience display; check the stable keys.
        aud = matches[0].get('audience',{})
        if aud.get('type') != 'application' or aud.get('value') != app_id:
            raise Refuse('ROLE_AUDIENCE_COLLISION')
    return matches[0] if matches else None


def verified_role(client, cred, brand, role_id, name, app_id, members, scopes):
    obj = read(client, role_base(brand)+'/'+role_id, cred)
    if obj.get('id') != role_id or obj.get('displayName') != name:
        raise Refuse('ROLE_ID_DRIFT')
    if obj.get('audience',{}).get('value') != app_id:
        raise Refuse('ROLE_AUDIENCE_DRIFT')
    if {x.get('value') for x in obj.get('permissions',[])} != set(scopes):
        raise Refuse('ROLE_PERMISSIONS_DRIFT')
    if {x.get('value') for x in obj.get('users',[])} != set(members):
        raise Refuse('ROLE_MEMBERS_DRIFT')
    return True


def verified_api(client, cred, brand, api_id, spec):
    data = read(client, api_base(brand)+'/api-resources/'+api_id, cred)
    if data.get('identifier') != spec['identifier'] or data.get('requiresAuthorization') is not True:
        raise Refuse('API_RESOURCE_DRIFT')
    entries = read(client, api_base(brand)+'/api-resources/'+api_id+'/scopes', cred)
    if not isinstance(entries, list): raise Refuse('API_SCOPES_SCHEMA_UNEXPECTED')
    if {x['name'] for x in entries} != {x['name'] for x in spec['scopes']}:
        raise Refuse('API_SCOPE_DRIFT')
    return True


def journal_init(spec):
    return {'schema':'ciampoc.v4.business-journal.v1',
        'specSha256':hashlib.sha256(SPEC_FILE.read_bytes()).hexdigest(),
        'tenants':{b:{'api':{},'apps':{},'roles':{}} for b in resources.DOMAINS}}


def execute(mode):
    spec,t,o,identities = context()
    state = resources.private_read(JOURNAL, False) or journal_init(spec)
    if state.get('schema') != 'ciampoc.v4.business-journal.v1' or state.get('specSha256') != journal_init(spec)['specSha256']:
        raise Refuse('BUSINESS_JOURNAL_DRIFT')
    if mode == 'apply' and os.environ.get('WSO2_CIAM_V4_BUSINESS_CONFIRM') != CONFIRM:
        raise Refuse('EXPLICIT_BUSINESS_CONFIRMATION_REQUIRED')
    remote = resources.HTTPS()
    cred = {b:auth(t,b) for b in resources.DOMAINS}
    api_spec = spec['businessApi']
    plans = []
    # preflight validates all remote collisions/owned ids before any writes
    for brand in resources.DOMAINS:
        node = state['tenants'][brand]
        found = api_record(remote, cred[brand], brand, api_spec['identifier'])
        if found and not node['api'].get('id'): raise Refuse('UNJOURNALED_API_COLLISION_'+brand)
        if node['api'].get('id') and (not found or found.get('id') != node['api']['id']):
            raise Refuse('API_MISSING_OR_DRIFT_'+brand)
        for channel in ('web','app'):
            appid = o['tenants'][brand]['clients'][channel]['id']
            appnode = node['apps'].get(channel)
            authlist = read(remote, api_base(brand)+'/applications/'+appid+'/authorized-apis', cred[brand])
            if not isinstance(authlist, list): raise Refuse('AUTHORIZED_APIS_SCHEMA_UNEXPECTED')
            matching = [x for x in authlist if x.get('identifier') == api_spec['identifier']]
            if len(matching) > 1: raise Refuse('AUTHORIZED_APIS_DUPLICATE')
            if matching and not appnode: raise Refuse('UNJOURNALED_API_AUTH_COLLISION')
            if appnode and appnode.get('id') != appid: raise Refuse('APP_ID_DRIFT')
            for kind, scopes in api_spec['rolePermissions'].items():
                if kind not in {p.get('kind') for p in identities['tenants'][brand]['users'].values()}:
                    continue
                key = channel+':'+kind
                name = 'CIAM Business '+kind.title()+' '+channel.upper()
                role = role_record(remote, cred[brand], brand, name, appid)
                rn = node['roles'].get(key)
                if role and not rn: raise Refuse('UNJOURNALED_BUSINESS_ROLE_COLLISION_'+key)
                if rn and (not role or role['id'] != rn['id']): raise Refuse('BUSINESS_ROLE_MISSING_OR_DRIFT')
        plans.append({'brand':brand,'apiExists':bool(found), 'rolesRecorded':len(node['roles'])})
    if mode == 'plan':
        return {'stage':'CIAM_BUSINESS_V4','mode':'PLAN','remoteWrites':0,'plan':plans}
    def save(): resources.atomic_save(JOURNAL, state)
    if mode == 'apply':
        save()
        for brand in resources.DOMAINS:
            node = state['tenants'][brand]
            c = cred[brand]
            if not node['api'].get('id'):
                node['api'] = {'state':'post-started'}; save()
                status,_ = call(remote,'POST',api_base(brand)+'/api-resources',c,{
                    'name':api_spec['name'], 'identifier':api_spec['identifier'],
                    'description':api_spec['description'],'requiresAuthorization':True,
                    'scopes':api_spec['scopes']})
                if status not in (200,201): raise Refuse('API_POST_UNCERTAIN_NO_RETRY_'+str(status))
                found = api_record(remote,c,brand,api_spec['identifier'])
                if not found or not found.get('id'): raise Refuse('API_POST_NO_READBACK_NO_RETRY')
                node['api'] = {'state':'verified','id':found['id']};save()
            api_id = node['api']['id']
            verified_api(remote,c,brand,api_id,api_spec)
            for channel in ('web','app'):
                appid = o['tenants'][brand]['clients'][channel]['id']
                if channel not in node['apps']:
                    node['apps'][channel] = {'id':appid,'state':'post-started'};save()
                    status,_ = call(remote,'POST',api_base(brand)+'/applications/'+appid+'/authorized-apis',c,{
                        'id':api_id,'policyIdentifier':'RBAC',
                        'scopes':[s['name'] for s in api_spec['scopes']]})
                    # HTTP 200 or 201 must be followed by remote readback.
                    if status not in (200, 201):
                        raise Refuse('API_AUTH_POST_UNCERTAIN_'+str(status))
                    node['apps'][channel]['state']='created';save()
                authlist = read(remote,api_base(brand)+'/applications/'+appid+'/authorized-apis',c)
                matching = [x for x in authlist if x.get('identifier') == api_spec['identifier']]
                if len(matching)!=1 or {x['name'] for x in matching[0].get('authorizedScopes',[])} != {s['name'] for s in api_spec['scopes']}:
                    raise Refuse('API_AUTH_READBACK_DRIFT')
                policy = matching[0].get(
                    'policyId',
                    matching[0].get('policyIdentifier')
                )
                if policy != 'RBAC':
                    raise Refuse('API_AUTH_POLICY_DRIFT')
                node['apps'][channel]['state']='verified';save()
                for kind, scopes in api_spec['rolePermissions'].items():
                    members = [x['id'] for x in identities['tenants'][brand]['users'].values() if x['kind']==kind]
                    if not members: continue
                    key=channel+':'+kind
                    name='CIAM Business '+kind.title()+' '+channel.upper()
                    if key not in node['roles']:
                        node['roles'][key]={'state':'post-started'};save()
                        status,_=call(remote,'POST',role_base(brand),c,{
                            'schemas':[ROLE_SCHEMA],'displayName':name,
                            'audience':{'value':appid,'type':'application'},
                            'permissions':[{'value':scope} for scope in scopes],
                            'users':[{'value':m} for m in members]})
                        if status not in (200,201): raise Refuse('ROLE_POST_UNCERTAIN_'+str(status))
                        found=role_record(remote,c,brand,name,appid)
                        if not found or not found.get('id'):raise Refuse('ROLE_POST_NO_READBACK')
                        node['roles'][key]={'state':'verified','id':found['id']};save()
                    verified_role(remote,c,brand,node['roles'][key]['id'],name,appid,members,scopes)
        return {'stage':'CIAM_BUSINESS_V4','mode':'APPLY','remoteWrites':'JOURNALED','readback':'VERIFIED'}
    if mode == 'verify':
        for brand in resources.DOMAINS:
            node=state['tenants'][brand];c=cred[brand]
            api_id=node['api'].get('id')
            if not api_id: raise Refuse('API_NOT_PROVISIONED')
            verified_api(remote,c,brand,api_id,api_spec)
            for channel in ('web','app'):
                appid=o['tenants'][brand]['clients'][channel]['id']
                authlist=read(remote,api_base(brand)+'/applications/'+appid+'/authorized-apis',c)
                match=[x for x in authlist if x.get('identifier')==api_spec['identifier']]
                if len(match)!=1 or {x['name'] for x in match[0].get('authorizedScopes',[])} != {x['name'] for x in api_spec['scopes']}:
                    raise Refuse('API_AUTH_NOT_VERIFIED')
                policy = match[0].get(
                    'policyId',
                    match[0].get('policyIdentifier')
                )
                if policy != 'RBAC':
                    raise Refuse('API_AUTH_POLICY_DRIFT')
                for kind,scopes in api_spec['rolePermissions'].items():
                    members=[x['id'] for x in identities['tenants'][brand]['users'].values() if x['kind']==kind]
                    if not members: continue
                    key=channel+':'+kind
                    n=node['roles'].get(key)
                    if not n or n.get('state')!='verified':raise Refuse('BUSINESS_ROLE_NOT_VERIFIED')
                    verified_role(remote,c,brand,n['id'],'CIAM Business '+kind.title()+' '+channel.upper(),appid,members,scopes)
        return {'stage':'CIAM_BUSINESS_V4','mode':'VERIFY','readback':'VERIFIED','businessRuntime':'NOT_TESTED'}
    raise Refuse('UNKNOWN_MODE')

if __name__ == '__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('plan','apply','verify'):
            raise Refuse('USAGE: business-bootstrap.py plan|apply|verify')
        print(json.dumps(execute(sys.argv[1]),indent=2))
    except (Refuse, KeyError, ValueError, OSError, TypeError) as e:
        print('REFUSED: '+str(e),file=sys.stderr)
        sys.exit(2)
