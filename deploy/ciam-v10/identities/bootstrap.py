#!/usr/bin/env python3
"""Additive WSO2 IS 7.3 SCIM users/application roles, journaled and fail-closed.

Uses the repo's existing authenticated HTTPS client and the EXISTING tenant,
application and authority journals. Does not provision unsupported B2B/MFA/
consent/agent flows. This is a resource-creation stage, not an acceptance test.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import urllib.parse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = importlib.util.spec_from_file_location('ciam_resources', ROOT / 'resources/bootstrap.py')
resources = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resources)
Refuse = resources.Refuse
DOMAINS = resources.DOMAINS
STATE = resources.ROOT / 'private/bootstrap-identities-v10.private.json'
LOCK = resources.ROOT / 'private/bootstrap-identities-v10.lock'
CONFIRM = 'CREATE_DEMO_PEOPLE_AND_APP_ROLES'
SCOPE = 'ciam:profile:read'
SEED = HERE / 'seed.json'
ROLE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:2.0:Role'


def load():
    doc = json.loads(SEED.read_text())
    if doc.get('schema') != 'ciampoc.iam.real-identities.v1':
        raise Refuse('SEED_SCHEMA_MISMATCH')
    people = doc.get('people')
    if not isinstance(people, list) or len(people) != 6:
        raise Refuse('SEED_PEOPLE_MISMATCH')
    seen = set()
    for p in people:
        if (p.get('key') in seen or
            not re.fullmatch(r'[a-z0-9.-]{3,64}', p.get('username', '')) or
            not p.get('givenName') or not p.get('familyName') or
            not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', p.get('email','')) or
            p.get('type') not in doc['roleLabels'] or
            not p.get('brands') or not set(p['brands']).issubset(DOMAINS)):
            raise Refuse('UNSAFE_OR_DUPLICATE_SEED')
        seen.add(p['key'])
    if doc.get('implementedPermissionAssignments') != {'customer': [SCOPE]}:
        raise Refuse('UNAPPROVED_PERMISSION_CHANGE')
    return doc


def context():
    ts = resources.private_read(resources.TENANT_FILE)
    rs = resources.private_read(resources.STATE_FILE)
    oj = resources.private_read(resources.ROOT / 'private/bootstrap-oidc-v10.private.json')
    aj = resources.private_read(resources.ROOT / 'private/bootstrap-authority-v10.private.json')
    resources.validate_state(rs, ts)
    if (ts.get('schema') != 'identity.wso2.ciam.v10.tenants' or
        ts.get('base') != resources.BASE or ts.get('domains') != DOMAINS or
        rs.get('acceptance') != 'MANAGEMENT_AND_USERS_VERIFIED_OIDC_NOT_PROVISIONED' or
        aj.get('acceptance') != 'API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED' or
        oj.get('schema') != 'identity.wso2.ciam.v10.oidc.v1'):
        raise Refuse('FOUNDATION_OR_AUTHORITY_NOT_VERIFIED')
    version = aj.get('roleApiVersion')
    if version not in ('v2', 'v3'):
        raise Refuse('AUTHORITY_ROLE_API_VERSION_INVALID')
    if version == 'v2' and os.getenv('WSO2_CIAM_V10_ROLE_V2_CONFIRM') != 'USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES':
        raise Refuse('V2_ROLE_API_REQUIRES_EXPLICIT_APPROVAL')
    for b, domain in DOMAINS.items():
        if (ts['tenants'][b].get('domain') != domain or
            ts['tenants'][b].get('status') != 'readback-verified' or
            not ts['tenants'][b].get('owner', {}).get('password') or
            oj['tenants'][b].get('tenantId') != ts['tenants'][b].get('tenantId')):
            raise Refuse('TENANT_CONTEXT_DRIFT_' + b)
        for channel in ('web','app'):
            record = oj['tenants'][b].get('clients', {}).get(channel, {})
            if (record.get('state') != 'verified' or
                not resources.ID.fullmatch(str(record.get('id', '')))):
                raise Refuse('OIDC_APPLICATION_NOT_VERIFIED_' + b + '_' + channel)
    return ts, oj, version


def auth_of(ts, brand):
    return resources.basic(resources.OWNER + '@' + DOMAINS[brand], ts['tenants'][brand]['owner']['password'])


def required(client, path, auth):
    code, body, _ = client.call('GET', path, auth=auth)
    if code != 200 or not isinstance(body, dict):
        raise Refuse('REMOTE_READ_FAILED_HTTP_' + str(code))
    return body


def user_path(brand):
    return '/t/' + DOMAINS[brand] + '/scim2/Users'


def role_path(brand, version):
    return '/t/' + DOMAINS[brand] + '/scim2/' + version + '/Roles'


def exact_user(client, brand, auth, username):
    query = urllib.parse.urlencode({'filter': 'userName eq "' + username + '"', 'count':'100', 'startIndex':'1'})
    doc = required(client, user_path(brand) + '?' + query, auth)
    entries = resources.collection(doc, ('Resources', 'resources'))
    if doc.get('totalResults') != len(entries):
        raise Refuse('USER_PAGINATION_UNSAFE')
    matched = [x for x in entries if x.get('userName','').removeprefix('PRIMARY/') == username]
    if len(matched) > 1: raise Refuse('DUPLICATE_SCIM_USER')
    return matched[0] if matched else None


def exact_role(client, brand, version, auth, name, appid):
    query = urllib.parse.urlencode({'filter':'displayName eq "' + name + '"', 'count':'100', 'startIndex':'1'})
    doc = required(client, role_path(brand, version) + '?' + query, auth)
    entries = resources.collection(doc, ('Resources', 'resources'))
    if doc.get('totalResults', len(entries)) > len(entries):
        raise Refuse('ROLE_PAGINATION_UNSAFE')
    matched = [x for x in entries if x.get('displayName') == name]
    if len(matched) > 1: raise Refuse('DUPLICATE_ROLE')
    if matched and (matched[0].get('audience',{}).get('type') != 'application' or matched[0].get('audience',{}).get('value') != appid):
        raise Refuse('ROLE_AUDIENCE_COLLISION')
    return matched[0] if matched else None


def verify_user(client, brand, auth, p, node):
    found = exact_user(client, brand, auth, p['username'])
    if not found:
        return None
    identity = found.get('id')
    if (not resources.ID.fullmatch(str(identity)) or
        found.get('externalId') != node.get('externalId') or
        (node.get('id') and node['id'] != identity)):
        raise Refuse('SCIM_USER_NOT_OWNED_' + brand + '_' + p['key'])
    detail = required(client, user_path(brand) + '/' + identity, auth)
    if (detail.get('id') != identity or detail.get('externalId') != node['externalId'] or
        detail.get('active') is False or
        detail.get('name', {}).get('givenName') != p['givenName'] or
        detail.get('name', {}).get('familyName') != p['familyName'] or
        not any(e.get('value','').lower()==p['email'].lower() for e in detail.get('emails', []) if isinstance(e,dict))):
        raise Refuse('SCIM_USER_READBACK_DRIFT_' + brand + '_' + p['key'])
    return identity


def verify_role(client, brand, version, auth, name, appid, members, expected_permissions, node):
    found = exact_role(client, brand, version, auth, name, appid)
    if not found: return None
    rid = found.get('id')
    if not resources.ID.fullmatch(str(rid)) or (node.get('id') and node['id'] != rid):
        raise Refuse('ROLE_ID_DRIFT')
    detail = required(client, role_path(brand, version) + '/' + rid, auth)
    if (detail.get('id') != rid or detail.get('displayName') != name or
        (detail.get('audience',{}).get('type') != 'application' or detail.get('audience',{}).get('value') != appid)):
        raise Refuse('ROLE_DETAIL_DRIFT')
    actual_members = {m.get('value') for m in detail.get('users', []) if isinstance(m, dict)}
    actual_permissions = {m.get('value') for m in detail.get('permissions', []) if isinstance(m, dict)}
    if actual_members != set(members) or actual_permissions != set(expected_permissions):
        raise Refuse('ROLE_MEMBERS_OR_PERMISSIONS_DRIFT_' + name)
    return rid


def initial(ts, version, seed):
    return {'schema':'identity.wso2.ciam.v10.real-people.v1',
            'base':resources.BASE,
            'roleApiVersion':version,
            'seed':seed['schema'],'seedHash':hashlib.sha256(SEED.read_bytes()).hexdigest(),
            'tenants':{b:{'tenantId':ts['tenants'][b]['tenantId'],'users':{},'roles':{}} for b in DOMAINS}}


def execute(mode):
    seed = load()
    ts, oj, version = context()
    state = resources.private_read(STATE, False) or initial(ts, version, seed)
    expected = initial(ts, version, seed)
    if any(state.get(k) != expected[k] for k in ('schema','base','roleApiVersion','seed','seedHash')):
        raise Refuse('IDENTITY_JOURNAL_HEADER_DRIFT')
    for b in DOMAINS:
        if state.get('tenants',{}).get(b,{}).get('tenantId') != expected['tenants'][b]['tenantId']:
            raise Refuse('IDENTITY_JOURNAL_TENANT_DRIFT')
    if mode == 'apply' and os.getenv('WSO2_CIAM_V10_IDENTITIES_CONFIRM') != CONFIRM:
        raise Refuse('EXPLICIT_IDENTITY_PROVISIONING_CONFIRMATION_REQUIRED')
    client = resources.HTTPS()
    credentials = {b: auth_of(ts,b) for b in DOMAINS}
    # Read-only preflight EVERY object before any write; no adoption of unjournaled resources.
    for b in DOMAINS:
        auth = credentials[b]
        users = state['tenants'][b]['users']
        roles = state['tenants'][b]['roles']
        for p in seed['people']:
            if b not in p['brands']: continue
            found = exact_user(client,b,auth,p['username'])
            node = users.get(p['key'])
            if found and not node: raise Refuse('UNJOURNALED_USER_COLLISION_' + b + '_' + p['key'])
            if node and (node.get('username') != p['username'] or node.get('kind') != p['type']):
                raise Refuse('USER_JOURNAL_DEFINITION_DRIFT')
            if found and node: verify_user(client,b,auth,p,node)
            if not found and node and node.get('state') in ('created','verified'):
                raise Refuse('PREVIOUSLY_CREATED_USER_MISSING')
        for channel in ('web','app'):
            appid = oj['tenants'][b]['clients'][channel]['id']
            # Fail closed if application role audience was changed after initial provisioning.
            app = required(client,'/t/'+DOMAINS[b]+'/api/server/v1/applications/'+appid,auth)
            if app.get('associatedRoles',{}).get('allowedAudience') != 'APPLICATION':
                raise Refuse('APP_ROLE_AUDIENCE_NOT_APPLICATION')
            for kind, label in seed['roleLabels'].items():
                if not any(b in p['brands'] and p['type']==kind for p in seed['people']): continue
                key = channel + ':' + kind
                name = 'CIAM Demo ' + label + ' ' + channel.upper()
                found = exact_role(client,b,version,auth,name,appid)
                if found and key not in roles: raise Refuse('UNJOURNALED_ROLE_COLLISION_' + b + '_' + key)
                if key in roles and roles[key].get('name') != name:
                    raise Refuse('ROLE_JOURNAL_DEFINITION_DRIFT')
                if not found and key in roles and roles[key].get('state') in ('created','verified'):
                    raise Refuse('PREVIOUSLY_CREATED_ROLE_MISSING')
    if mode == 'plan':
        return {'stage':'REAL_IDENTITY_SEED','mode':'READ_ONLY','remoteWrites':0,
                'people':len(seed['people']), 'perTenantMemberships':{b:sum(b in p['brands'] for p in seed['people']) for b in DOMAINS},
                'note':'Roles for unsupported scenarios have no action permissions'}
    if mode == 'verify':
        for b in DOMAINS:
            users=state['tenants'][b]['users'];roles=state['tenants'][b]['roles'];auth=credentials[b]
            for p in seed['people']:
                if b not in p['brands']:continue
                n=users.get(p['key'])
                if not n or n.get('state')!='verified' or not verify_user(client,b,auth,p,n):
                    raise Refuse('USER_NOT_VERIFIED')
            expected_role_keys = {channel+':'+p['type'] for channel in ('web','app') for p in seed['people'] if b in p['brands']}
            if set(roles) != expected_role_keys: raise Refuse('EXPECTED_ROLE_CATALOG_INCOMPLETE')
            for key,n in roles.items():
                channel,kind=key.split(':',1)
                appid=oj['tenants'][b]['clients'][channel]['id']
                members=[users[p['key']]['id'] for p in seed['people'] if b in p['brands'] and p['type']==kind]
                perms=seed['implementedPermissionAssignments'].get(kind,[])
                if n.get('state')!='verified' or not verify_role(client,b,version,auth,n['name'],appid,members,perms,n):
                    raise Refuse('ROLE_NOT_VERIFIED')
        return {'stage':'REAL_IDENTITY_SEED','mode':'VERIFY','users':'READBACK_VERIFIED',
                'roles':'READBACK_VERIFIED','interactiveLogins':'NOT_VERIFIED',
                'syntheticPortals':'NOT_REPLACED_BY_THIS_STAGE'}
    if mode != 'apply': raise Refuse('USAGE_PLAN_APPLY_VERIFY')
    def save():resources.atomic_save(STATE,state)
    save()
    for b in DOMAINS:
        auth=credentials[b];usernodes=state['tenants'][b]['users']
        for p in seed['people']:
            if b not in p['brands']:continue
            node=usernodes.get(p['key'])
            if node is None:
                node={'username':p['username'],'kind':p['type'],'externalId':'ciampoc-'+secrets.token_hex(16),
                      'password':resources.password(), 'state':'prepared'}
                usernodes[p['key']]=node;save()
            if node.get('state') not in ('prepared','post-started','created','verified'):
                raise Refuse('UNKNOWN_USER_STATE')
            existing=verify_user(client,b,auth,p,node)
            if existing:
                node['id']=existing;node['state']='verified';save();continue
            if node['state'] != 'prepared':
                raise Refuse('UNCERTAIN_USER_POST_NO_RETRY')
            node['state']='post-started';save()
            payload={'schemas':['urn:ietf:params:scim:schemas:core:2.0:User'],
                     'userName':p['username'],'password':node['password'],'externalId':node['externalId'],
                     'name':{'givenName':p['givenName'],'familyName':p['familyName']},
                     'displayName':p['givenName']+' '+p['familyName'],
                     'emails':[{'value':p['email'],'primary':True}], 'active':True}
            status,_,_=client.call('POST',user_path(b),auth=auth,data=payload)
            if status != 201: raise Refuse('SCIM_CREATE_UNCERTAIN_HTTP_'+str(status)+'_NO_RETRY')
            uid=verify_user(client,b,auth,p,node)
            if not uid: raise Refuse('SCIM_POST_NO_READBACK_NO_RETRY')
            node['id']=uid;node['state']='verified';save()
    for b in DOMAINS:
        auth=credentials[b];usernodes=state['tenants'][b]['users'];rolenodes=state['tenants'][b]['roles']
        for channel in ('web','app'):
            appid=oj['tenants'][b]['clients'][channel]['id']
            for kind,label in seed['roleLabels'].items():
                matching=[p for p in seed['people'] if b in p['brands'] and p['type']==kind]
                if not matching:continue
                key=channel+':'+kind
                name='CIAM Demo '+label+' '+channel.upper()
                members=[usernodes[p['key']]['id'] for p in matching]
                perms=seed['implementedPermissionAssignments'].get(kind,[])
                node=rolenodes.get(key)
                if node is None:
                    node={'name':name,'state':'prepared','applicationId':appid}
                    rolenodes[key]=node;save()
                if node.get('applicationId')!=appid:raise Refuse('ROLE_APPLICATION_JOURNAL_DRIFT')
                found=verify_role(client,b,version,auth,name,appid,members,perms,node)
                if found:
                    node['id']=found;node['state']='verified';save();continue
                if node['state']!='prepared':raise Refuse('UNCERTAIN_ROLE_POST_NO_RETRY')
                node['state']='post-started';save()
                payload={'schemas':[ROLE_SCHEMA],'displayName':name,
                         'audience':{'value':appid,'type':'application'},
                         'permissions':[{'value':value} for value in perms],
                         'users':[{'value':mid} for mid in members]}
                status,_,_=client.call('POST',role_path(b,version),auth=auth,data=payload)
                if status not in (200,201):raise Refuse('ROLE_POST_UNCERTAIN_HTTP_'+str(status)+'_NO_RETRY')
                rid=verify_role(client,b,version,auth,name,appid,members,perms,node)
                if not rid:raise Refuse('ROLE_POST_NO_READBACK_NO_RETRY')
                node['id']=rid;node['state']='verified';save()
    return {'stage':'REAL_IDENTITY_SEED','mode':'APPLY','users':'READBACK_VERIFIED',
            'roles':'READBACK_VERIFIED','interactiveLogins':'NOT_VERIFIED',
            'syntheticPortals':'NOT_REPLACED_BY_THIS_STAGE'}


def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('plan','apply','verify'):
        raise Refuse('USAGE: python3 deploy/ciam-v10/identities/bootstrap.py {plan|apply|verify}')
    fd=None
    try:
        if sys.argv[1]=='apply':
            fd=os.open(LOCK,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            os.write(fd,str(os.getpid()).encode())
        result=execute(sys.argv[1])
        print(json.dumps(result,indent=2))
    finally:
        if fd is not None:
            os.close(fd);LOCK.unlink()

if __name__=='__main__':
    try:main()
    except (Refuse, OSError, ValueError, KeyError, TypeError) as exc:
        print('REFUSED: '+str(exc),file=sys.stderr)
        sys.exit(2)
