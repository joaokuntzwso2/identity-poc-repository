#!/usr/bin/env python3
"""Guarded additive v10 business API/RBAC stage. No modifications to existing journals.

Scope: two existing tenants, four existing OIDC apps, and two existing SCIM users.
Every write is prepared in a 0600 private journal, followed by exact readback.
Unknown outcomes are never retried; reconcile is strictly read-only.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import urllib.parse

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('v10_existing_resources', HERE.parent / 'resources/bootstrap.py')
resources = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resources)
ROOT = resources.ROOT
PRIVATE = ROOT / 'private'
JOURNAL = PRIVATE / 'bootstrap-authority-v10.private.json'
LOCK = PRIVATE / 'bootstrap-authority-v10.lock'
TENANTS = resources.TENANT_FILE
RESOURCES = resources.STATE_FILE
OIDC = PRIVATE / 'bootstrap-oidc-v10.private.json'
DOMAINS = resources.DOMAINS
API_IDENTIFIER = 'https://api.ciam-v10.test/profile'
API_SCOPE = 'ciam:profile:read'
API_NAME = 'CIAM v10 Profile API'
CONFIRM = 'AUTHORIZE_EXISTING_V10_OIDC_AND_ASSIGN_SCIM_USERS'
ROLE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:2.0:Role'
Refuse = resources.Refuse
ID = resources.ID


def private_context():
    tenants = resources.private_read(TENANTS)
    rs = resources.private_read(RESOURCES)
    oidc = resources.private_read(OIDC)
    resources.validate_state(rs, tenants)
    if (tenants.get('schema') != 'identity.wso2.ciam.v10.tenants' or tenants.get('base') != resources.BASE or tenants.get('domains') != DOMAINS):
        raise Refuse('TENANT_JOURNAL_CONTEXT_INVALID')
    if rs.get('acceptance') != 'MANAGEMENT_AND_USERS_VERIFIED_OIDC_NOT_PROVISIONED':
        raise Refuse('EXISTING_RESOURCE_JOURNAL_NOT_VERIFIED')
    if oidc.get('schema') != 'identity.wso2.ciam.v10.oidc.v1' or oidc.get('base') != resources.BASE:
        raise Refuse('OIDC_JOURNAL_CONTEXT_INVALID')
    for brand, domain in DOMAINS.items():
        t = tenants['tenants'][brand]
        r = rs['tenants'][brand]
        o = oidc.get('tenants', {}).get(brand, {})
        if (t.get('domain') != domain or t.get('status') != 'readback-verified' or
            t.get('owner', {}).get('username') != resources.OWNER or
            not t.get('owner', {}).get('password') or
            r.get('management', {}).get('state') != 'verified' or
            r.get('user', {}).get('state') != 'verified-browser-not-tested' or
            not ID.fullmatch(str(r.get('user', {}).get('id', ''))) or
            o.get('tenantId') != t.get('tenantId') or
            o.get('domain') != domain or o.get('managementAppId') != r['management']['id']):
            raise Refuse('OWNERSHIP_OR_IDENTITY_NOT_VERIFIED_' + brand)
        for channel in ('web', 'app'):
            app = o.get('clients', {}).get(channel, {})
            if (app.get('state') != 'verified' or not ID.fullmatch(str(app.get('id', '')))
                or not app.get('clientId') or app.get('domain') != domain):
                raise Refuse('OIDC_CHANNEL_NOT_VERIFIED_' + brand + '_' + channel)
    return tenants, rs, oidc


def new_journal(tenants, oidc):
    return {'schema': 'identity.wso2.ciam.v10.authority.v1', 'base': resources.BASE,
            'apiIdentifier': API_IDENTIFIER, 'scope': API_SCOPE,
            'tenants': {b: {'domain': d, 'tenantId': tenants['tenants'][b]['tenantId'],
                            'apps': {c: oidc['tenants'][b]['clients'][c]['id'] for c in ('web','app')}}
                        for b,d in DOMAINS.items()},
            'acceptance': 'NOT_VERIFIED'}


def read_journal(tenants, oidc):
    expected = new_journal(tenants, oidc)
    result = resources.private_read(JOURNAL, False) or expected
    for k in ('schema', 'base', 'apiIdentifier', 'scope'):
        if result.get(k) != expected[k]: raise Refuse('AUTHORITY_JOURNAL_CONTEXT_DRIFT_'+k)
    for brand in DOMAINS:
        for k in ('domain', 'tenantId', 'apps'):
            if result.get('tenants',{}).get(brand,{}).get(k) != expected['tenants'][brand][k]:
                raise Refuse('AUTHORITY_JOURNAL_TENANT_DRIFT_'+brand+'_'+k)
    return result


def tenant_auth(tenants, brand):
    o = tenants['tenants'][brand]['owner']
    return resources.basic(resources.OWNER + '@' + DOMAINS[brand], o['password'])


def get(client, path, auth):
    response = client.call('GET', path, auth=auth)
    if response[0] != 200: raise Refuse('READ_FAILED_HTTP_'+str(response[0])+'_'+('ROLES_V3' if '/v3/Roles' in path else 'AUTHORITY'))
    return response[1]


def role_path(brand):
    return '/t/' + DOMAINS[brand] + '/scim2/v3/Roles'


def api_path(brand):
    return '/t/' + DOMAINS[brand] + '/api/server/v1/api-resources'


def app_path(brand, app_id):
    if not ID.fullmatch(app_id): raise Refuse('UNSAFE_APP_ID')
    return '/t/' + DOMAINS[brand] + '/api/server/v1/applications/' + app_id


def exact_catalog(client, brand, auth):
    query = urllib.parse.urlencode({'filter': 'identifier eq ' + API_IDENTIFIER, 'limit': '100'})
    data = get(client, api_path(brand)+'?'+query, auth)
    rows = resources.collection(data, ('APIResources','apiResources','resources','list'))
    if isinstance(data,dict) and isinstance(data.get('totalResults'),int) and data['totalResults']>len(rows):
        raise Refuse('RESOURCE_CATALOG_PAGINATION_UNSAFE')
    matches = [x for x in rows if isinstance(x,dict) and x.get('identifier') == API_IDENTIFIER]
    if len(matches) > 1: raise Refuse('DUPLICATE_BUSINESS_RESOURCE_'+brand)
    return matches[0] if matches else None


def verified_resource_detail(client, brand, auth, resource, node):
    """Refuse collision/adoption unless the private, pre-POST owner marker matches."""
    if not isinstance(resource, dict) or not isinstance(node, dict):
        raise Refuse('BUSINESS_API_OWNER_NOT_JOURNALED')
    if not isinstance(node.get('ownerMarker'),str) or not re.fullmatch(r'ciam-v10-[a-f0-9]{32}',node['ownerMarker']):
        raise Refuse('BUSINESS_API_MARKER_MISSING')
    rid=resource.get('id')
    if not ID.fullmatch(str(rid)):
        raise Refuse('BUSINESS_API_ID_UNSAFE')
    detail=get(client,api_path(brand)+'/'+rid,auth)
    if (detail.get('id')!=rid or detail.get('identifier')!=API_IDENTIFIER or
        detail.get('description')!=node['ownerMarker'] or
        detail.get('requiresAuthorization') is not True):
        raise Refuse('BUSINESS_API_OWNERSHIP_OR_POLICY_NOT_VERIFIED')
    return resource


def resource_scopes(client, brand, auth, resource_id):
    if not ID.fullmatch(str(resource_id)): raise Refuse('RESOURCE_ID_UNSAFE')
    data = get(client, api_path(brand)+'/'+resource_id+'/scopes', auth)
    rows = resources.collection(data, ('scopes',),empty_allowed=False)
    return {x if isinstance(x,str) else x.get('name') if isinstance(x,dict) else None for x in rows}


def role_name(channel):
    return 'CIAM v10 Profile Reader '+channel.upper()


def role_matches(client, brand, channel, auth, app_id):
    # Exact query; do not invent a matching role based on a substring.
    query = urllib.parse.urlencode({'filter':'displayName eq "'+role_name(channel)+'"', 'count': '100', 'startIndex': '1'})
    data = get(client, role_path(brand)+'?'+query, auth)
    rows = resources.collection(data, ('Resources','resources'))
    if isinstance(data, dict) and isinstance(data.get('totalResults'),int) and data['totalResults']>len(rows):
        raise Refuse('ROLES_V3_PAGINATION_UNSAFE')
    matches=[x for x in rows if isinstance(x,dict) and x.get('displayName')==role_name(channel)]
    if len(matches)>1: raise Refuse('ROLES_V3_NOT_UNIQUE')
    if matches:
        audience=matches[0].get('audience',{})
        if audience.get('type')!='application' or audience.get('value')!=app_id:
            raise Refuse('ROLES_V3_AUDIENCE_COLLISION_'+brand+'_'+channel)
    return matches[0] if matches else None


def role_readback(client, brand, auth, role_id, app_id, user_id, channel):
    if not ID.fullmatch(str(role_id)):raise Refuse('ROLE_ID_UNSAFE')
    data=get(client,role_path(brand)+'/'+role_id,auth)
    if not isinstance(data,dict) or data.get('id')!=role_id or data.get('displayName')!=role_name(channel):
        raise Refuse('ROLE_READBACK_IDENTITY_INVALID')
    audience=data.get('audience',{})
    if audience.get('type')!='application' or audience.get('value')!=app_id:
        raise Refuse('ROLE_READBACK_WRONG_AUDIENCE')
    # Absence of assignments or permissions in GET is NOT proof of success.
    ps={p.get('value') for p in data.get('permissions',[]) if isinstance(p,dict)}
    users={p.get('value') for p in data.get('users',[]) if isinstance(p,dict)}
    if API_SCOPE not in ps or user_id not in users:raise Refuse('ROLE_READBACK_PERMISSIONS_OR_USERS_NOT_VERIFIED')
    return True


def plan(client, tenants, rs, oidc, journal):
    result={'stage':'CIAM_V10_AUTHORITY','mode':'GET_ONLY','remoteWrites':0,'tenants':{},'safeToApply':True}
    for brand in DOMAINS:
        auth=tenant_auth(tenants,brand)
        resource=exact_catalog(client,brand,auth)
        rnode=journal['tenants'][brand].get('resource')
        resource_state='ABSENT'
        if resource:
            if not ID.fullmatch(str(resource.get('id',''))):raise Refuse('RESOURCE_UNSAFE_ID')
            if rnode is None:raise Refuse('UNJOURNALED_BUSINESS_API_COLLISION_'+brand)
            if rnode.get('id') not in (None,resource['id']):raise Refuse('RESOURCE_ID_DRIFT')
            verified_resource_detail(client,brand,auth,resource,rnode)
            resource_state='PRESENT_SCOPE_VERIFIED' if API_SCOPE in resource_scopes(client,brand,auth,resource['id']) else 'PRESENT_SCOPE_MISSING'
            if resource_state!='PRESENT_SCOPE_VERIFIED': result['safeToApply']=False
        elif rnode and rnode.get('state') not in ('prepared',):
            result['safeToApply']=False
            resource_state='MISSING_AFTER_JOURNALED_WRITE'
        role_status={}
        for channel in ('web','app'):
            app_id=oidc['tenants'][brand]['clients'][channel]['id']
            app=get(client,app_path(brand,app_id),auth)
            if app.get('id')!=app_id or app.get('name')!=oidc['tenants'][brand]['clients'][channel]['name']:
                raise Refuse('OIDC_APP_REMOTE_DRIFT')
            auths=resources.auth_list(client,brand,auth,app_id)
            authorized='ABSENT'
            if resource:
                xs=[x for x in auths if isinstance(x,dict) and x.get('id')==resource['id']]
                if len(xs)>1:raise Refuse('DUPLICATE_API_AUTHORIZATION')
                if xs:
                    authorized='SCOPE_VERIFIED' if API_SCOPE in resources.scope_names(xs[0]) else 'PARTIAL_UNSAFE'
                    if authorized!='SCOPE_VERIFIED':result['safeToApply']=False
                    if journal['tenants'][brand].get('authorizations',{}).get(channel,{}).get('state') is None:
                        raise Refuse('UNJOURNALED_API_AUTHORIZATION_COLLISION_'+brand+'_'+channel)
            auth_node=journal['tenants'][brand].get('authorizations',{}).get(channel,{})
            if authorized=='ABSENT' and auth_node.get('state') in ('verified','post-started'):
                result['safeToApply']=False
                authorized='REMOVED_OR_UNCERTAIN_DO_NOT_REGRANT'
            r=role_matches(client,brand,channel,auth,app_id)
            role_node=journal['tenants'][brand].get('role_'+channel,{})
            if r and not role_node:
                raise Refuse('UNJOURNALED_BUSINESS_ROLE_COLLISION_'+brand+'_'+channel)
            if r and role_node.get('state')=='verified':
                role_readback(client,brand,auth,r['id'],app_id,rs['tenants'][brand]['user']['id'],channel)
            role_state='PRESENT' if r else 'ABSENT'
            if not r and role_node.get('state') in ('verified','create-started'):
                result['safeToApply']=False
                role_state='REMOVED_OR_UNCERTAIN_DO_NOT_RECREATE'
            role_status[channel]={'apiAuthorization':authorized,'role':role_state}
        result['tenants'][brand]={'businessAPI':resource_state,'channels':role_status}
    return result


def guarded_create(client, journal, tenant_node, key, payload, path, auth, save, readback):
    """Only a previously journaled write or a fresh owned write is admissible."""
    node=tenant_node.setdefault(key, {'state':'prepared'})
    if node.get('state') not in ('prepared','create-started','verified'):
        raise Refuse('UNKNOWN_WRITE_STATE_'+key)
    if node['state']=='create-started':
        # For the caller to recover an interrupted response it must first perform exact readback.
        found=readback()
        if not found:raise Refuse('UNCERTAIN_WRITE_NO_READBACK_'+key+'_DO_NOT_RETRY')
        node['id']=found['id'];node['state']='verified';save()
        return node['id']
    if node['state']=='verified':
        found=readback()
        if not found or found.get('id')!=node.get('id'):
            raise Refuse('PREVIOUSLY_VERIFIED_RESOURCE_MISSING_'+key)
        return node['id']
    if readback():raise Refuse('UNJOURNALED_REMOTE_OBJECT_COLLISION_'+key)
    node['state']='create-started';save()  # durable journal BEFORE POST
    response=client.call('POST',path,auth=auth,data=payload)
    if response[0] not in (200,201):
        raise Refuse('CREATE_UNCERTAIN_HTTP_'+str(response[0])+'_'+key+'_DO_NOT_RETRY')
    found=readback()
    if not found or not ID.fullmatch(str(found.get('id',''))):
        raise Refuse('CREATE_UNCERTAIN_READBACK_'+key+'_DO_NOT_RETRY')
    node['id']=found['id'];node['state']='verified';save()
    return node['id']


def apply(client, tenants, rs, oidc, journal, save):
    if os.environ.get('WSO2_CIAM_V10_AUTHORITY_CONFIRM') != CONFIRM:
        raise Refuse('EXPLICIT_AUTHORITY_WRITE_CONFIRMATION_REQUIRED')
    # All tenants must pass GET preflight before any mutation.
    inventory=plan(client,tenants,rs,oidc,journal)
    if not inventory['safeToApply']:raise Refuse('READ_ONLY_PRECHECK_NOT_SAFE_FOR_WRITES')
    result={'stage':'CIAM_V10_AUTHORITY','mode':'APPLY','tenants':{},'status':'NOT_YET_VERIFIED'}
    for brand in DOMAINS:
        auth=tenant_auth(tenants,brand)
        own=journal['tenants'][brand]
        domain=DOMAINS[brand]
        if 'resource' not in own:
            own['resource']={'state':'prepared','ownerMarker':'ciam-v10-'+secrets.token_hex(16)};save()
        def found_api():
            item=exact_catalog(client,brand,auth)
            return verified_resource_detail(client,brand,auth,item,own['resource']) if item else None
        rid=guarded_create(client,journal,own,'resource',{
            'name':API_NAME,'identifier':API_IDENTIFIER,'description':own['resource']['ownerMarker'],
            'requiresAuthorization':True,
            'scopes':[{'name':API_SCOPE,'displayName':'Read CIAM Profile','description':'Read protected profile metadata'}]},
            api_path(brand),auth,save,found_api)
        if API_SCOPE not in resource_scopes(client,brand,auth,rid):raise Refuse('BUSINESS_SCOPE_NOT_VERIFIED_'+brand)
        out={}
        for channel in ('web','app'):
            app_id=oidc['tenants'][brand]['clients'][channel]['id']
            appauth=app_path(brand,app_id)+'/authorized-apis'
            a=own.setdefault('authorizations',{}).setdefault(channel,{'state':'prepared'})
            def auth_readback():
                xs=[x for x in resources.auth_list(client,brand,auth,app_id) if isinstance(x,dict) and x.get('id')==rid]
                if len(xs)>1:raise Refuse('DUPLICATE_AUTHORIZATION')
                if xs and API_SCOPE not in resources.scope_names(xs[0]):raise Refuse('PARTIAL_SCOPE_GRANT_REFUSED')
                return bool(xs)
            if auth_readback():
                if a['state']=='prepared':raise Refuse('UNJOURNALED_API_AUTHORIZATION_COLLISION')
                a['state']='verified';save()
            elif a['state']!='prepared':
                raise Refuse('UNCERTAIN_OR_REVOKED_AUTHORIZATION_DO_NOT_RETRY')
            else:
                a['state']='post-started';save()
                status=client.call('POST',appauth,auth=auth,data={'id':rid,'policyIdentifier':'RBAC','scopes':[API_SCOPE]})[0]
                if status not in (200,201) or not auth_readback():
                    raise Refuse('API_AUTHORIZATION_UNCERTAIN_DO_NOT_RETRY')
                a['state']='verified';save()
            user_id=rs['tenants'][brand]['user']['id']
            def found_role():
                found=role_matches(client,brand,channel,auth,app_id)
                if found:
                    role_readback(client,brand,auth,found['id'],app_id,user_id,channel)
                return found
            role_id=guarded_create(client,journal,own,'role_'+channel,{
                'schemas':[ROLE_SCHEMA], 'displayName':role_name(channel),
                'audience':{'value':app_id,'type':'application'},
                'permissions':[{'value':API_SCOPE,'display':'Read CIAM Profile'}],
                'users':[{'value':user_id}]},role_path(brand),auth,save,found_role)
            role_readback(client,brand,auth,role_id,app_id,user_id,channel)
            out[channel]={'authorizedScope':'READBACK_VERIFIED','roleAndUser':'READBACK_VERIFIED'}
        result['tenants'][brand]=out
    journal['acceptance']='API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED';save()
    result['status']='PROVISIONING_READBACK_VERIFIED_BROWSER_NOT_TESTED'
    return result


def diagnostic(client, tenants, rs, oidc):
    report={'stage':'CIAM_V10_AUTHORITY_DIAGNOSTIC', 'methods':['GET'], 'remoteWrites':0,
            'server':resources.BASE, 'tenantStates':{}, 'updateLevel':'NOT_PROVEN_BY_HTTP'}
    for brand,domain in DOMAINS.items():
        owner=tenants['tenants'][brand]['owner']
        auth=tenant_auth(tenants,brand)
        bare=resources.basic(resources.OWNER,owner['password'])
        paths={'apiResources':api_path(brand)+'?limit=1',
               'rolesV3':role_path(brand)+'?count=1&startIndex=1',
               'rolesV2':'/t/'+domain+'/scim2/v2/Roles?count=1&startIndex=1',
               'consentV2':'/t/'+domain+'/api/identity/consent-mgt/v2.0/purposes?limit=1'}
        out={}
        for label,path in paths.items():
            out[label]={'tenantQualifiedBasic':client.call('GET',path,auth=auth)[0],
                        'bareBasic':client.call('GET',path,auth=bare)[0]}
        # Never print server-generated error bodies or authentication challenges.
        report['tenantStates'][brand]=out
    return report



def consolidated_evidence(client, tenants, rs, oidc):
    """No management mutation. A token grant is POST-but-not-a-resource-write."""
    evidence=diagnostic(client,tenants,rs,oidc)
    evidence['stage']='CIAM_V10_AUTHORITY_CONSOLIDATED_EVIDENCE'
    evidence['methods']=['GET','POST_OAUTH_TOKEN_ONLY']
    evidence['remoteWrites']=0
    evidence['consent']=consent_status(client,tenants)['tenants']
    evidence['m2mScopes']={}
    scope_targets={'role':'internal_role_mgt_view','consent':'internal_consent_mgt_purpose_view'}
    for brand,domain in DOMAINS.items():
        m=rs['tenants'][brand]['management']
        if not m.get('clientId') or not m.get('clientSecret'):raise Refuse('M2M_CLIENT_JOURNAL_INCOMPLETE')
        output={}
        # Authenticate ONLY the pre-existing, tenant-scoped client. Do not change grants.
        for kind,scope in scope_targets.items():
            token_response=client.call('POST','/t/'+domain+'/oauth2/token',
                 auth=resources.basic(m['clientId'],m['clientSecret']),
                 form={'grant_type':'client_credentials','scope':scope})
            status, body=token_response[:2]
            granted=(status==200 and isinstance(body,dict) and
                     body.get('token_type','').lower()=='bearer' and
                     scope in str(body.get('scope','')).split() and
                     bool(body.get('access_token')))
            output[kind]={'tokenHttp':status,'requiredScopeIssued':granted,
                          'apiHttp':'NOT_CHECKED_MISSING_SCOPE'}
            if granted:
                url=role_path(brand)+'?count=1&startIndex=1' if kind=='role' else                     '/t/'+domain+'/api/identity/consent-mgt/v2.0/purposes?limit=1'
                output[kind]['apiHttp']=client.call('GET',url,
                    auth='Bearer '+body['access_token'])[0]
        evidence['m2mScopes'][brand]=output
    # Local Docker introspection is optional. No config contents, env, command line
    # arguments, raw errors or WSO2 updater files are exported to the report.
    name='wso2-ciam-v10-is-1'
    conf=os.path.join(os.sep, 'home', 'wso2carbon', 'wso2is-7.3.0', 'repository', 'conf', 'deployment.toml')
    evidence['container']={'name':name,'running':'UNKNOWN',
        'consentV2Setting':'UNKNOWN','updateLevel':'NOT_ESTABLISHED_FROM_DOCKER_IMAGE_TAG'}
    try:
        p=subprocess.run(['docker','inspect','-f','{{.State.Running}}',name],
             capture_output=True,timeout=5,text=True)
        if p.returncode==0 and p.stdout.strip() in ('true','false'):
            evidence['container']['running']=p.stdout.strip().upper()
        p=subprocess.run(['docker','exec',name,'sh','-c',
             'grep -Eq "^[[:space:]]*enable_v2_api[[:space:]]*=[[:space:]]*true" '+conf],
             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8)
        if evidence['container']['running']=='TRUE':
            evidence['container']['consentV2Setting']='ENABLED' if p.returncode==0 else 'NOT_ENABLED_OR_NOT_READABLE'
    except (OSError,subprocess.TimeoutExpired):pass
    return evidence

def consent_status(client,tenants):
    out={'stage':'CIAM_V10_CONSENT_V2_CAPABILITY','methods':['GET'], 'remoteWrites':0,
         'feature':'NOT_VERIFIED_LIVE','updateLevel':'NOT_PROVEN','tenants':{}}
    for brand,domain in DOMAINS.items():
        auth=tenant_auth(tenants,brand)
        url='/t/'+domain+'/api/identity/consent-mgt/v2.0/purposes?limit=1'
        code=client.call('GET',url,auth=auth)[0]
        out['tenants'][brand]={'tenantQualifiedBasicHTTP':code,
            'capability':'ACCESSIBLE_WITH_THIS_AUTH' if code==200 else 'NOT_VERIFIED'}
    return out


def status(journal):
    return {'stage':'CIAM_V10_AUTHORITY_STATUS','remoteWrites':0,
            'acceptance':journal.get('acceptance','NOT_VERIFIED'),
            'tenants':{b:{'resource':journal['tenants'][b].get('resource',{}).get('state','NOT_STARTED'),
                          'authorizedChannels':{c:journal['tenants'][b].get('authorizations',{}).get(c,{}).get('state','NOT_STARTED') for c in ('web','app')},
                          'roleChannels':{c:journal['tenants'][b].get('role_'+c,{}).get('state','NOT_STARTED') for c in ('web','app')}}
                       for b in DOMAINS}}


def main():
    command=sys.argv[1] if len(sys.argv)==2 else 'help'
    if command=='help':
        print('COMMANDS: authority-preflight authority-evidence authorization-plan authorization-apply authorization-reconcile consent-verify consent-plan consent-apply authority-status')
        return
    if command not in ('authority-preflight','authority-evidence','authorization-plan','authorization-apply','authorization-reconcile','consent-verify','consent-plan','consent-apply','authority-status'):
        raise Refuse('UNKNOWN_AUTHORITY_COMMAND')
    if Path.cwd().resolve()!=ROOT.resolve():raise Refuse('RUN_ONLY_FROM_V10_HOME')
    ts,rs,oidc=private_context()
    journal=read_journal(ts,oidc)
    if command=='authority-status': print(json.dumps(status(journal),indent=2));return
    if command in ('consent-plan','consent-apply'):
        # Contract + feature level must be proven before there is any safe consent write.
        print(json.dumps({'stage':'CIAM_V10_CONSENT','status':'BLOCKED',
                          'reason':'UPDATE_LEVEL_ACTIVATION_AUTH_AND_V2_CONTRACT_NOT_VERIFIED',
                          'remoteWrites':0,'noLocalConsentFallback':True},indent=2))
        if command=='consent-apply':raise Refuse('CONSENT_WRITES_REFUSED_UNVERIFIED_FEATURE')
        return
    client=resources.HTTPS()
    if command=='authority-preflight': outcome=diagnostic(client,ts,rs,oidc)
    elif command=='authority-evidence':outcome=consolidated_evidence(client,ts,rs,oidc)
    elif command=='consent-verify':outcome=consent_status(client,ts)
    elif command in ('authorization-plan','authorization-reconcile'):
        outcome=plan(client,ts,rs,oidc,journal)
        if command=='authorization-reconcile':outcome['mode']='READ_ONLY_RECONCILIATION'
    else:
        fd=None
        if os.environ.get('WSO2_CIAM_V10_AUTHORITY_CONFIRM')!=CONFIRM:raise Refuse('EXPLICIT_AUTHORITY_WRITE_CONFIRMATION_REQUIRED')
        if LOCK.exists() or LOCK.is_symlink():raise Refuse('AUTHORITY_LOCK_EXISTS_STOP')
        fd=os.open(LOCK,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:
            def save():resources.atomic_save(JOURNAL,journal)
            outcome=apply(client,ts,rs,oidc,journal,save)
        finally:
            os.close(fd);LOCK.unlink()
    print(json.dumps(outcome,indent=2))


if __name__=='__main__':
    try:main()
    except (Refuse,OSError,ValueError,KeyError,TypeError) as e:
        # A terse error name only: never print the exception's potentially sensitive data.
        print('CIAM_V10_AUTHORITY_REFUSED: '+type(e).__name__+(': '+str(e) if isinstance(e,Refuse) else ''),file=sys.stderr)
        sys.exit(1)
