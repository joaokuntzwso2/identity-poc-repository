#!/usr/bin/env python3
"""WSO2 IS 7.3 local v10: journaled, tenant-qualified API provisioning.

Stage: 2 management M2M clients, scopes for Application API and SCIM2 Users,
2 non-admin SCIM users. No OIDC callback, browser-login, or SSO claim.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import tempfile
import urllib.parse

BASE = 'https://localhost:9444'
HOST, PORT = 'localhost', 9444
ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10')))
ADM_FILE = ROOT / 'private/admin.private.json'
TENANT_FILE = ROOT / 'private/bootstrap-tenants-v10.private.json'
STATE_FILE = ROOT / 'private/bootstrap-resources-v10.private.json'
LOCK_FILE = ROOT / 'private/bootstrap-resources-v10.lock'
DOMAINS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}
BRANDS = tuple(DOMAINS)
OWNER = 'labtenantadmin'
ID = re.compile(r'^[A-Za-z0-9_-]{5,256}={0,2}$')
USERNAMES = {'aurora': 'ciam_aurora', 'brisa': 'ciam_brisa'}
APP_RESOURCE = '/api/server/v1/applications'
USER_RESOURCE = '/scim2/Users'
APP_SCOPES = ('internal_application_mgt_view', 'internal_application_mgt_create', 'internal_application_mgt_client_secret_view')
USER_SCOPES = ('internal_user_mgt_list', 'internal_user_mgt_view', 'internal_user_mgt_create')
ALL_SCOPES = APP_SCOPES + USER_SCOPES

class Refuse(Exception):
    pass

def private_read(p, required=True):
    if p.is_symlink(): raise Refuse('PRIVATE_SYMLINK_REFUSED_' + p.name)
    if not p.exists():
        if required: raise Refuse('PRIVATE_FILE_MISSING_' + p.name)
        return None
    s = p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600:
        raise Refuse('PRIVATE_FILE_UNSAFE_' + p.name)
    return json.loads(p.read_text())

def atomic_save(p, value):
    if p.is_symlink(): raise Refuse('PRIVATE_TARGET_SYMLINK')
    if p.exists(): private_read(p)
    if not p.parent.is_dir() or p.parent.is_symlink() or stat.S_IMODE(p.parent.stat().st_mode) & 0o022:
        raise Refuse('PRIVATE_PARENT_UNSAFE')
    fd, tmp = tempfile.mkstemp(prefix='.ciam-resources-', dir=p.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(value, f, indent=2)
            f.write('\n')
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)
        dfd = os.open(p.parent, os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def create_lock():
    if LOCK_FILE.exists() or LOCK_FILE.is_symlink(): raise Refuse('EXISTING_BOOTSTRAP_LOCK_STOP')
    fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.write(fd, str(os.getpid()).encode()); os.fsync(fd)
    return fd

def release_lock(fd):
    os.close(fd); LOCK_FILE.unlink()

def basic(user, password):
    if not isinstance(user, str) or not isinstance(password, str) or not password:
        raise Refuse('INVALID_AUTH_CONTEXT')
    return 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()

class HTTPS:
    def __init__(self):
        cert = ssl.get_server_certificate((HOST, PORT))
        self.context = ssl.create_default_context(cadata=cert)
        self.context.check_hostname = False  # local only, cert trusted from local server

    def call(self, method, path, *, auth, data=None, form=None):
        if method not in ('GET','POST') or not path.startswith('/') or path.startswith('//') or '\\' in path or '..' in path or '#' in path:
            raise Refuse('UNSAFE_HTTP_REQUEST')
        if not (path.startswith('/t/aurora.identity.test/') or path.startswith('/t/brisa.identity.test/') or path.startswith('/api/server/v1/tenants/')):
            raise Refuse('HTTP_PATH_NOT_ALLOWED')
        headers = {'Authorization': auth, 'Accept': 'application/json'}
        if data is not None and form is not None: raise Refuse('INVALID_REQUEST_BODY')
        body = None
        if data is not None:
            headers['Content-Type'] = 'application/scim+json' if '/scim2/' in path else 'application/json'
            body = json.dumps(data)
        if form is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            body = urllib.parse.urlencode(form)
        c = http.client.HTTPSConnection(HOST, PORT, context=self.context, timeout=20)
        try:
            c.request(method, path, body=body, headers=headers)
            r = c.getresponse()
            raw = r.read(300001)
            if len(raw)>300000: raise Refuse('HTTP_RESPONSE_TOO_LARGE')
            if 300 <= r.status < 400: raise Refuse('HTTP_REDIRECT_REFUSED')
            try: obj = json.loads(raw) if raw else {}
            except (ValueError, UnicodeDecodeError):
                if 200 <= r.status < 300: raise Refuse('SUCCESS_RESPONSE_NOT_JSON')
                obj = {}
            return r.status, obj, r.getheader('Location')
        finally:
            c.close()

def require(resp, code, stage):
    if resp[0] != code:
        raise Refuse(stage+'_HTTP_'+str(resp[0]))
    return resp[1]

def scope_names(entry):
    values = entry.get('authorizedScopes', entry.get('scopes', []))
    if not isinstance(values, list): raise Refuse('AUTHORIZED_SCOPES_UNRECOGNIZED')
    out = []
    for v in values:
        value = v if isinstance(v, str) else v.get('name') if isinstance(v, dict) else None
        if not isinstance(value, str): raise Refuse('AUTHORIZED_SCOPE_SHAPE_UNRECOGNIZED')
        out.append(value)
    return set(out)

def collection(data, keys, *, empty_allowed=True):
    if isinstance(data, list): return data
    if not isinstance(data, dict): raise Refuse('COLLECTION_NOT_OBJECT')
    for key in keys:
        if isinstance(data.get(key), list): return data[key]
    if empty_allowed and data.get('totalResults') == 0 and data.get('count', 0) == 0:
        return []
    raise Refuse('COLLECTION_SHAPE_UNRECOGNIZED')

def verify_tenants(client, admin, tenants):
    if tenants.get('schema') != 'identity.wso2.ciam.v10.tenants' or tenants.get('base') != BASE or tenants.get('domains') != DOMAINS:
        raise Refuse('TENANT_CONTEXT_MISMATCH')
    creds = {}
    for brand, domain in DOMAINS.items():
        item = tenants.get('tenants', {}).get(brand, {})
        o = item.get('owner', {})
        if item.get('status') != 'readback-verified' or item.get('domain') != domain or not ID.fullmatch(str(item.get('tenantId',''))) or not ID.fullmatch(str(item.get('ownerId',''))) or o.get('username') != OWNER or not isinstance(o.get('password'), str):
            raise Refuse('TENANT_JOURNAL_INCOMPLETE_'+brand)
        tid, oid = item['tenantId'], item['ownerId']
        record = require(client.call('GET', f'/api/server/v1/tenants/{tid}/owners/{oid}', auth=admin),200,'OWNER_ROOT_READ_'+brand)
        if record.get('id') != oid or record.get('username') != OWNER:
            raise Refuse('OWNER_ID_MISMATCH_'+brand)
        auth = basic(OWNER+'@'+domain, o['password'])
        for name,path in [('apps', '/api/server/v1/applications?limit=1'), ('resources', '/api/server/v1/api-resources?limit=1'), ('scim','/scim2/Users?count=1&startIndex=1')]:
            require(client.call('GET', '/t/'+domain+path, auth=auth),200,'QUALIFIED_ADMIN_'+name+'_'+brand)
        creds[brand] = auth
    return creds

def discover_resources(client, brand, auth):
    domain=DOMAINS[brand]
    root=f'/t/{domain}/api/server/v1/api-resources'
    found={}
    # The API supports filter=identifier eq. Verify each result's exact identifier.
    for identifier, scopes in ((APP_RESOURCE,APP_SCOPES),(USER_RESOURCE,USER_SCOPES)):
        query=urllib.parse.urlencode({'filter':'identifier eq '+identifier,'limit':'100'})
        data=require(client.call('GET',root+'?'+query,auth=auth),200,'API_RESOURCE_CATALOG_'+brand)
        matches=[x for x in collection(data,('APIResources','apiResources','resources','list')) if isinstance(x,dict) and x.get('identifier')==identifier]
        if not matches:
            # Some installations ignore the filter or expose system APIs only via
            # cursor pages. Follow *only* bounded 'after' cursor values, never
            # server-supplied URLs or a second origin.
            after = None
            seen = set()
            for page in range(25):
                q = {'limit':'100'}
                if after: q['after'] = after
                catalog = require(client.call('GET',root+'?'+urllib.parse.urlencode(q),auth=auth),200,'API_RESOURCE_FALLBACK_'+brand)
                matches.extend(x for x in collection(catalog,('APIResources','apiResources','resources','list')) if isinstance(x,dict) and x.get('identifier')==identifier)
                if matches: break
                links = catalog.get('links',[]) if isinstance(catalog,dict) else []
                cursor_links = [x for x in links if isinstance(x,dict) and x.get('rel') in ('next','after')]
                if len(cursor_links)>1:raise Refuse('API_RESOURCE_MULTIPLE_CURSORS_'+brand)
                if not cursor_links:break
                href = cursor_links[0].get('href')
                if not isinstance(href,str):raise Refuse('API_RESOURCE_CURSOR_INVALID_'+brand)
                parsed=urllib.parse.urlparse(href)
                if parsed.scheme or parsed.netloc or parsed.path not in (root,'/api/server/v1/api-resources'):
                    raise Refuse('API_RESOURCE_CURSOR_ORIGIN_INVALID_'+brand)
                values=urllib.parse.parse_qs(parsed.query).get('after',[])
                if len(values)!=1 or not values[0] or len(values[0])>512 or values[0] in seen:
                    raise Refuse('API_RESOURCE_CURSOR_INVALID_'+brand)
                after=values[0];seen.add(after)
                if page==24:raise Refuse('API_RESOURCE_PAGINATION_LIMIT_'+brand)
        if len(matches)!=1 or not ID.fullmatch(str(matches[0].get('id',''))):
            raise Refuse('API_RESOURCE_NOT_UNIQUE_'+brand+'_'+('APP' if identifier==APP_RESOURCE else 'SCIM'))
        rid=matches[0]['id']
        more=require(client.call('GET',root+'/'+urllib.parse.quote(rid,safe='')+'/scopes',auth=auth),200,'RESOURCE_SCOPES_'+brand)
        published=set()
        for x in collection(more,('scopes',),empty_allowed=False):
            name=x if isinstance(x,str) else x.get('name') if isinstance(x,dict) else None
            if isinstance(name,str): published.add(name)
        if not set(scopes).issubset(published):
            raise Refuse('REQUIRED_SCOPES_NOT_IN_CATALOG_'+brand+'_'+identifier.strip('/').replace('/','_'))
        found[identifier]={'id':rid,'scopes':list(scopes)}
    return found

def app_list(client,brand,auth,name):
    domain=DOMAINS[brand]
    url=f'/t/{domain}/api/server/v1/applications?'+urllib.parse.urlencode({'limit':'100','offset':'0','filter':f'name eq {name}'})
    d=require(client.call('GET',url,auth=auth),200,'APP_NAME_LIST_'+brand)
    apps=collection(d,('applications','Applications','list'))
    total=d.get('totalResults') if isinstance(d,dict) else len(apps)
    if isinstance(total,int) and total>len(apps): raise Refuse('APP_NAME_LIST_PAGINATION_UNSAFE')
    return [x for x in apps if isinstance(x,dict) and x.get('name')==name]

def auth_list(client,brand,auth,app_id):
    d=require(client.call('GET',f'/t/{DOMAINS[brand]}/api/server/v1/applications/{app_id}/authorized-apis',auth=auth),200,'AUTHORIZED_API_READ_'+brand)
    return collection(d,('authorizedAPIs','authorizedApis','apis','resources'))

def password():
    return secrets.token_urlsafe(33)+'!aA9'

def prepare(s,kind,brand,details,save):
    node=s['tenants'][brand].get(kind)
    if node is None:
        s['tenants'][brand][kind]={'state':'prepared',**details};save()
        node=s['tenants'][brand][kind]
    for k,v in details.items():
        if node.get(k)!=v: raise Refuse('JOURNAL_CONTEXT_DRIFT_'+kind+'_'+brand)
    return node

def management(client,brand,auth,resources,s,save):
    domain=DOMAINS[brand]
    prefix=f'/t/{domain}/api/server/v1/applications'
    name=f'Identity Lab {brand.upper()} Management Bootstrap'
    node=prepare(s,'management',brand,{'name':name,'domain':domain},save)
    if node['state']=='prepared':
        if app_list(client,brand,auth,name): raise Refuse('UNJOURNALED_MANAGEMENT_APP_COLLISION_'+brand)
        node['state']='create-started';save()
        data={'name':name,'description':'Isolated v10 lab-owned tenant automation', 'isManagementApp':True,
              'inboundProtocolConfiguration':{'oidc':{'grantTypes':['client_credentials'],'publicClient':False}}}
        response=client.call('POST',prefix,auth=auth,data=data)
        if response[0]!=201: raise Refuse('MANAGEMENT_CREATE_HTTP_'+str(response[0])+'_'+brand+'_DO_NOT_RETRY')
        app_id=response[1].get('id') or str(response[2] or '').split('?')[0].rstrip('/').split('/')[-1]
        if not ID.fullmatch(str(app_id)):raise Refuse('MANAGEMENT_CREATE_NO_ID_'+brand+'_DO_NOT_RETRY')
        node['id']=app_id;node['state']='created';save()
    if node['state']=='create-started':raise Refuse('MANAGEMENT_CREATE_UNCERTAIN_'+brand+'_DO_NOT_RETRY')
    if node['state'] not in ('created','auth-started','authorized','verified'):raise Refuse('MANAGEMENT_STATE_UNKNOWN_'+brand)
    app_id=node.get('id')
    if not ID.fullmatch(str(app_id)): raise Refuse('MANAGEMENT_ID_UNSAFE_'+brand)
    item=require(client.call('GET',prefix+'/'+app_id,auth=auth),200,'MANAGEMENT_GET_'+brand)
    if item.get('id')!=app_id or item.get('name')!=name or item.get('isManagementApp') is not True:
        raise Refuse('MANAGEMENT_READBACK_INVALID_'+brand)
    auth_url=prefix+'/'+app_id+'/authorized-apis'
    current=auth_list(client,brand,auth,app_id)
    for api in (APP_RESOURCE,USER_RESOURCE):
        resource=resources[api]
        matches=[x for x in current if isinstance(x,dict) and x.get('id')==resource['id']]
        if len(matches)>1:raise Refuse('DUPLICATE_AUTH_'+brand)
        if matches:
            # Remote readback is authoritative after a previous interrupted POST.
            # This is the *only* path allowed to clear an uncertain auth-started
            # journal entry; HTTP 200 by itself is never considered sufficient.
            if not set(resource['scopes']).issubset(scope_names(matches[0])):
                raise Refuse('PARTIALLY_GRANTED_API_UNSAFE_'+brand)
            pending = node.get('authStarted')
            if pending not in (None, api):
                raise Refuse('OTHER_AUTHORIZATION_UNRESOLVED_'+brand)
            node.setdefault('authorized',{})[api]=resource['id']
            if pending == api:
                node.pop('authStarted',None)
                node['state']='authorized'
            save()
            continue
        if node.get('authStarted')==api:raise Refuse('AUTHORIZATION_UNCERTAIN_'+brand+'_DO_NOT_RETRY')
        if node.get('authorized',{}).get(api):raise Refuse('AUTHORIZED_API_MISSING_ON_SERVER_'+brand)
        node['authStarted']=api;node['state']='auth-started';save()
        response=client.call('POST',auth_url,auth=auth,data={'id':resource['id'],'policyIdentifier':'RBAC','scopes':resource['scopes']})
        if response[0] not in (200,201):raise Refuse('AUTHORIZATION_POST_HTTP_'+str(response[0])+'_'+brand+'_DO_NOT_RETRY')
        latest=auth_list(client,brand,auth,app_id)
        present=[x for x in latest if isinstance(x,dict) and x.get('id')==resource['id']]
        if len(present)!=1 or not set(resource['scopes']).issubset(scope_names(present[0])):
            raise Refuse('AUTHORIZATION_READBACK_MISSING_'+brand+'_DO_NOT_RETRY')
        node.setdefault('authorized',{})[api]=resource['id'];node.pop('authStarted',None);node['state']='authorized';save()
        current=latest
    protocol=require(client.call('GET',prefix+'/'+app_id+'/inbound-protocols/oidc',auth=auth),200,'M2M_PROTOCOL_'+brand)
    if not protocol.get('clientId') or not protocol.get('clientSecret'):
        raise Refuse('M2M_CLIENT_CREDENTIALS_NOT_EXPOSED_'+brand)
    if node.get('clientId') and node['clientId']!=protocol['clientId']:
        raise Refuse('M2M_CLIENT_ID_DRIFT_'+brand)
    node['clientId']=protocol['clientId'];node['clientSecret']=protocol['clientSecret'];save()
    token_path=f'/t/{domain}/oauth2/token'
    result=require(client.call('POST',token_path,auth=basic(node['clientId'],node['clientSecret']),form={'grant_type':'client_credentials','scope':' '.join(ALL_SCOPES)}),200,'M2M_TOKEN_'+brand)
    granted=set(str(result.get('scope','')).split())
    if result.get('token_type','').lower()!='bearer' or not result.get('access_token') or not set(ALL_SCOPES).issubset(granted):
        raise Refuse('M2M_TOKEN_MISSING_REQUIRED_SCOPES_'+brand)
    bearer='Bearer '+result['access_token']
    for desc,path in [('applications','/api/server/v1/applications?limit=1'),('scim','/scim2/Users?count=1&startIndex=1')]:
        require(client.call('GET','/t/'+domain+path,auth=bearer),200,'M2M_BEARER_ACCESS_'+desc+'_'+brand)
    node['state']='verified';save()
    return bearer

def scim_list(client,brand,auth,name):
    filter_string=f'userName eq "{name}"'
    path='/t/'+DOMAINS[brand]+'/scim2/Users?'+urllib.parse.urlencode({'filter':filter_string,'count':'100','startIndex':'1'})
    data=require(client.call('GET',path,auth=auth),200,'SCIM_FILTER_'+brand)
    rs=collection(data,('Resources','resources'))
    if not isinstance(data,dict) or not isinstance(data.get('totalResults'),int) or data['totalResults']!=len(rs):
        raise Refuse('SCIM_LIST_TRUNCATED_OR_UNRECOGNIZED_'+brand)
    matches=[x for x in rs if isinstance(x,dict) and str(x.get('userName','')).removeprefix('PRIMARY/')==name]
    if len(matches)>1:raise Refuse('DUPLICATE_USER_'+brand)
    return matches[0] if matches else None

def scim_user(client,brand,bearer,s,save):
    name=USERNAMES[brand]
    own=s['tenants'][brand]
    if 'user' not in own:
        own['user']={'state':'prepared','username':name,'password':password(),'externalId':'v10-'+secrets.token_hex(16)};save()
    node=own['user']
    if node.get('username')!=name or not node.get('password') or not re.fullmatch(r'v10-[a-f0-9]{32}',str(node.get('externalId'))):
        raise Refuse('USER_JOURNAL_INVALID_'+brand)
    found=scim_list(client,brand,bearer,name)
    if found:
        if found.get('externalId')!=node['externalId'] or not ID.fullmatch(str(found.get('id',''))):
            raise Refuse('EXISTING_UNOWNED_USER_COLLISION_'+brand)
        if node.get('id') and node['id']!=found['id']:raise Refuse('USER_ID_DRIFT_'+brand)
        node['id']=found['id'];save()
    else:
        if node['state']!='prepared':raise Refuse('UNCERTAIN_USER_CREATION_'+brand+'_DO_NOT_RETRY')
        node['state']='create-started';save()
        payload={'schemas':['urn:ietf:params:scim:schemas:core:2.0:User'],
                 'userName':name,'password':node['password'],'externalId':node['externalId'],
                 'name':{'givenName':'CIAM','familyName':brand.title()},
                 'emails':[{'value':f'ciam-{brand}@example.invalid','primary':True}],
                 'active':True}
        resp=client.call('POST','/t/'+DOMAINS[brand]+'/scim2/Users',auth=bearer,data=payload)
        if resp[0]!=201 or not ID.fullmatch(str(resp[1].get('id',''))) or resp[1].get('externalId')!=node['externalId']:
            raise Refuse('SCIM_CREATE_UNCERTAIN_'+brand+'_HTTP_'+str(resp[0]))
        node['id']=resp[1]['id'];node['state']='created';save()
    detail=require(client.call('GET','/t/'+DOMAINS[brand]+'/scim2/Users/'+node['id'],auth=bearer),200,'SCIM_READBACK_'+brand)
    if detail.get('id')!=node['id'] or detail.get('externalId')!=node['externalId'] or str(detail.get('userName','')).removeprefix('PRIMARY/')!=name or detail.get('active') is False:
        raise Refuse('SCIM_USER_READBACK_INVALID_'+brand)
    node['state']='verified-browser-not-tested';save()
    return {'username':name,'readback':'VERIFIED','browser':'NOT_VERIFIED'}

def initial(tenants):
    return {'schema':'identity.wso2.ciam.v10.resources.v1','base':BASE,
            'tenants':{b:{'domain':d,'tenantId':tenants['tenants'][b]['tenantId'],
                          'ownerId':tenants['tenants'][b]['ownerId']} for b,d in DOMAINS.items()},
            'acceptance':'NOT_VERIFIED'}

def validate_state(s,tenants):
    if s.get('schema')!='identity.wso2.ciam.v10.resources.v1' or s.get('base')!=BASE or not isinstance(s.get('tenants'),dict):
        raise Refuse('RESOURCE_JOURNAL_CONTEXT_INVALID')
    for b,d in DOMAINS.items():
        if any(s['tenants'].get(b,{}).get(k)!=v for k,v in [('domain',d),('tenantId',tenants['tenants'][b]['tenantId']),('ownerId',tenants['tenants'][b]['ownerId'])]):
            raise Refuse('RESOURCE_TENANT_ID_DRIFT_'+b)
    return s

def status(state):
    if state is None:return {'stage':'V10_RESOURCES','status':'NOT_STARTED'}
    return {'stage':'V10_RESOURCES','base':BASE,'tenants':{
        b:{'management':state.get('tenants',{}).get(b,{}).get('management',{}).get('state','NOT_STARTED'),
           'user':state.get('tenants',{}).get(b,{}).get('user',{}).get('state','NOT_STARTED')}
        for b in BRANDS},'oidcClients':'NOT_PROVISIONED','bffBrowserAuthentication':'NOT_VERIFIED',
        'acceptance':state.get('acceptance','NOT_VERIFIED')}

def run(mode,client,admin,tenants,s,save):
    creds=verify_tenants(client,admin,tenants)
    catalogs={b:discover_resources(client,b,creds[b]) for b in BRANDS}
    if mode=='plan':
        return {'stage':'V10_RESOURCES','mode':'GET_ONLY','adminAuthorization':'VERIFIED_BOTH',
                'apiResourceScopes':'VERIFIED_BOTH','plannedManagementClients':2,'plannedScimUsers':2,
                'writes':0,'oidcClients':'NOT_IN_THIS_STAGE'}
    if mode!='apply' or os.environ.get('WSO2_CIAM_V10_RESOURCE_CONFIRM')!='PROVISION_MANAGEMENT_AND_USERS':
        raise Refuse('EXPLICIT_RESOURCE_WRITE_CONFIRMATION_REQUIRED')
    out={}
    for b in BRANDS:
        bearer=management(client,b,creds[b],catalogs[b],s,save)
        out[b]=scim_user(client,b,bearer,s,save)
    s['acceptance']='MANAGEMENT_AND_USERS_VERIFIED_OIDC_NOT_PROVISIONED';save()
    return {'stage':'V10_RESOURCES','mode':'APPLIED','managementClients':'2_AUTHORIZED_BEARER_VERIFIED',
            'users':out,'oidcClients':'NOT_PROVISIONED','browserAuthentication':'NOT_VERIFIED',
            'acceptance':'PARTIAL_RESOURCES_ONLY'}

def reconcile(client,admin,tenants,s):
    # Read-only, bounded by journaled IDs. A previous POST cannot be repeated
    # when the server did not confirm the exact API and scope grant.
    creds=verify_tenants(client,admin,tenants)
    catalogs={b:discover_resources(client,b,creds[b]) for b in BRANDS}
    output={'stage':'V10_RESOURCES_V1_1','mode':'READ_ONLY_RECONCILIATION',
            'remoteWrites':0,'tenants':{},'safeToResume':True}
    for b in BRANDS:
        node=s['tenants'][b].get('management')
        if node is None:
            output['tenants'][b]={'state':'NOT_STARTED','pendingAuthorization':'NONE'}
            continue
        expected_name=f'Identity Lab {b.upper()} Management Bootstrap'
        if (node.get('name')!=expected_name or node.get('domain')!=DOMAINS[b]
            or not ID.fullmatch(str(node.get('id','')))):
            raise Refuse('MANAGEMENT_JOURNAL_INCOMPLETE_'+b)
        prefix=f'/t/{DOMAINS[b]}/api/server/v1/applications/{node["id"]}'
        item=require(client.call('GET',prefix,auth=creds[b]),200,'MANAGEMENT_RECONCILE_GET_'+b)
        if (item.get('id')!=node['id'] or item.get('name')!=expected_name
            or item.get('isManagementApp') is not True):
            raise Refuse('MANAGEMENT_RECONCILE_ID_MISMATCH_'+b)
        current=auth_list(client,b,creds[b],node['id'])
        statuses={}
        for api,details in catalogs[b].items():
            matches=[x for x in current if isinstance(x,dict) and x.get('id')==details['id']]
            if len(matches)>1:raise Refuse('DUPLICATE_AUTH_'+b)
            if not matches:statuses[api]='MISSING'
            elif set(details['scopes']).issubset(scope_names(matches[0])):
                statuses[api]='SCOPES_VERIFIED'
            else:statuses[api]='PARTIAL_OR_UNRECOGNIZED'
        pending=node.get('authStarted')
        if pending is None and node.get('state')=='auth-started':
            raise Refuse('AUTH_STARTED_WITHOUT_PENDING_RESOURCE_'+b)
        if pending is not None and pending not in catalogs[b]:
            raise Refuse('UNEXPECTED_PENDING_API_'+b)
        pending_ok=pending is None or statuses.get(pending)=='SCOPES_VERIFIED'
        if not pending_ok:output['safeToResume']=False
        output['tenants'][b]={'state':node.get('state','UNKNOWN'),
              'managementIdentity':'VERIFIED','authorizedAPIs':statuses,
              'pendingAuthorization':pending or 'NONE',
              'pendingWriteReadback':('VERIFIED' if pending and pending_ok
                                       else 'NOT_VERIFIED' if pending else 'NOT_APPLICABLE')}
    return output

def main():
    mode=sys.argv[1] if len(sys.argv)>1 else 'plan'
    if mode not in ('plan','apply','status','reconcile'):raise Refuse('EXPECTED_plan_apply_status_reconcile')
    if Path.cwd().resolve()!=ROOT.resolve():raise Refuse('RUN_ONLY_FROM_V10_HOME')
    tenants=private_read(TENANT_FILE)
    s=private_read(STATE_FILE,False) or initial(tenants)
    validate_state(s,tenants)
    if mode=='status':print(json.dumps(status(s),indent=2));return
    adm=private_read(ADM_FILE)
    if adm.get('username')!='admin' or not isinstance(adm.get('password'),str):raise Refuse('SUPER_ADMIN_JOURNAL_MISMATCH')
    client=HTTPS()
    auth=basic('admin',adm['password'])
    if mode=='reconcile':
        result=reconcile(client,auth,tenants,s)
    elif mode=='plan':
        # no journal writes at all
        result=run(mode,client,auth,tenants,s,lambda:None)
    else:
        fd=create_lock()
        try:result=run(mode,client,auth,tenants,s,lambda:atomic_save(STATE_FILE,s))
        finally:release_lock(fd)
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    try:main()
    except (Refuse,OSError,ssl.SSLError,ValueError,KeyError,http.client.HTTPException) as exc:
        kind=str(exc) if isinstance(exc,Refuse) else type(exc).__name__
        print('CIAM_V10_RESOURCES_STOP: '+kind,file=sys.stderr)
        sys.exit(1)
