#!/usr/bin/env python3
"""P2.24 dedicated Aurora management authority, provisioned by existing v10 owner.

No super-tenant writes, OAuth credentials printed, blind retries, or TLS bypass.
Single source of truth: owner/journaled v10 credentials in CIAM_V10_HOME/private.
This stage only creates/authorizes an Aurora P2 client; partner creation is handled
by the existing P2 JS reconciler after a successful readback and OAuth probe.
"""
import base64
import subprocess
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

BASE_HOST = 'localhost'
DOMAIN = 'aurora.identity.test'
ROOT_ID = '/api/server/v1/organizations'
ORG_ID = '/o/api/server/v1/organizations'
USERS_ID = '/o/scim2/Users'
GROUPS_ID = '/o/scim2/Groups'
APPS_ID = '/o/api/server/v1/applications'
ROLES_ID = '/o/scim2/Roles'  # API resource identifier; REST endpoint is /o/scim2/v2/Roles
# The P2 reconciler calls /o/api/server/v1/organizations exclusively. Do not
# authorize the distinct root management API (/api/server/v1/organizations).
# That separate API uses internal_organization_* permissions and is not needed
# by this P2 workflow. Least-privilege authorization belongs to /o/ only.
POLICY = {
    ORG_ID: ('internal_org_organization_view', 'internal_org_organization_create'),
    USERS_ID: ('internal_org_user_mgt_list', 'internal_org_user_mgt_view', 'internal_org_user_mgt_create', 'internal_org_user_mgt_update'),
    GROUPS_ID: ('internal_org_group_mgt_view', 'internal_org_group_mgt_create', 'internal_org_group_mgt_update'),
    # List and read use the *view* permission; GA does not publish a
    # separate internal_org_application_mgt_list scope.
    APPS_ID: ('internal_org_application_mgt_view',
              'internal_org_application_mgt_create', 'internal_org_application_mgt_update'),
    ROLES_ID: ('internal_org_role_mgt_view', 'internal_org_role_mgt_create',
               'internal_org_role_mgt_update', 'internal_org_role_mgt_permissions_update',
               'internal_org_role_mgt_users_update'),
}
ROOT_SCOPES = POLICY[ORG_ID]
APP_NAME = 'Identity Lab P2 Aurora Partner Bootstrap'
APP_PREFIX = '/t/' + DOMAIN + '/api/server/v1/applications'
CATALOG = '/t/' + DOMAIN + '/api/server/v1/api-resources'
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)
ID = re.compile(r'^[A-Za-z0-9_-]{5,256}={0,2}$')
PIN = '2ba361a032ffd4b34f7df066de72b61c5e836a09f7a7bd7105eb87b4094d9712'
MARKER = re.compile(r'^p2-bootstrap-[a-f0-9]{32}$')

class Stop(Exception):
    pass

def must(condition, code):
    if not condition: raise Stop(code)

def private_read(path, *, optional=False):
    must(not path.is_symlink(), 'PRIVATE_SYMLINK_REFUSED')
    if not path.exists():
        if optional: return None
        raise Stop('EXISTING_V10_BOOTSTRAP_FILE_MISSING_' + path.name)
    st = path.stat()
    must(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size < 131072,
         'PRIVATE_FILE_OWNER_OR_MODE_INVALID_' + path.name)
    try: return json.loads(path.read_text())
    except (ValueError, UnicodeError): raise Stop('PRIVATE_JSON_INVALID_' + path.name) from None

def private_write(path, value):
    must(path.parent.is_dir() and not path.parent.is_symlink(), 'PRIVATE_DIR_MISSING_OR_SYMLINK')
    must(not (path.parent.stat().st_mode & 0o022), 'PRIVATE_DIR_GROUP_WRITABLE')
    current=private_read(path, optional=True)
    if current==value: return
    fd, name = tempfile.mkstemp(prefix='.p224-authority-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(name): os.unlink(name)

def basic(user, password):
    must(isinstance(password, str) and len(password) >= 8, 'V10_OWNER_PASSWORD_UNAVAILABLE')
    return 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()

def verify_source(repo):
    # Uses exactly the resources source studied from the supplied source export.
    target = repo / 'deploy/ciam-v10/resources/bootstrap.py'
    must(target.is_file() and not target.is_symlink(), 'V10_RESOURCES_SOURCE_MISSING')
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    must(digest == 'c53e50f270acf83b7f3126bdd85ac945001323752218005f5b97df74fd5ecae1',
         'V10_RESOURCES_SOURCE_CHANGED_REVIEW_REQUIRED')

def environment(repo, home):
    must(home.is_absolute(), 'V10_HOME_MUST_BE_ABSOLUTE')
    private = home / 'private'
    must(private.is_dir() and not private.is_symlink() and not private.stat().st_mode & 0o022,
         'V10_PRIVATE_DIRECTORY_UNSAFE')
    tenants = private_read(private / 'bootstrap-tenants-v10.private.json')
    resources = private_read(private / 'bootstrap-resources-v10.private.json')
    must(tenants.get('schema') == 'identity.wso2.ciam.v10.tenants' and
         tenants.get('base') == 'https://localhost:9444' and
         tenants.get('domains') == {'aurora':'aurora.identity.test', 'brisa':'brisa.identity.test'},
         'V10_TENANT_JOURNAL_CONTEXT_DRIFT')
    t = tenants.get('tenants',{}).get('aurora',{})
    r = resources.get('tenants',{}).get('aurora',{})
    must(t.get('domain') == DOMAIN and t.get('status') == 'readback-verified' and
         t.get('owner',{}).get('username') == 'labtenantadmin' and
         t.get('tenantId') == r.get('tenantId') and t.get('ownerId') == r.get('ownerId') and
         resources.get('schema') == 'identity.wso2.ciam.v10.resources.v1' and
         resources.get('base') == 'https://localhost:9444' and
         r.get('management',{}).get('state') == 'verified' and
         r.get('management',{}).get('domain') == DOMAIN and
         r.get('management',{}).get('name') == 'Identity Lab AURORA Management Bootstrap' and
         ID.fullmatch(str(r.get('management',{}).get('id',''))),
         'V10_AURORA_AUTHORITY_NOT_READBACK_VERIFIED')
    owner_password = t['owner'].get('password')
    must(isinstance(owner_password,str) and len(owner_password)>=8, 'V10_OWNER_PASSWORD_UNAVAILABLE')
    return private, basic('labtenantadmin@' + DOMAIN, owner_password), r['management']['id']

def tls_context(repo):
    cert = repo / 'var/wso2/tls/wso2-local.pem'
    must(cert.is_file() and not cert.is_symlink(), 'WSO2_CERTIFICATE_UNAVAILABLE')
    try:
        pem = cert.read_text()
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (ValueError, ssl.SSLError):
        raise Stop('WSO2_CERTIFICATE_INVALID') from None
    must(hashlib.sha256(der).hexdigest() == PIN, 'WSO2_CERTIFICATE_PIN_CHANGED')
    return ssl.create_default_context(cafile=str(cert))  # hostname verification stays ON

class Wire:
    def __init__(self, ctx): self.ctx=ctx
    def call(self, method, path, *, auth, payload=None, form=None):
        must(method in ('GET','POST','PATCH') and isinstance(path,str) and path.startswith('/t/'+DOMAIN+'/') and
             '..' not in path and '\\' not in path and '#' not in path and not path.startswith('//'),
             'HTTP_PATH_OR_METHOD_NOT_ALLOWED')
        must((payload is None or form is None), 'BODY_CONFLICT')
        headers = {'Authorization':auth,'Accept':'application/json'}
        body=None
        if payload is not None:
            body=json.dumps(payload); headers['Content-Type']='application/json'
        if form is not None:
            body=urllib.parse.urlencode(form); headers['Content-Type']='application/x-www-form-urlencoded'
        conn=http.client.HTTPSConnection(BASE_HOST,9444,context=self.ctx,timeout=12)
        try:
            conn.request(method,path,headers=headers,body=body)
            resp=conn.getresponse(); data=resp.read(262145)
            must(len(data) <= 262144,'HTTP_BODY_TOO_LARGE')
            must(resp.status not in range(300,400),'HTTP_REDIRECT_REFUSED')
            try: parsed=json.loads(data) if data else {}
            except ValueError:
                if 200 <= resp.status < 300: raise Stop('WSO2_SUCCESS_BODY_NOT_JSON') from None
                parsed={}
            return resp.status,parsed,resp.getheader('Location')
        finally: conn.close()

def need(response, code, stage):
    if response[0] != code: raise Stop(stage+'_HTTP_'+str(response[0]))
    return response[1]

def rows(body, keys):
    if isinstance(body,list): return body
    for key in keys:
        if isinstance(body,dict) and isinstance(body.get(key),list): return body[key]
    if isinstance(body,dict) and body.get('totalResults') == 0: return []
    raise Stop('API_LIST_SHAPE_UNSUPPORTED')

def approved_scopes(record):
    entries=record.get('authorizedScopes',record.get('scopes'))
    must(isinstance(entries,list),'APP_AUTH_SCOPES_MISSING')
    return {x if isinstance(x,str) else x.get('name') for x in entries if isinstance(x,(str,dict))}

def next_page_parameter(href, url, kind):
    """Extract only a vetted cursor/offset; NEVER follow WSO2-supplied href.

    WSO2 publishes tenant-qualified, root-relative, bare-resource and sometimes
    absolute self links. All subsequent HTTP requests are rebuilt from the
    locally pinned Aurora API path, not from the supplied link.
    """
    must(isinstance(href,str) and 0 < len(href) <= 2048, 'NEXT_LINK_INVALID')
    parsed=urllib.parse.urlsplit(href)
    must(not parsed.fragment and not parsed.username and not parsed.password,
         'NEXT_LINK_ORIGIN_OR_PATH_INVALID')
    if parsed.scheme or parsed.netloc:
        # A remote origin or a different port is *never* a valid pagination hop.
        must(parsed.scheme=='https' and parsed.netloc=='localhost:9444',
             'NEXT_LINK_ORIGIN_OR_PATH_INVALID')
    bare=url.split('/t/'+DOMAIN,1)[1]
    basename=url.rsplit('/',1)[-1]
    must(parsed.path in (url,bare,basename,'', './'+basename),
         'NEXT_LINK_ORIGIN_OR_PATH_INVALID')
    try:
        fields=urllib.parse.parse_qsl(parsed.query,keep_blank_values=True,
                                      strict_parsing=True,max_num_fields=8)
    except ValueError:
        raise Stop('NEXT_LINK_QUERY_INVALID') from None
    allowed={'limit','after'} if kind=='cursor' else {'limit','offset'}
    must(fields and all(k in allowed for k,v in fields) and
         len(fields)==len({k for k,v in fields}), 'NEXT_LINK_QUERY_INVALID')
    params=dict(fields)
    if 'limit' in params:
        must(params['limit'].isdigit() and 1 <= int(params['limit']) <= 1000,
             'NEXT_LINK_LIMIT_INVALID')
    key='after' if kind=='cursor' else 'offset'
    must(key in params,'NEXT_LINK_PAGE_PARAMETER_MISSING')
    value=params[key]
    if kind=='cursor':
        # Opaque base64-like cursor is never sent to an origin from the href.
        must(0 < len(value) <= 512 and value.isascii() and
             all(c.isprintable() and c not in ('\\','\r','\n') for c in value),
             'NEXT_CURSOR_INVALID')
        return value
    must(value.isascii() and value.isdigit() and len(value)<=8 and
         0 < int(value) <= 1000000, 'NEXT_OFFSET_INVALID')
    return int(value)

def listing(wire, url, auth, keys, *, limit=100):
    """Bounded, complete Aurora-only pagination for two distinct WSO2 APIs."""
    must(url in (CATALOG,APP_PREFIX) and isinstance(limit,int) and
         not isinstance(limit,bool) and 1 <= limit <= 100, 'LIST_ENDPOINT_OR_LIMIT_INVALID')
    kind='cursor' if url==CATALOG else 'offset'
    gathered=[]; seen=set(); after=None; offset=0
    for _ in range(25):
        query={'limit':str(limit)}
        if kind=='cursor' and after is not None: query['after']=after
        if kind=='offset': query['offset']=str(offset)
        body=need(wire.call('GET',url+'?'+urllib.parse.urlencode(query),auth=auth),200,'LIST')
        page=rows(body,keys)
        must(isinstance(page,list), 'LIST_PAGE_INVALID')
        gathered.extend(page)
        must(len(gathered)<=100000,'LIST_TOO_LARGE')
        links=body.get('links',[]) if isinstance(body,dict) else []
        must(isinstance(links,list),'PAGINATION_LINKS_INVALID')
        nxt=[x for x in links if isinstance(x,dict) and x.get('rel') in ('next','after')]
        must(len(nxt)<=1,'UNEXPECTED_PAGINATION')
        if not nxt:
            if isinstance(body,dict) and 'totalResults' in body:
                total=body['totalResults']
                must(type(total) is int and 0 <= total <= 100000 and
                     total==len(gathered), 'PARTIAL_LIST_PAGINATION')
            elif len(page)>=limit:
                raise Stop('PAGINATION_COMPLETENESS_NOT_ATTESTED')
            return gathered
        must(bool(page),'EMPTY_PAGE_WITH_NEXT_LINK')
        next_value=next_page_parameter(nxt[0].get('href'),url,kind)
        must(next_value not in seen,'PAGINATION_CURSOR_LOOP')
        seen.add(next_value)
        if kind=='cursor':
            after=next_value
        else:
            # No gaps or overlaps when listing applications by offset.
            must(next_value==offset+len(page), 'PAGINATION_OFFSET_GAP_OR_OVERLAP')
            offset=next_value
    raise Stop('PAGINATION_LIMIT_REACHED')

def discovery(wire, owner):
    found={}
    catalog=listing(wire,CATALOG,owner,('APIResources','apiResources','resources','list'))
    for identifier, expected in POLICY.items():
        items=[x for x in catalog if isinstance(x,dict) and x.get('identifier')==identifier]
        must(len(items)==1 and ID.fullmatch(str(items[0].get('id',''))),
             'P2_REQUIRED_API_RESOURCE_NOT_UNIQUE_'+identifier.replace('/','_'))
        rid=items[0]['id']
        details=need(wire.call('GET',CATALOG+'/'+rid,auth=owner),200,'API_RESOURCE_READBACK')
        must(details.get('id')==rid and details.get('identifier')==identifier,'API_RESOURCE_IDENTITY_CHANGED')
        # WSO2 API-resource detail may not embed the full scope inventory.
        # Its dedicated GET /api-resources/{id}/scopes API is authoritative
        # when the embedded list is absent or insufficient. Never add scopes.
        def names(value):
            if not isinstance(value, list): return None
            result=set()
            for item in value:
                name=item if isinstance(item,str) else item.get('name') if isinstance(item,dict) else None
                must(isinstance(name,str) and re.fullmatch(r'[a-zA-Z0-9_:.-]{1,128}',name),
                     'API_RESOURCE_SCOPE_LIST_MALFORMED')
                result.add(name)
            return result
        actual=names(details.get('scopes'))
        if actual is None or not set(expected).issubset(actual):
            listed=need(wire.call('GET',CATALOG+'/'+rid+'/scopes',auth=owner),200,
                        'API_RESOURCE_DEDICATED_SCOPES_READBACK')
            actual=names(listed)
            must(actual is not None,'API_RESOURCE_DEDICATED_SCOPES_SHAPE_UNSUPPORTED')
        missing=sorted(set(expected)-actual)
        if missing:
            category={ORG_ID:'organizations',USERS_ID:'users',GROUPS_ID:'groups',ROLES_ID:'roles',APPS_ID:'applications'}[identifier]
            # These are only expected, static permission names; no WSO2
            # response bodies, tokens, credentials or user data are printed.
            raise Stop('API_RESOURCE_REQUIRED_SCOPE_UNSUPPORTED_'+category+'_'+','.join(missing))
        found[identifier]=rid
    must(len(set(found.values()))==len(found),'API_RESOURCE_IDS_NOT_UNIQUE')
    return found

def app_by_name(wire, owner):
    apps=listing(wire,APP_PREFIX,owner,('applications','Applications','list'))
    found=[x for x in apps if isinstance(x,dict) and x.get('name')==APP_NAME]
    must(len(found)<=1,'P2_APP_NAME_COLLISION')
    return found[0] if found else None

def verify_app(wire, owner, appid, marker):
    must(ID.fullmatch(str(appid)) and MARKER.fullmatch(str(marker)), 'P2_APP_ID_OR_MARKER_INVALID')
    record=need(wire.call('GET',APP_PREFIX+'/'+appid,auth=owner),200,'P2_APP_READBACK')
    must(record.get('id')==appid and record.get('name')==APP_NAME and
         record.get('description')==marker and record.get('isManagementApp') is True,
         'P2_APP_READBACK_IDENTITY_MISMATCH')
    protocol=need(wire.call('GET',APP_PREFIX+'/'+appid+'/inbound-protocols/oidc',auth=owner),200,'P2_OIDC_PROTOCOL_READBACK')
    grants=protocol.get('grantTypes')
    must(isinstance(grants,list) and {'client_credentials','organization_switch'}.issubset(set(grants)),
         'P2_OIDC_GRANT_TYPES_NOT_VERIFIED')
    return protocol

def authorizations(wire,owner,appid):
    body=need(wire.call('GET',APP_PREFIX+'/'+appid+'/authorized-apis',auth=owner),200,'P2_AUTH_READBACK')
    result=rows(body,('authorizedAPIs','authorizedApis','apis','resources'))
    return result

def verify_auth(records, resource_id, required):
    matched=[x for x in records if isinstance(x,dict) and x.get('id')==resource_id]
    must(len(matched)<=1,'P2_DUPLICATE_API_AUTH')
    if not matched:return False
    must(set(required)==approved_scopes(matched[0]),'P2_PARTIAL_OR_EXCESS_API_AUTH_SCOPE_BLOCKED')
    policy=matched[0].get('policyIdentifier',matched[0].get('policyId','RBAC'))
    must(policy=='RBAC','P2_API_AUTH_POLICY_UNEXPECTED')
    return True

def minted_root(wire,client_id,secret):
    response=need(wire.call('POST','/t/'+DOMAIN+'/oauth2/token', auth=basic(client_id,secret),
          form={'grant_type':'client_credentials','scope':' '.join(ROOT_SCOPES)}),200,'P2_ROOT_TOKEN')
    must(response.get('token_type','').lower()=='bearer' and
         isinstance(response.get('access_token'),str) and len(response['access_token'])>=16 and
         set(ROOT_SCOPES).issubset(str(response.get('scope','')).split()),
         'P2_ROOT_TOKEN_GRANT_NOT_VERIFIED')
    token=response['access_token']
    self_path='/t/'+DOMAIN+'/o/api/server/v1/organizations/self'
    self_obj=need(wire.call('GET',self_path,auth='Bearer '+token),200,'P2_ROOT_ORGANIZATION_READBACK')
    must(UUID.fullmatch(str(self_obj.get('id',''))) and not (self_obj.get('parent') or {}).get('id') and
         self_obj.get('status')=='ACTIVE', 'P2_ROOT_TOKEN_NOT_BOUND_TO_ROOT_ORGANIZATION')
    return self_obj['id']

def reconcile(wire, *, home, owner, previous_app_id, write):
    # Remote authority must still refer to the exact v10 management application.
    prior=need(wire.call('GET',APP_PREFIX+'/'+previous_app_id,auth=owner),200,'EXISTING_V10_MGMT_READBACK')
    must(prior.get('id')==previous_app_id and
         prior.get('name')=='Identity Lab AURORA Management Bootstrap' and
         prior.get('isManagementApp') is True, 'EXISTING_V10_MGMT_AUTHORITY_DRIFT')
    journal_path=home/'private'/'p2-bootstrap-authority.private.json'
    existing=private_read(journal_path, optional=True)
    if existing is not None:
        must(existing.get('schema')=='identity.wso2.p224.authority.v1' and
             existing.get('domain')==DOMAIN and existing.get('sourceAppId')==previous_app_id and
             MARKER.fullmatch(str(existing.get('marker',''))) and
             existing.get('state') in ('prepared','create-started','created','authorizing','verified'),
             'P2_JOURNAL_CONTEXT_INVALID')
    resources=discovery(wire,owner)
    if existing:
        # A single monotonic migration is permitted: the previously verified v1
        # 3-resource manifest may acquire only the exact organization Roles and Applications APIs.
        prior_resources=existing.get('resources')
        must(isinstance(prior_resources,dict) and all(resources.get(k)==v for k,v in prior_resources.items()) and
             set(resources)-set(prior_resources) <= {ROLES_ID, APPS_ID} and
             set(prior_resources) >= {ORG_ID, USERS_ID, GROUPS_ID}, 'P2_API_RESOURCE_ID_DRIFT')
        if prior_resources!=resources and write:
            existing['resources']=resources
            private_write(journal_path,existing)
    already=app_by_name(wire,owner)
    if not existing:
        must(not already,'UNJOURNALED_P2_MANAGEMENT_APP_COLLISION')
        if not write:return {'stage':'P2_AUTHORITY','mode':'CHECK','state':'MISSING','candidate':'DEDICATED_AURORA_MANAGEMENT_APP','remoteWrites':0}
        existing={'schema':'identity.wso2.p224.authority.v1','domain':DOMAIN,
                  'sourceAppId':previous_app_id,'state':'prepared',
                  'marker':'p2-bootstrap-'+secrets.token_hex(16),'resources':resources,'authorized':{}}
        private_write(journal_path,existing)
    def save(): private_write(journal_path,existing)
    if already:
        must(existing['state']!='prepared','UNJOURNALED_APP_COLLISION')
        must(already.get('id')==existing.get('appId') or existing['state']=='create-started',
             'P2_JOURNALED_APP_ID_CHANGED')
        if existing['state']=='create-started':
            # Only adopt an uncertain POST if the existing name AND marker match.
            item=need(wire.call('GET',APP_PREFIX+'/'+str(already.get('id')),auth=owner),200,'P2_UNCERTAIN_CREATE_READBACK')
            must(item.get('description')==existing['marker'] and item.get('isManagementApp') is True,
                 'P2_UNCERTAIN_CREATE_NO_PROVEN_OWNERSHIP')
            existing['appId']=item['id'];existing['state']='created'
            if write: save()
    elif existing['state']=='create-started':
        raise Stop('P2_CREATE_OUTCOME_UNCERTAIN_NO_AUTOMATIC_RETRY')
    elif existing.get('appId'):
        raise Stop('P2_JOURNALED_APP_MISSING_FROM_REMOTE')
    elif existing['state']=='prepared' and write:
        existing['state']='create-started';save()
        payload={'name':APP_NAME,'description':existing['marker'],'isManagementApp':True,
                 'inboundProtocolConfiguration':{'oidc':{'grantTypes':['client_credentials','organization_switch'],
                   'publicClient':False}}}
        response=wire.call('POST',APP_PREFIX,auth=owner,payload=payload)
        must(response[0]==201,'P2_CREATE_RESULT_UNCERTAIN_DO_NOT_RETRY')
        appid=response[1].get('id') or str(response[2] or '').split('/')[-1]
        must(ID.fullmatch(str(appid)),'P2_CREATE_RESPONSE_ID_INVALID')
        existing['appId']=appid;existing['state']='created';save()
    if not existing.get('appId'):
        return {'stage':'P2_AUTHORITY','mode':'CHECK','state':existing['state'],'remoteWrites':0}
    appid=existing['appId']
    protocol=verify_app(wire,owner,appid,existing['marker'])
    all_auth = authorizations(wire,owner,appid)
    must(all(isinstance(x,dict) and x.get('id') in set(resources.values()) for x in all_auth),
         'P2_EXTRA_AUTHORIZED_API_RESOURCE_REFUSED')
    for ident, scopes in POLICY.items():
        auth_records=authorizations(wire,owner,appid)
        rid=resources[ident]
        matched=[x for x in auth_records if isinstance(x,dict) and x.get('id')==rid]
        must(len(matched)<=1,'P2_DUPLICATE_API_AUTH')
        actual=approved_scopes(matched[0]) if matched else set()
        must(not matched or matched[0].get('policyIdentifier',matched[0].get('policyId','RBAC'))=='RBAC',
             'P2_API_AUTH_POLICY_UNEXPECTED')
        target=set(scopes)
        if actual==target:
            existing.setdefault('authorized',{})[ident]=rid
            if existing.get('pending') in (ident, 'upgrade:'+ident):
                existing.pop('pending',None);existing['state']='authorizing'
                if write:save()
            continue
        # Existing v1 Users authorization may be upgraded, never replaced,
        # deleted or silently widened. The dedicated Roles API is new.
        legacy_users={'internal_org_user_mgt_list','internal_org_user_mgt_view'}
        # Only the two previously attested user-scope profiles may gain the
        # exact user-update permission. No arbitrary subset or broadening.
        if ident==USERS_ID and matched and actual in (
                legacy_users, legacy_users|{'internal_org_user_mgt_create'}):
            if existing.get('pending')=='upgrade:'+ident:
                raise Stop('P2_SCOPE_UPGRADE_OUTCOME_UNCERTAIN_NO_RETRY')
            if not write:
                return {'stage':'P2_AUTHORITY','mode':'CHECK','state':'SCOPE_UPGRADE_REQUIRED',
                        'api':'users','remoteWrites':0}
            existing['pending']='upgrade:'+ident;existing['state']='authorizing';save()
            response=wire.call('PATCH',APP_PREFIX+'/'+appid+'/authorized-apis/'+rid,auth=owner,
                               payload={'addedScopes':sorted(target-actual),'removedScopes':[]})
            must(response[0]==200,'P2_SCOPE_UPGRADE_RESULT_UNCERTAIN_NO_RETRY')
            must(verify_auth(authorizations(wire,owner,appid),rid,scopes),
                 'P2_SCOPE_UPGRADE_READBACK_FAILED')
            existing['authorized'][ident]=rid;existing.pop('pending',None);save()
            continue
        must(not matched,'P2_PARTIAL_OR_EXCESS_API_AUTH_SCOPE_BLOCKED')
        if existing.get('pending')==ident:
            raise Stop('P2_AUTHORIZATION_OUTCOME_UNCERTAIN_NO_AUTOMATIC_RETRY')
        must(ident not in existing.get('authorized',{}),'P2_AUTHORIZATION_DISAPPEARED_REMOTE')
        if not write:
            return {'stage':'P2_AUTHORITY','mode':'CHECK','state':'API_AUTHORIZATION_MISSING','api':ident,'remoteWrites':0}
        existing['state']='authorizing';existing['pending']=ident;save()
        response=wire.call('POST',APP_PREFIX+'/'+appid+'/authorized-apis',auth=owner,
                           payload={'id':rid,'policyIdentifier':'RBAC','scopes':list(scopes)})
        must(response[0] in (200,201),'P2_AUTH_WRITE_RESULT_UNCERTAIN_DO_NOT_RETRY')
        must(verify_auth(authorizations(wire,owner,appid),rid,scopes),'P2_AUTH_READBACK_FAILED')
        existing['authorized'][ident]=rid;existing.pop('pending',None);save()
    client_id=protocol.get('clientId');secret=protocol.get('clientSecret')
    must(isinstance(client_id,str) and len(client_id)>=8 and isinstance(secret,str) and len(secret)>=8,
         'P2_CLIENT_CREDENTIALS_READBACK_UNAVAILABLE')
    root_id=minted_root(wire,client_id,secret)
    if not write:
        return {'stage':'P2_AUTHORITY','mode':'CHECK','state':'READY','rootOrganizationId':root_id,'remoteWrites':0}
    existing['aurora.identity.test']={'clientId':client_id,'clientSecret':secret}
    existing['rootOrganizationId']=root_id;existing['state']='verified';existing.pop('pending',None);save()
    return {'stage':'P2_AUTHORITY','mode':'APPLY','state':'VERIFIED',
            'rootOrganizationId':root_id,'managedAppId':appid,'authorizations':len(POLICY),
            'remoteReadback':'VERIFIED','credentialHandoff':'PRIVATE_OWNER_ONLY',
            'tenant':DOMAIN}

def verify_runtime_image():
    try:
        value=subprocess.run(['docker','inspect','--format','{{.Config.Image}}','wso2-ciam-v10-is-1'],
              capture_output=True,text=True,timeout=6,check=True).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
        raise Stop('WSO2_RUNTIME_IMAGE_NOT_INSPECTABLE') from None
    must(value=='wso2/wso2is:7.3.0','WSO2_VERSION_NOT_APPROVED_NO_MUTATION')

def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('check','apply'):
        raise Stop('usage: p2-bootstrap-authority.py check|apply')
    mode=sys.argv[1]
    repo=Path(__file__).resolve().parent.parent
    verify_source(repo)
    verify_runtime_image()
    home=Path(os.environ.get('CIAM_V10_HOME',str(Path.home()/'wso2-ciam-v10')))
    private,owner,prior=environment(repo,home)
    ctx=tls_context(repo)
    lock=private/'p2-bootstrap-authority.lock'
    fd=None
    if mode=='apply':
        try:fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        except FileExistsError:raise Stop('P2_EXISTING_BOOTSTRAP_LOCK')
    try:
        result=reconcile(Wire(ctx),home=home,owner=owner,previous_app_id=prior,write=mode=='apply')
    finally:
        if fd is not None:
            os.close(fd);os.unlink(lock)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (Stop,OSError,ValueError,KeyError,TypeError,ssl.SSLError,http.client.HTTPException) as exc:
        msg=str(exc) if isinstance(exc,Stop) else type(exc).__name__
        print(json.dumps({'stage':'P2_AUTHORITY','status':'BLOCKED', 'error':msg[:180],
                          'mutations':'NOT_ASSUMED', 'secrets':'NEVER_PRINTED'}),file=sys.stderr)
        sys.exit(1)
