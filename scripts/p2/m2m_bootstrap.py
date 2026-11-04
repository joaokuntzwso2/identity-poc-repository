#!/usr/bin/env python3
"""P2.24 dedicated Aurora M2M org-view client: guarded bootstrap, no prompts.

The only permitted remote management writes are POST a new named Aurora-only
application and POST one exact Organization Management API authorization.
Requires pre-existing locally authorized tenant admin credentials and verified
HTTPS. Fail closed, durable write-ahead journal, never print credentials.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import subprocess
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TENANT = 'aurora.identity.test'
ORIGIN = 'https://localhost:9444'
SCOPE = 'internal_org_organization_view'
NAME = 'P2 Aurora Organization View M2M'
DESCRIPTION = 'P2.24 dedicated tenant-only organization inventory; no partner/user mutation permissions.'
APP_ROOT = f'/t/{TENANT}/api/server/v1/applications'
API_ROOT = f'/t/{TENANT}/api/server/v1/api-resources'
ORG_ROOT = f'/t/{TENANT}/o/api/server/v1/organizations'
TOKEN_PATH = f'/t/{TENANT}/oauth2/token'
APPROVAL = 'CREATE_AURORA_ORG_VIEW_M2M'
UUID = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$', re.I)
ALLOWED_API_IDENTIFIERS = frozenset(('/api/server/v1/organizations', '/o/api/server/v1/organizations'))
API_ID = re.compile(r'^[A-Za-z0-9_-]{3,150}$')
EXPECTED_IMAGE_SHA = 'sha256:d9ffe26f8a87d479b0987e9e22df8f8214407fd0138d78ba6f2dd8c0f75fbfc6'
MAX_RESPONSE = 512_000

class Block(Exception):
    pass

def require(ok, code):
    if not ok: raise Block(code)

def report(status, **values):
    print(json.dumps({'phase':'P2.24', 'tenant':TENANT, 'status':status, **values},
                     indent=2, sort_keys=True))

def secure_dir(path):
    try: s = path.lstat()
    except OSError: raise Block('PRIVATE_DIRECTORY_MISSING')
    require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and
            s.st_uid == os.getuid() and not (s.st_mode & 0o077), 'PRIVATE_DIRECTORY_UNSAFE')

def safe_private_file(path, required=True, max_size=1024*1024):
    try: s = path.lstat()
    except FileNotFoundError:
        if required: raise Block('PRIVATE_FILE_MISSING')
        return False
    require(stat.S_ISREG(s.st_mode) and not stat.S_ISLNK(s.st_mode) and
            s.st_uid == os.getuid() and (s.st_mode & 0o777) == 0o600 and
            0 < s.st_size <= max_size, 'PRIVATE_FILE_UNSAFE')
    return True

def read_json_private(path):
    safe_private_file(path)
    try: v = json.loads(path.read_text(encoding='utf8'))
    except (ValueError, OSError, UnicodeError): raise Block('PRIVATE_FILE_INVALID_JSON')
    require(isinstance(v, dict), 'PRIVATE_FILE_NOT_OBJECT')
    return v

def fsync_directory(directory):
    fd = os.open(directory, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def exclusive_json(path, obj):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try: fd = os.open(path, flags, 0o600)
    except FileExistsError: raise Block('WRITE_AHEAD_JOURNAL_EXISTS_NO_RETRY')
    with os.fdopen(fd, 'w', encoding='utf8') as f:
        json.dump(obj, f, sort_keys=True, separators=(',',':'))
        f.write('\n'); f.flush(); os.fsync(f.fileno())
    fsync_directory(path.parent)

def replace_json(path, obj):
    # Only replace an existing owner-only file written by this workflow.
    safe_private_file(path)
    tmp = path.with_name(path.name + '.tmp.' + str(os.getpid()))
    exclusive_json(tmp, obj)
    os.replace(tmp, path)
    fsync_directory(path.parent)

def hash_id(v):
    return hashlib.sha256(v.encode('utf8')).hexdigest()[:16]

def _aurora_scoped(path, record):
    """Prove a record belongs to Aurora, never infer identity from a lone secret.

    The v10 tenant journals have evolved: some keep tenantAdmin.password or
    adminPassword without repeating username=admin. Treat only those exact
    admin-specific layouts as eligible, within an explicit Aurora branch.
    """
    parts = tuple(str(p).casefold() for p in path)
    if any(p in ('brisa', 'brisa.identity.test', 'carbon.super', 'carbon',
                 'applications', 'apps', 'clients', 'users', 'groups',
                 'oauth', 'oidc', 'organizations')
           for p in parts):
        return False
    identity = record.get('tenantDomain') or record.get('tenant') or record.get('domain')
    if isinstance(identity, str):
        if identity.casefold() != TENANT:
            return False
        return True
    return any(p in ('aurora', TENANT) for p in parts)


def _admin_name(value):
    return isinstance(value, str) and value.casefold() in ('admin', f'admin@{TENANT}')


def find_tenant_admin(doc):
    """Resolve only explicitly Aurora-owned admin credentials; never print them.

    Supported structures:
      tenants.aurora.{username,password}
      tenants.aurora.{admin,tenantAdmin}.{password[,username]}
      tenants.aurora.{adminPassword,admin_password,tenantAdminPassword}
    A mismatched user, another tenant, or multiple distinct passwords blocks.
    """
    found = []
    def add(password):
        if isinstance(password, str) and 0 < len(password) <= 4096:
            found.append((f'admin@{TENANT}', password))

    def walk(value, path=(), depth=0):
        if depth > 12:
            return
        if isinstance(value, list):
            for i, child in enumerate(value):
                if isinstance(child, (dict, list)):
                    walk(child, path+(str(i),), depth+1)
            return
        if not isinstance(value, dict):
            return
        owned = _aurora_scoped(path, value)
        if owned:
            username = value.get('username', value.get('userName'))
            password = value.get('password')
            # Co-located ordinary username/password is accepted only with
            # an explicit username matching the tenant administrator.
            if _admin_name(username):
                add(password)
            # Admin-specific child record with no username is still a known
            # owner-admin layout; never infer this from a generic user record.
            if path and str(path[-1]).casefold() in ('admin', 'tenantadmin', 'administrator'):
                if username is None or _admin_name(username):
                    add(password)
            # Explicitly named admin password on an Aurora-owned tenant record.
            # A conflicting named username rejects implicit admin selection.
            if username is None or _admin_name(username):
                for key in ('adminPassword', 'admin_password', 'tenantAdminPassword',
                            'tenant_admin_password', 'administratorPassword'):
                    add(value.get(key))
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                walk(child, path+(str(key),), depth+1)
    walk(doc)
    unique = list(dict.fromkeys(found))
    require(len(unique) <= 1, 'MULTIPLE_AURORA_ADMIN_CREDENTIALS_CONFLICT')
    return unique


def _load_authority_context(repo):
    """Use the same repository-owned private-context loader as authority.

    Importing this module is read-only; no command dispatch or mutation occurs.
    """
    import importlib.util
    authority = repo/'deploy/ciam-v10/authority/bootstrap.py'
    require(authority.is_file() and not authority.is_symlink(),
            'AUTHORITY_SOURCE_UNAVAILABLE')
    prefix = str(authority.parent.parent)
    if prefix not in sys.path:
        sys.path.insert(0, prefix)
    spec = importlib.util.spec_from_file_location('p2_existing_authority_context', authority)
    require(spec is not None and spec.loader is not None, 'AUTHORITY_IMPORT_UNAVAILABLE')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = module.private_context()
    require(isinstance(output, (tuple,list)) and len(output)==3,
            'AUTHORITY_PRIVATE_CONTEXT_SHAPE_UNVERIFIED')
    return output


def _admin_schema_hints(doc):
    """Return booleans only: never print field values or arbitrary private keys."""
    flags={'auroraBranch':False,'explicitAdminPassword':False,
           'namedAdminPassword':False,'usernamePasswordPair':False}
    def walk(value, path=(), depth=0):
        if depth > 12:
            return
        if isinstance(value, list):
            for i,child in enumerate(value):
                if isinstance(child,(dict,list)):
                    walk(child,path+(str(i),),depth+1)
            return
        if not isinstance(value,dict):
            return
        if _aurora_scoped(path,value):
            flags['auroraBranch']=True
            if any(isinstance(value.get(k),str) and bool(value[k]) for k in
                   ('adminPassword','admin_password','tenantAdminPassword',
                    'tenant_admin_password','administratorPassword')):
                flags['explicitAdminPassword']=True
            if path and str(path[-1]).casefold() in ('admin','tenantadmin','administrator'):
                flags['namedAdminPassword'] |= isinstance(value.get('password'),str)
            flags['usernamePasswordPair'] |= (isinstance(value.get('username'),str)
                                              and isinstance(value.get('password'),str))
        for key,child in value.items():
            if isinstance(child,(dict,list)):
                walk(child,path+(str(key),),depth+1)
    walk(doc)
    return flags


def _admin_source_documents(private, repo=None):
    """Only known owner-only journals and the existing authority context."""
    names = ('bootstrap-tenants-v10.private.json',
             'bootstrap-resources-v10.private.json',
             'bootstrap-oidc-v10.private.json')
    documents=[]
    for name in names:
        path=private/name
        if path.exists() or path.is_symlink():
            documents.append((name.removesuffix('.private.json'),read_json_private(path)))
    if repo is not None:
        try:
            ts, rs, oidc = _load_authority_context(repo)
            documents.extend((('authority_tenants',ts),('authority_resources',rs),
                              ('authority_oidc',oidc)))
        except Block:
            raise
        except Exception:
            raise Block('EXISTING_AUTHORITY_CONTEXT_NOT_READABLE')
    return documents


def read_admin(private, repo=None):
    documents=_admin_source_documents(private,repo)
    matches=[]
    for label,doc in documents:
        matches.extend(find_tenant_admin(doc))
    unique=list(dict.fromkeys(matches))
    require(len(unique) <= 1, 'MULTIPLE_AURORA_ADMIN_CREDENTIALS_CONFLICT')
    require(len(unique)==1,
            'AURORA_ADMIN_CREDENTIAL_NOT_LOCATABLE_IN_APPROVED_JOURNALS')
    return unique[0]


def admin_diagnostic(private, repo=None):
    """Private-data-safe diagnostic: only boolean shape information."""
    docs=_admin_source_documents(private,repo)
    candidates=[]
    shape={'auroraBranch':False,'explicitAdminPassword':False,
           'namedAdminPassword':False,'usernamePasswordPair':False}
    for _,doc in docs:
        flags=_admin_schema_hints(doc)
        for key,val in flags.items(): shape[key] |= val
        candidates.extend(find_tenant_admin(doc))
    return {'sourcesExamined':len(docs), 'uniqueCandidateCount':min(2,len(set(candidates))),
            'recognizedAuroraCredentialShapes':shape, 'remoteManagementWrites':0}


class AuthorityBasic:
    """In-memory Basic header produced by the existing v10 authority diagnostic.

    No serialisation, printing or persistence. A successful WSO2 GET still gates
    subsequent management activity, and the same exact header is used thereafter.
    """
    __slots__ = ('_header',)
    def __init__(self, header):
        self._header = header
    def __repr__(self):
        return '<AuthorityBasic redacted>'
    __str__ = __repr__


def _extract_basic(value, depth=0):
    """Extract only explicit Basic Authorization headers, not arbitrary secrets."""
    if depth > 5:
        return []
    if isinstance(value, str):
        if value.startswith('Basic '):
            return [value]
        return []
    if isinstance(value, dict):
        found=[]
        for key, val in value.items():
            if str(key).lower() in ('authorization','auth','headers','basic'):
                found.extend(_extract_basic(val, depth+1))
        return found
    if isinstance(value, (tuple,list)):
        found=[]
        for item in value:
            found.extend(_extract_basic(item,depth+1))
        return found
    return []


def _approved_basic_header(header):
    """Reject bare Basic, foreign tenant, malformed or truncated header."""
    if not isinstance(header,str) or not header.startswith('Basic '):
        return False
    encoded=header[6:]
    if not (8 <= len(encoded) <= 8192) or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', encoded):
        return False
    try:
        raw=base64.b64decode(encoded,validate=True).decode('utf-8')
    except (ValueError,UnicodeError):
        return False
    if ':' not in raw:
        return False
    username,password=raw.split(':',1)
    # Tenant qualification is non-negotiable; no Carbon/Bare/Brisa fallback.
    if not (0 < len(username) <= 512 and 0 < len(password) <= 4096 and
            username.lower().endswith('@'+TENANT) and
            username.count('@') == 1 and username.lower() != '@'+TENANT and '\n' not in username and
            '\r' not in username):
        return False
    return True


def read_existing_authority_admin(repo):
    """Reuse Basic Authorization observed on Aurora GETs of the existing v10 diagnostic.

    The existing source can implement Basic with a module-level function or
    an imported/namespaced helper; no particular helper location is required.
    A capture-only transport raises on ALL calls and has no networking code.
    Its observed credential still needs the real WSO2 readback in bootstrap().
    """
    import importlib.util
    source=repo/'deploy/ciam-v10/authority/bootstrap.py'
    require(source.is_file() and not source.is_symlink(),
            'AUTHORITY_SOURCE_UNAVAILABLE')
    prefix=str(source.parent.parent)
    if prefix not in sys.path: sys.path.insert(0,prefix)
    try:
        spec=importlib.util.spec_from_file_location('p2_v10_authority_probe',source)
        require(spec is not None and spec.loader is not None,
                'AUTHORITY_SOURCE_IMPORT_UNAVAILABLE')
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ('private_context','diagnostic'):
            require(callable(getattr(module,name,None)),
                    'AUTHORITY_DIAGNOSTIC_CONTRACT_CHANGED')
        context=module.private_context()
        require(isinstance(context,(tuple,list)) and len(context)==3 and
                all(isinstance(x,dict) for x in context),
                'AUTHORITY_CONTEXT_SHAPE_CHANGED')
    except Block:
        raise
    except Exception:
        raise Block('EXISTING_AUTHORITY_CONTEXT_UNAVAILABLE')

    observed=[]
    calls=[0]
    aurora_gets=[0]
    basic_values=[0]
    class CaptureOnlyClient:
        def call(self,*args,**kwargs):
            # Intentionally NEVER calls the network, even for unexpected methods.
            calls[0]+=1
            require(calls[0]<=100, 'AUTHORITY_DIAGNOSTIC_EXCESSIVE_CALLS')
            values=list(args)+list(kwargs.values())
            strings=[x for x in values if isinstance(x,str)]
            method=kwargs.get('method')
            if method is None:
                method=next((x for x in strings if x in
                            ('GET','POST','PUT','PATCH','DELETE')),None)
            # Accept only an actual Aurora tenant API path, not query-string
            # text mentioning another tenant or a foreign absolute origin.
            def valid_path(value):
                if not isinstance(value,str): return False
                if value.startswith('/t/'+TENANT+'/'):
                    return '?' not in value.split('/t/'+TENANT+'/',1)[0]
                if value.startswith(ORIGIN+'/t/'+TENANT+'/'):
                    return True
                return False
            if method=='GET' and any(valid_path(v) for v in strings):
                aurora_gets[0]+=1
                headers=[]
                for val in values:
                    headers.extend(_extract_basic(val))
                basic_values[0]+=len(headers)
                observed.extend(v for v in headers if _approved_basic_header(v))
            raise OSError('P2_V10_CAPTURE_ONLY_NO_NETWORK')

    try:
        module.diagnostic(CaptureOnlyClient(),*context)
    except Block:
        raise
    except Exception:
        # The diagnostic may stop after a simulated read failure. We only
        # adopt an observed, tenant-qualified header from an actual GET call.
        pass
    require(calls[0]>0, 'AURORA_AUTHORITY_BASIC_NOT_UNAMBIGUOUS_NO_CALLS')
    require(aurora_gets[0]>0, 'AURORA_AUTHORITY_BASIC_NOT_UNAMBIGUOUS_NO_AURORA_GET')
    require(basic_values[0]>0, 'AURORA_AUTHORITY_BASIC_NOT_UNAMBIGUOUS_NO_BASIC_HEADER')
    unique=list(dict.fromkeys(observed))
    require(len(unique)==1, 'AURORA_AUTHORITY_BASIC_NOT_UNAMBIGUOUS')
    return AuthorityBasic(unique[0])

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class Http:
    def __init__(self, ca_path=None):
        try: ctx = ssl.create_default_context(cafile=ca_path)
        except (OSError, ssl.SSLError): raise Block('TRUSTED_TLS_CA_INVALID')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                     urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    def call(self, method, path, *, basic=None, bearer=None, data=None):
        require(method in ('GET','POST'), 'HTTP_METHOD_NOT_ALLOWED')
        require(path.startswith(f'/t/{TENANT}/') and not any(x in path for x in ('..','\\','#','\r','\n','//')),
                'CROSS_TENANT_OR_UNSAFE_PATH')
        permitted_get = (path.startswith(APP_ROOT),path.startswith(API_ROOT),
                         path in (ORG_ROOT+'/metadata',))
        permitted_post = (path == APP_ROOT or
                          (path.startswith(APP_ROOT+'/') and path.endswith('/authorized-apis')) or
                          path == TOKEN_PATH)
        require(any(permitted_get) if method=='GET' else permitted_post,
                'UNAUTHORIZED_ENDPOINT_OR_METHOD')
        require(bool(basic) != bool(bearer), 'AUTH_NOT_EXCLUSIVE')
        if isinstance(basic, AuthorityBasic):
            require(_approved_basic_header(basic._header),
                    'AUTHORITY_BASIC_TENANT_QUALIFICATION_FAILED')
            auth = basic._header
        elif basic:
            # Retain existing local-fixture path for legacy offline tests.
            require(basic[0] == f'admin@{TENANT}', 'CROSS_TENANT_ADMIN_FORBIDDEN')
            auth = 'Basic ' + base64.b64encode((basic[0]+':'+basic[1]).encode()).decode('ascii')
        else:
            auth = 'Bearer '+bearer
        headers={'Authorization':auth,'Accept':'application/json'}
        body = None
        if method=='POST':
            require(isinstance(data, dict), 'POST_BODY_REQUIRED')
            if path == TOKEN_PATH:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                body = urllib.parse.urlencode(data).encode()
            else:
                headers['Content-Type'] = 'application/json'
                body = json.dumps(data, separators=(',',':')).encode()
        request = urllib.request.Request(ORIGIN+path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=18) as resp:
                status=resp.status
                raw=resp.read(MAX_RESPONSE+1)
                location=resp.headers.get('Location', '')
        except urllib.error.HTTPError as exc:
            raise Block(f'WSO2_{method}_HTTP_{exc.code}')
        except (ssl.SSLError, urllib.error.URLError, TimeoutError, OSError):
            raise Block(f'WSO2_{method}_OUTCOME_UNKNOWN_NO_RETRY')
        require(len(raw)<=MAX_RESPONSE, 'WSO2_RESPONSE_TOO_LARGE')
        if not raw.strip(): return (status,{},location)
        try: result=json.loads(raw)
        except (ValueError, UnicodeError): raise Block('WSO2_RESPONSE_NOT_JSON')
        require(isinstance(result,(dict,list)), 'WSO2_RESPONSE_SHAPE_INVALID')
        return (status,result,location)

def inventory(http, root, collection, admin):
    """Complete paginated inventory; missing metadata never implies absence."""
    results=[]; seen=set(); offset=0; total=None
    for _ in range(40):
        path=f'{root}?limit=100&offset={offset}'
        status, doc, _ = http.call('GET', path, basic=admin)
        require(status==200 and isinstance(doc,dict), 'INVENTORY_HTTP_OR_SHAPE_INVALID')
        items=doc.get(collection)
        require(isinstance(items,list), 'INVENTORY_COLLECTION_MISSING')
        n=doc.get('totalResults')
        require(isinstance(n,int) and not isinstance(n,bool) and 0<=n<=4000,
                'INVENTORY_TOTAL_INVALID')
        if total is None: total=n
        require(total==n, 'INVENTORY_CHANGED_DURING_PAGINATION')
        require(len(items)<=100, 'INVENTORY_PAGE_TOO_LONG')
        for item in items:
            require(isinstance(item,dict) and isinstance(item.get('id'),str) and
                    UUID.fullmatch(item['id']), 'INVENTORY_ITEM_INVALID')
            require(item['id'] not in seen, 'INVENTORY_DUPLICATE_ID')
            seen.add(item['id']); results.append(item)
        require(len(results)<=total, 'INVENTORY_EXCEEDS_TOTAL')
        if len(results)==total: return results
        require(len(items)>0, 'INVENTORY_TRUNCATED')
        offset += len(items)
    raise Block('INVENTORY_PAGE_LIMIT_EXCEEDED')

def _complete_filtered_api_resource_page(doc):
    """Accept the observed 7.3.0 GA `apiResources` field, fail closed otherwise.

    The API uses cursor pagination. For these two exact-identifier filters,
    completeness is proved only when the returned collection length equals
    totalResults AND there is no next/after link. A page needing pagination
    must block rather than silently authorize an arbitrary API resource.
    """
    require(isinstance(doc,dict), 'ORG_API_RESOURCE_QUERY_FAILED')
    keys=[key for key in ('apiResources','APIResources') if key in doc]
    require(len(keys)==1, 'ORG_API_RESOURCE_COLLECTION_MISSING_OR_AMBIGUOUS')
    items=doc[keys[0]]
    total=doc.get('totalResults')
    require(isinstance(items,list) and isinstance(total,int) and
            not isinstance(total,bool) and 0 <= total <= 100 and len(items)==total,
            'ORG_API_RESOURCE_QUERY_INCOMPLETE')
    links=doc.get('links',[])
    require(isinstance(links,list), 'ORG_API_RESOURCE_LINKS_UNVERIFIED')
    for link in links:
        require(isinstance(link,dict) and isinstance(link.get('rel'),str),
                'ORG_API_RESOURCE_LINKS_UNVERIFIED')
        require(link['rel'].lower() not in ('next','after'),
                'ORG_API_RESOURCE_CURSOR_INCOMPLETE')
    return items


def pick_org_api(http, admin):
    # WSO2 GA responds with `apiResources` (lowercase a); older contract
    # fixtures can use `APIResources`. Never accept both simultaneously.
    # Two exact-identifier filtered queries only; never mistake a partial
    # cursor page (or an unfiltered 184-item inventory) for a complete list.
    eligible=[]
    for identifier in sorted(ALLOWED_API_IDENTIFIERS):
        query=urllib.parse.urlencode({'filter':'identifier eq '+identifier,'limit':'100'})
        status, doc, _=http.call('GET',f'{API_ROOT}?{query}',basic=admin)
        require(status==200, 'ORG_API_RESOURCE_QUERY_FAILED')
        items=_complete_filtered_api_resource_page(doc)
        for row in items:
            require(isinstance(row,dict) and row.get('identifier')==identifier and
                    isinstance(row.get('id'),str) and API_ID.fullmatch(row['id']),
                    'ORG_API_RESOURCE_LIST_ITEM_INVALID')
            status, full, _ = http.call('GET',f'{API_ROOT}/{row["id"]}',basic=admin)
            require(status==200 and isinstance(full,dict) and full.get('id')==row['id'] and
                    full.get('identifier')==identifier, 'ORG_API_DETAIL_UNVERIFIED')
            scopes=full.get('scopes')
            require(isinstance(scopes,list), 'ORG_API_SCOPES_UNVERIFIED')
            names={scope.get('name') for scope in scopes if isinstance(scope,dict)}
            if SCOPE in names: eligible.append(full)
    require(len(eligible)==1, 'ORG_MANAGEMENT_RESOURCE_NOT_UNAMBIGUOUS')
    return eligible[0]

def exact_authorization(doc, api_id):
    require(isinstance(doc,list), 'AUTHORIZED_APIS_SHAPE_UNVERIFIED')
    require(len(doc)==1 and isinstance(doc[0],dict) and doc[0].get('id')==api_id,
            'AUTHORIZED_APIS_NOT_EXACTLY_ONE_RESOURCE')
    names=doc[0].get('authorizedScopes')
    require(isinstance(names,list) and len(names)==1 and
            isinstance(names[0],dict) and names[0].get('name')==SCOPE,
            'AUTHORIZED_SCOPE_READBACK_NOT_EXACTLY_VIEW')

def require_new_app_config(doc):
    require(isinstance(doc,dict) and doc.get('name')==NAME and
            doc.get('isManagementApp') is True and doc.get('applicationEnabled') is not False,
            'APPLICATION_READBACK_NOT_OWNED')
    oidc=(doc.get('inboundProtocolConfiguration') or {}).get('oidc') or {}
    # Some GA responses put OIDC only in a separate inbound-protocol endpoint;
    # the caller checks that endpoint as source of truth.
    if oidc:
        require(oidc.get('grantTypes')==['client_credentials'] and
                oidc.get('publicClient') is False, 'APPLICATION_OIDC_GRANTS_NOT_EXACT')

def get_oidc(http, admin, app_id):
    status, doc, _ = http.call('GET',f'{APP_ROOT}/{app_id}/inbound-protocols/oidc', basic=admin)
    require(status==200 and isinstance(doc,dict), 'OIDC_READBACK_FAILED')
    require(doc.get('grantTypes')==['client_credentials'] and doc.get('publicClient') is False,
            'OIDC_GRANTS_NOT_EXACT')
    cid=doc.get('clientId'); secret=doc.get('clientSecret')
    require(isinstance(cid,str) and 4<=len(cid)<=512, 'OIDC_CLIENT_ID_NOT_VERIFIED')
    require(isinstance(secret,str) and 8<=len(secret)<=4096, 'OIDC_SECRET_NOT_AVAILABLE_NO_ROTATION')
    return cid,secret

def oauth_token(http, cid, secret):
    # OAuth HTTP Basic is (clientId,clientSecret), unlike tenant-admin Basic.
    # This token endpoint uses a distinct request with exact fixed path.
    raw=base64.b64encode((cid+':'+secret).encode()).decode()
    form=urllib.parse.urlencode({'grant_type':'client_credentials','scope':SCOPE}).encode()
    req=urllib.request.Request(ORIGIN+TOKEN_PATH,data=form,method='POST',headers={
        'Authorization':'Basic '+raw,'Content-Type':'application/x-www-form-urlencoded',
        'Accept':'application/json'})
    try:
        with http.opener.open(req, timeout=18) as resp:
            require(resp.status==200, 'OAUTH_TOKEN_NOT_200')
            doc=json.loads(resp.read(65536))
    except urllib.error.HTTPError as e: raise Block(f'OAUTH_TOKEN_HTTP_{e.code}')
    except (ssl.SSLError, urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise Block('OAUTH_TOKEN_OUTCOME_UNKNOWN_OR_INVALID')
    require(isinstance(doc,dict) and doc.get('token_type','').lower()=='bearer',
            'OAUTH_TOKEN_TYPE_NOT_BEARER')
    scopes=doc.get('scope')
    require(isinstance(scopes,str) and set(scopes.split())=={SCOPE},
            'OAUTH_SCOPE_NOT_EXACTLY_ORG_VIEW')
    token=doc.get('access_token')
    require(isinstance(token,str) and 25<=len(token)<=8192 and not any(ch.isspace() for ch in token),
            'OAUTH_ACCESS_TOKEN_INVALID')
    return token

def root_readback(http, token):
    status, doc, _ = http.call('GET',ORG_ROOT+'/metadata',bearer=token)
    require(status==200 and isinstance(doc,dict) and UUID.fullmatch(str(doc.get('id',''))),
            'ORG_ROOT_METADATA_ID_INVALID')
    require(doc.get('type')=='TENANT' and doc.get('status') in ('ACTIVE',None),
            'ORG_ROOT_NOT_ACTIVE_TENANT')
    require(doc.get('orgHandle')==TENANT or doc.get('domain')==TENANT,
            'ORG_ROOT_TENANT_HANDLE_MISMATCH')
    return doc['id']

def verified_existing(http, private, admin, record):
    require(record.get('schema')=='p2.24.aurora.m2m.bootstrap.v1' and
            record.get('phase')=='COMPLETE' and record.get('tenant')==TENANT and
            record.get('appName')==NAME and record.get('scope')==SCOPE,
            'COMPLETED_JOURNAL_IDENTITY_INVALID')
    app_id=record.get('appId'); api_id=record.get('resourceId')
    require(isinstance(app_id,str) and UUID.fullmatch(app_id) and
            isinstance(api_id,str) and API_ID.fullmatch(api_id), 'COMPLETED_JOURNAL_IDS_INVALID')
    creds=read_json_private(private/'p2-aurora-orgview-client.private.json')
    require(creds.get('state')=='SCOPE_VERIFIED' and creds.get('tenantDomain')==TENANT and
            creds.get('appId')==app_id and creds.get('authorizedScopes')==[SCOPE] and
            creds.get('grantTypes')==['client_credentials'], 'EXISTING_CLIENT_RECORD_INVALID')
    status, detail, _=http.call('GET',f'{APP_ROOT}/{app_id}',basic=admin)
    require(status==200,'EXISTING_APP_READBACK_FAILED')
    require_new_app_config(detail)
    cid, secret=get_oidc(http,admin,app_id)
    require(cid==creds.get('clientId') and secret==creds.get('clientSecret'),
            'EXISTING_CLIENT_CREDENTIALS_CHANGED')
    status, authz, _=http.call('GET',f'{APP_ROOT}/{app_id}/authorized-apis',basic=admin)
    require(status==200,'EXISTING_AUTHORIZATION_READBACK_FAILED')
    exact_authorization(authz,api_id)
    token=oauth_token(http,cid,secret)
    root_id=root_readback(http,token)
    require(root_id==record.get('rootId'), 'EXISTING_ROOT_CONTEXT_DRIFT')
    # Refresh local short-lived token safely; no WSO2 management mutation.
    path=private/'p2-aurora-root-token.private.txt'
    safe_private_file(path,max_size=8192)
    tmp=path.with_name(path.name+'.tmp.'+str(os.getpid()))
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(tmp,flags,0o600)
    with os.fdopen(fd,'w') as f:
        f.write(token);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path);fsync_directory(private)
    return {'action':'ALREADY_VERIFIED','rootFingerprint':hash_id(root_id),
            'applicationFingerprint':hash_id(app_id),'tokenFileReady':True,
            'remoteManagementWrites':0}

def bootstrap(http, private, admin, mode):
    journal=private/'p2-aurora-orgview-bootstrap.private.json'
    creds=private/'p2-aurora-orgview-client.private.json'
    token_path=private/'p2-aurora-root-token.private.txt'
    # A COMPLETE journal is safely idempotent after fresh WSO2 readback.
    # Interrupted or unverified writes are never automatically retried.
    if journal.exists() or journal.is_symlink():
        record=read_json_private(journal)
        if record.get('phase')=='COMPLETE':
            return verified_existing(http,private,admin,record)
        raise Block('PREVIOUS_BOOTSTRAP_JOURNAL_REQUIRES_RECONCILIATION')
    require(not creds.exists() and not creds.is_symlink(), 'PREVIOUS_CLIENT_FILE_REQUIRES_RECONCILIATION')
    require(not token_path.exists() and not token_path.is_symlink(), 'PREVIOUS_TOKEN_REQUIRES_RECONCILIATION')
    apps=inventory(http,APP_ROOT,'applications',admin)
    existing=[a for a in apps if a.get('name')==NAME]
    require(not existing, 'DEDICATED_APP_ALREADY_EXISTS_NO_BLIND_ADOPTION')
    api=pick_org_api(http,admin)
    if mode=='plan':
        return {'action':'CREATE_DEDICATED_APP_THEN_AUTHORIZE_VIEW',
                'applicationInventoryCount':len(apps), 'resourceFingerprint':hash_id(api['id']),
                'remoteManagementWrites':0}
    require(mode=='apply', 'UNKNOWN_MODE')
    # Crash-safe POST guard: an existing journal halts all subsequent attempts.
    exclusive_json(journal, {'schema':'p2.24.aurora.m2m.bootstrap.v1','phase':'CREATE_INTENT',
                             'tenant':TENANT, 'appName':NAME,'resourceId':api['id'],
                             'scope':SCOPE,'remoteWritesAttempted':0})
    payload={'name':NAME,'description':DESCRIPTION,'isManagementApp':True,
             'inboundProtocolConfiguration':{'oidc':{'grantTypes':['client_credentials'],
                   'publicClient':False}}}
    status, body, location = http.call('POST',APP_ROOT,basic=admin,data=payload)
    require(status==201, 'CREATE_APP_OUTCOME_NOT_CONFIRMED_NO_RETRY')
    app_id=body.get('id') if isinstance(body,dict) else None
    if not app_id and location.startswith(APP_ROOT+'/'):
        app_id=location.rsplit('/',1)[-1]
    require(isinstance(app_id,str) and UUID.fullmatch(app_id),
            'CREATED_APP_ID_NOT_VERIFIED_NO_RETRY')
    status, detail, _=http.call('GET',f'{APP_ROOT}/{app_id}',basic=admin)
    require(status==200,'CREATE_APP_READBACK_FAILED')
    require_new_app_config(detail)
    cid, secret=get_oidc(http,admin,app_id)
    # Local private record is saved BEFORE second remote write.
    exclusive_json(creds, {'tenantDomain':TENANT,'clientId':cid,'clientSecret':secret,
                           'grantTypes':['client_credentials'],'state':'REGISTERED_UNAUTHORIZED',
                           'appId':app_id})
    replace_json(journal,{'schema':'p2.24.aurora.m2m.bootstrap.v1','phase':'AUTHORIZATION_INTENT',
                          'tenant':TENANT,'appName':NAME,'appId':app_id,'resourceId':api['id'],
                          'scope':SCOPE,'remoteWritesAttempted':1})
    result_status, _, _=http.call('POST',f'{APP_ROOT}/{app_id}/authorized-apis', basic=admin,
                             data={'id':api['id'],'policyIdentifier':'RBAC','scopes':[SCOPE]})
    require(result_status==201, 'API_AUTHORIZATION_OUTCOME_UNVERIFIED_NO_RETRY')
    status, authz, _=http.call('GET',f'{APP_ROOT}/{app_id}/authorized-apis', basic=admin)
    require(status==200,'API_AUTHORIZATION_READBACK_FAILED')
    exact_authorization(authz,api['id'])
    replace_json(creds, {'tenantDomain':TENANT,'clientId':cid,'clientSecret':secret,
                         'grantTypes':['client_credentials'],'authorizedScopes':[SCOPE],
                         'state':'SCOPE_VERIFIED','appId':app_id})
    token=oauth_token(http,cid,secret)
    root_id=root_readback(http,token)
    # P2 CLI expects raw bearer text, not JSON. Never overwrite existing.
    fd=os.open(token_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'w') as f:
        f.write(token); f.flush(); os.fsync(f.fileno())
    fsync_directory(private)
    replace_json(journal, {'schema':'p2.24.aurora.m2m.bootstrap.v1','phase':'COMPLETE',
                           'tenant':TENANT,'appName':NAME,'appId':app_id,'resourceId':api['id'],
                           'scope':SCOPE,'rootId':root_id,'remoteWritesAttempted':2})
    return {'action':'CREATED_AND_READBACK_VERIFIED','rootFingerprint':hash_id(root_id),
            'applicationFingerprint':hash_id(app_id),'tokenFileReady':True,
            'remoteManagementWrites':2}

def runtime_guard(repo, private):
    """Strictly verify unchanged 7.3.0 GA image and pinned v2 authority preflight."""
    journal=read_json_private(private/'bootstrap-authority-v10.private.json')
    require(journal.get('roleApiVersion')=='v2', 'ROLE_API_JOURNAL_NOT_PINNED_V2')
    try:
        result=subprocess.run(['docker','inspect','wso2-ciam-v10-is-1'],
                              capture_output=True,text=True,timeout=20,check=False)
        require(result.returncode==0, 'APPROVED_WSO2_CONTAINER_NOT_FOUND')
        payload=json.loads(result.stdout)
        require(isinstance(payload,list) and len(payload)==1, 'DOCKER_INSPECT_UNVERIFIED')
        node=payload[0]
        require(node.get('Name')=='/wso2-ciam-v10-is-1' and
                node.get('Config',{}).get('Image')=='wso2/wso2is:7.3.0' and
                node.get('Image')==EXPECTED_IMAGE_SHA and
                node.get('State',{}).get('Running') is True,
                'WSO2_IMAGE_OR_RUNTIME_DRIFT_NO_AUTOMATIC_UPGRADE')
        env=dict(os.environ,WSO2_CIAM_V10_ROLE_API='v2')
        probe=subprocess.run(['bash','scripts/ciam-v10.sh','authority-preflight'],
                 cwd=repo,env=env,capture_output=True,text=True,timeout=100,check=False)
        require(probe.returncode==0, 'JOURNAL_PINNED_AUTHORITY_PREFLIGHT_FAILED')
        proof=json.loads(probe.stdout)
        require(isinstance(proof,dict) and proof.get('methods')==['GET'] and
                proof.get('remoteWrites')==0 and
                all(proof.get('tenantStates',{}).get(tenant,{}).get('rolesV2',{})
                        .get('tenantQualifiedBasic')==200 for tenant in ('aurora','brisa')),
                'AUTHORITY_PREFLIGHT_NOT_GET_ONLY_OR_V2_UNVERIFIED')
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        raise Block('RUNTIME_ATTESTATION_UNAVAILABLE')

def main(argv):
    mode=('diagnose' if argv==['diagnose-admin'] else 'plan' if argv==['plan'] else
          'apply' if argv==['apply','--approve='+APPROVAL] else None)
    require(mode is not None,'USE_PLAN_OR_APPROVED_APPLY_COMMAND')
    cwd=Path.cwd().resolve()
    require((cwd/'scripts/ciam-v10.sh').is_file() and (cwd/'scripts/p2/cli.mjs').is_file(),
            'RUN_FROM_POC_IMPLEMENTATION_REPO_ROOT')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or Path.home()/'wso2-ciam-v10/private').expanduser().absolute()
    secure_dir(private)
    if mode=='diagnose':
        return {'action':'ADMIN_SCHEMA_DIAGNOSTIC_ONLY',
                **admin_diagnostic(private,cwd)}
    runtime_guard(cwd,private)
    admin=read_existing_authority_admin(cwd)
    ca=os.environ.get('NODE_EXTRA_CA_CERTS') or os.environ.get('SSL_CERT_FILE')
    if ca: require(Path(ca).is_file(), 'TRUSTED_TLS_CA_NOT_FOUND')
    http=Http(ca)
    return bootstrap(http,private,admin,mode)

if __name__=='__main__':
    try:
        result=main(sys.argv[1:]); report('DIAGNOSTIC_ONLY' if result['action']=='ADMIN_SCHEMA_DIAGNOSTIC_ONLY' else ('VERIFIED' if result['action'].endswith('VERIFIED') else 'PLAN_ONLY'), **result)
    except Block as e:
        report('BLOCKED', code=str(e), noAutomaticRetry=True)
        sys.exit(2)
    except Exception:
        report('BLOCKED', code='UNEXPECTED_FAILURE_SANITIZED_NO_RETRY', noAutomaticRetry=True)
        sys.exit(2)
