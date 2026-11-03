#!/usr/bin/env python3
"""Read-only, bounded Carbon Super inventory. Never prints secrets or tokens.

Uses server-local TLS certificate pinning, like the repo's v10 bootstrap. Some
super-tenant admin endpoints may be unavailable on this exact IS update.
Status != 200 means NOT VERIFIED, never an empty collection.
"""
import base64
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import sys
from urllib.parse import parse_qsl, quote, urlsplit

ROOT = Path(os.environ.get('CIAM_V10_HOME',str(Path.home()/'wso2-ciam-v10')))
ADMIN = ROOT/'private/admin.private.json'
PATHS = {
    'rootTenants':'/api/server/v1/tenants?limit=100&offset=0',
    'superApplications':'/api/server/v1/applications?limit=100&offset=0',
    'superApiResources':'/api/server/v1/api-resources?limit=100&offset=0',
    'superScimUsers':'/scim2/Users?count=100&startIndex=1',
    'superScimRolesV2':'/scim2/v2/Roles?count=100&startIndex=1',
}
MAX_API_RESOURCE_PAGES = 10
MAX_API_RESOURCES = 1000
API_RESOURCE_PATH = '/api/server/v1/api-resources'

COLLECTION_KEYS = {
    'rootTenants':('tenants',),
    'superApplications':('applications','Applications'),
    'superApiResources':('apiResources','APIResources'),
    'superScimUsers':('Resources',),
    'superScimRolesV2':('Resources',),
}

class Refuse(Exception):pass

def admin_auth():
    if ADMIN.is_symlink() or not ADMIN.is_file():raise Refuse('ADMIN_JOURNAL_MISSING_OR_UNSAFE')
    s=ADMIN.stat()
    if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        raise Refuse('ADMIN_PRIVATE_FILE_MODE_OR_OWNER_UNSAFE')
    obj=json.loads(ADMIN.read_text())
    if obj.get('username')!='admin' or not isinstance(obj.get('password'),str) or not obj['password']:
        raise Refuse('ADMIN_CONTEXT_INVALID')
    return 'Basic '+base64.b64encode(('admin:'+obj['password']).encode()).decode('ascii')

def is_approved_cursor_request(path):
    """Only allow local, cursor-based continuations of the pinned endpoint."""
    if not isinstance(path,str) or len(path)>2048 or not path.startswith(API_RESOURCE_PATH+'?'):
        return False
    try:
        parsed=urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path!=API_RESOURCE_PATH:
            return False
        pairs=parse_qsl(parsed.query,keep_blank_values=True,strict_parsing=True,max_num_fields=8)
        qs={}
        for k,v in pairs:
            if k in qs or k not in ('limit','after'):
                return False
            qs[k]=v
        return (qs.get('limit')=='100' and isinstance(qs.get('after'),str)
                and valid_cursor(qs['after']))
    except ValueError:
        return False


def valid_cursor(value):
    # Opaque URL-safe/standard Base64 and common opaque page tokens; never decode.
    return (isinstance(value,str) and 0<len(value)<=512 and
            all(c.isascii() and (c.isalnum() or c in '_-+/=') for c in value))


def forward_api_cursor(doc):
    """Get the forward cursor, never trust a remote host, path or query."""
    links=doc.get('links')
    if not isinstance(links,list) or len(links)>40:
        return None
    cursors=[]
    for link in links:
        if not isinstance(link,dict) or link.get('rel') not in ('next','after'):
            continue
        href=link.get('href')
        if not isinstance(href,str) or not 0<len(href)<=2048:
            return None
        try:
            u=urlsplit(href)
            if u.fragment or u.scheme not in ('','https'):
                return None
            if u.netloc:
                # 9443 may be the server's advertised port; all actual GETs
                # still go to locally pinned 9444, never to the advertised host.
                if u.scheme!='https' or u.username or u.password or u.hostname not in ('localhost','127.0.0.1') or u.port not in (9443,9444):
                    return None
            elif u.scheme:
                return None
            # Support absolute local links, origin-relative and query-relative.
            if u.path not in ('',API_RESOURCE_PATH):
                return None
            if not u.path and not href.startswith('?'):
                return None
            pairs=parse_qsl(u.query,keep_blank_values=True,strict_parsing=True,max_num_fields=8)
            qs={}
            for k,v in pairs:
                if k in qs or k not in ('limit','after'):
                    return None
                qs[k]=v
            if 'limit' in qs and qs['limit']!='100':
                return None
            token=qs.get('after')
            if not valid_cursor(token):
                return None
            cursors.append(token)
        except ValueError:
            return None
    return cursors[0] if len(cursors)==1 else None


def get(path,auth,context):
    if path not in PATHS.values() and not is_approved_cursor_request(path):
        raise Refuse('PATH_NOT_ALLOWLISTED')
    conn=http.client.HTTPSConnection('localhost',9444,context=context,timeout=12)
    try:
        conn.request('GET',path,headers={'Authorization':auth,'Accept':'application/json'})
        response=conn.getresponse()
        raw=response.read(200001)
        if len(raw)>200000:raise Refuse('RESPONSE_TOO_LARGE')
        if response.status != 200:return response.status,None
        try:doc=json.loads(raw)
        except ValueError:raise Refuse('JSON_RESPONSE_INVALID')
        return response.status,doc
    finally:conn.close()

def compact(name,status,doc):
    if status!=200:return {'status':'UNVERIFIED_HTTP_'+str(status)}
    if not isinstance(doc,dict):return {'status':'UNVERIFIED_COLLECTION_SCHEMA'}
    arr=next((doc[k] for k in COLLECTION_KEYS[name] if isinstance(doc.get(k),list)),None)
    total=doc.get('totalResults')
    if arr is None and total==0:arr=[]
    if not isinstance(arr,list):return {'status':'UNVERIFIED_COLLECTION_SCHEMA'}
    # A partial first page is not an authoritative complete inventory.
    complete= isinstance(total,int) and total==len(arr)
    result={'status':'FULL_FIRST_PAGE' if complete else 'PARTIAL_OR_UNVERIFIED',
            'pageCount':len(arr),'reportedTotal':total}
    if name=='rootTenants':
        result['domains']=[x.get('domain') for x in arr if isinstance(x,dict) and isinstance(x.get('domain'),str)]
    elif name=='superApplications':
        result['applicationNames']=[x.get('name') for x in arr if isinstance(x,dict) and isinstance(x.get('name'),str)][:100]
    elif name=='superApiResources':
        result['resourceIdentifiers']=[x.get('identifier') for x in arr if isinstance(x,dict) and isinstance(x.get('identifier'),str)][:100]
    elif name=='superScimUsers':
        result['adminAccountSeen']=any(x.get('userName') in ('admin','PRIMARY/admin') for x in arr if isinstance(x,dict))
        result['otherUserCountOnPage']=sum(x.get('userName') not in ('admin','PRIMARY/admin') for x in arr if isinstance(x,dict))
    elif name=='superScimRolesV2':
        result['roleNames']=[x.get('displayName') for x in arr if isinstance(x,dict) and isinstance(x.get('displayName'),str)][:100]
    return result

def complete_api_resources(auth,context):
    """Bounded cursor walk. A bad page stays UNVERIFIED, never a partial PASS."""
    identifiers=[]
    seen_ids=set()
    seen_cursors=set()
    expected_total=None
    path=PATHS['superApiResources']
    pages=0
    failure=None
    while pages<MAX_API_RESOURCE_PAGES:
        pages+=1
        try:
            status,doc=get(path,auth,context)
        except (OSError,Refuse,ssl.SSLError,http.client.HTTPException):
            failure='PAGE_GET_UNVERIFIED'
            break
        if status!=200:
            failure='PAGE_HTTP_UNVERIFIED'
            break
        if not isinstance(doc,dict):
            failure='PAGE_SCHEMA_UNVERIFIED'
            break
        a=next((doc[k] for k in COLLECTION_KEYS['superApiResources']
                 if isinstance(doc.get(k),list)),None)
        total=doc.get('totalResults')
        if (type(total) is not int or not 0<=total<=MAX_API_RESOURCES or
           not isinstance(a,list) or len(a)>100 or
           (len(a)==0 and total>len(identifiers))):
            failure='PAGE_CARDINALITY_UNVERIFIED'
            break
        if expected_total is None:
            expected_total=total
        if total!=expected_total or len(identifiers)+len(a)>total:
            failure='TOTAL_CHANGED_OR_OVERFLOW'
            break
        new=[]
        for item in a:
            value=item.get('identifier') if isinstance(item,dict) else None
            if (not isinstance(value,str) or not 0<len(value)<=512 or
                value in seen_ids or value in new):
                failure='INVALID_OR_DUPLICATE_IDENTIFIER'
                break
            new.append(value)
        if failure:
            break
        identifiers.extend(new)
        seen_ids.update(new)
        if len(identifiers)==expected_total:
            if pages==1:
                return {'status':'FULL_FIRST_PAGE','pageCount':len(identifiers),
                        'reportedTotal':expected_total,'resourceIdentifiers':identifiers}
            return {'status':'FULL_PAGINATED','pageCount':len(identifiers),
                    'reportedTotal':expected_total,'resourceIdentifiers':identifiers,
                    'pagesFetched':pages,'paginationMode':'WSO2_AFTER_CURSOR'}
        cursor=forward_api_cursor(doc)
        if cursor is None:
            failure='FORWARD_CURSOR_UNVERIFIED'
            break
        if cursor in seen_cursors:
            failure='REPEATED_CURSOR'
            break
        seen_cursors.add(cursor)
        path=API_RESOURCE_PATH+'?limit=100&after='+quote(cursor,safe='')
    if failure is None:
        failure='PAGE_LIMIT_EXCEEDED'
    return {'status':'PARTIAL_OR_UNVERIFIED',
            'pageCount':len(identifiers),'reportedTotal':expected_total,
            'pagesFetched':pages,'verificationCode':failure}

def main():
    auth=admin_auth()
    cert=ssl.get_server_certificate(('localhost',9444))
    ctx=ssl.create_default_context(cadata=cert)
    ctx.check_hostname=False  # laboratory cert pin; consistent with v10 bootstrap
    result={'stage':'CARBON_SUPER_READ_ONLY','remoteWrites':0,
            'identityAuthority':'carbon.super','inventory':{}}
    for name,path in PATHS.items():
        try:
            if name=='superApiResources':
                result['inventory'][name]=complete_api_resources(auth,ctx)
            else:
                status,doc=get(path,auth,ctx)
                result['inventory'][name]=compact(name,status,doc)
        except (OSError,Refuse,ssl.SSLError,http.client.HTTPException) as e:
            result['inventory'][name]={'status':'UNVERIFIED_'+type(e).__name__}
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    try:main()
    except (Refuse,ValueError,KeyError,OSError) as exc:
        print('REFUSED:',str(exc) if isinstance(exc,Refuse) else type(exc).__name__,file=sys.stderr)
        sys.exit(2)
