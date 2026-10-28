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

ROOT = Path(os.environ.get('CIAM_V10_HOME',str(Path.home()/'wso2-ciam-v10')))
ADMIN = ROOT/'private/admin.private.json'
PATHS = {
    'rootTenants':'/api/server/v1/tenants?limit=100&offset=0',
    'superApplications':'/api/server/v1/applications?limit=100&offset=0',
    'superApiResources':'/api/server/v1/api-resources?limit=100&offset=0',
    'superScimUsers':'/scim2/Users?count=100&startIndex=1',
    'superScimRolesV2':'/scim2/v2/Roles?count=100&startIndex=1',
}
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

def get(path,auth,context):
    if path not in PATHS.values():raise Refuse('PATH_NOT_ALLOWLISTED')
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

def main():
    auth=admin_auth()
    cert=ssl.get_server_certificate(('localhost',9444))
    ctx=ssl.create_default_context(cadata=cert)
    ctx.check_hostname=False  # laboratory cert pin; consistent with v10 bootstrap
    result={'stage':'CARBON_SUPER_READ_ONLY','remoteWrites':0,
            'identityAuthority':'carbon.super','inventory':{}}
    for name,path in PATHS.items():
        try:
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
