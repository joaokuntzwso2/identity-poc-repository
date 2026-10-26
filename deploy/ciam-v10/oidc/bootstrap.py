#!/usr/bin/env python3
"""Guarded WSO2 IS 7.3 v10 tenant OIDC app bootstrap and isolated BFF bridge.

Never touches the original WSO2 9443 or BFF 4000 processes. Lab only.
Pairwise subject requested but the explicit two-sector-host requirement remains separate.
"""
import base64
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import uuid

ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10')))
PRIVATE = ROOT / 'private'
BASE = 'https://localhost:9444'
TENANTS = PRIVATE / 'bootstrap-tenants-v10.private.json'
RESOURCES = PRIVATE / 'bootstrap-resources-v10.private.json'
OIDC = PRIVATE / 'bootstrap-oidc-v10.private.json'
LOCK = PRIVATE / 'bootstrap-oidc-v10.lock'
CERT = PRIVATE / 'wso2-9444-leaf.pem'
BFF_ORIGIN = 'http://127.0.0.1:4400'
DOMAINS = {'aurora':'aurora.identity.test', 'brisa':'brisa.identity.test'}
CHANNELS = ('web','app')
KEYS = tuple(f'{b}-{c}' for b in DOMAINS for c in CHANNELS)
ID = re.compile(r'^[A-Za-z0-9_-]{5,256}={0,2}$')
CONFIRM = 'CREATE_FOUR_V10_OIDC_APPS'
NAME = lambda b,c: f'Identity Lab v10 {b.title()} {"Web" if c == "web" else "Mobile Browser Preview"}'
CALLBACK = lambda b,c: f'{BFF_ORIGIN}/auth/{b}-{c}/callback'

class Refuse(Exception): pass

def read_private(path):
    if path.is_symlink() or not path.is_file(): raise Refuse('PRIVATE_FILE_NOT_REGULAR_'+path.name)
    s=path.stat()
    if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_uid!=os.getuid():
        raise Refuse('PRIVATE_FILE_MODE_OR_OWNER_'+path.name)
    raw=path.read_bytes()
    if len(raw)>256000:raise Refuse('PRIVATE_FILE_TOO_LARGE')
    try:return json.loads(raw)
    except ValueError:raise Refuse('PRIVATE_JSON_INVALID') from None

def atomic_save(path, data):
    if path.is_symlink():raise Refuse('PRIVATE_TARGET_SYMLINK')
    if path.exists():read_private(path)
    parent=path.parent
    if parent.is_symlink() or not parent.is_dir() or (stat.S_IMODE(parent.stat().st_mode)&0o022):
        raise Refuse('PRIVATE_DIRECTORY_UNSAFE')
    fd,tmp=tempfile.mkstemp(prefix='.v10-oidc-',dir=parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600)
            json.dump(data,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        pfd=os.open(parent,os.O_RDONLY)
        try:os.fsync(pfd)
        finally:os.close(pfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def read_context():
    ts=read_private(TENANTS)
    rs=read_private(RESOURCES)
    if ts.get('schema')!='identity.wso2.ciam.v10.tenants' or ts.get('base')!=BASE or ts.get('domains')!=DOMAINS:
        raise Refuse('TENANT_CONTEXT_INVALID')
    if rs.get('schema')!='identity.wso2.ciam.v10.resources.v1' or rs.get('base')!=BASE or rs.get('acceptance')!='MANAGEMENT_AND_USERS_VERIFIED_OIDC_NOT_PROVISIONED':
        raise Refuse('RESOURCES_NOT_VERIFIED')
    for b,domain in DOMAINS.items():
        a=ts.get('tenants',{}).get(b,{})
        r=rs.get('tenants',{}).get(b,{})
        if a.get('status')!='readback-verified' or a.get('domain')!=domain or r.get('domain')!=domain or a.get('tenantId')!=r.get('tenantId') or a.get('ownerId')!=r.get('ownerId'):
            raise Refuse('TENANT_ID_MISMATCH_'+b)
        m=r.get('management',{})
        u=r.get('user',{})
        if m.get('state')!='verified' or not m.get('clientId') or not m.get('clientSecret') or not ID.fullmatch(str(m.get('id',''))) or u.get('state')!='verified-browser-not-tested' or u.get('username')!=f'ciam_{b}' or not ID.fullmatch(str(u.get('id',''))):
            raise Refuse('RESOURCES_INCOMPLETE_'+b)
    return ts,rs

def auth_basic(user,secret):
    return 'Basic '+base64.b64encode((user+':'+secret).encode()).decode()

class HTTPS:
    def __init__(self):
        cert=ssl.get_server_certificate(('localhost',9444))
        self.context=ssl.create_default_context(cadata=cert)
        self.context.check_hostname=False
        self.pem=cert
    def call(self, method, path, *, auth=None, data=None, form=None):
        if method not in ('GET','POST') or not path.startswith('/') or path.startswith('//') or '..' in path or '\\' in path or '#' in path or len(path)>2500:
            raise Refuse('UNSAFE_PATH_OR_METHOD')
        if not any(path.startswith(f'/t/{d}/') for d in DOMAINS.values()):raise Refuse('UNEXPECTED_TENANT_PATH')
        if data is not None and form is not None:raise Refuse('BOTH_BODIES_UNSAFE')
        headers={'Accept':'application/json'}
        if auth:headers['Authorization']=auth
        body=None
        if data is not None:headers['Content-Type']='application/json';body=json.dumps(data)
        if form is not None:headers['Content-Type']='application/x-www-form-urlencoded';body=urllib.parse.urlencode(form)
        c=http.client.HTTPSConnection('localhost',9444,context=self.context,timeout=18)
        try:
            c.request(method,path,body=body,headers=headers)
            r=c.getresponse()
            raw=r.read(300001)
            if len(raw)>300000:raise Refuse('OVERSIZED_RESPONSE')
            if 300<=r.status<400:raise Refuse('REDIRECT_REFUSED')
            try:obj=json.loads(raw) if raw else {}
            except ValueError:
                if 200<=r.status<300:raise Refuse('NONJSON_SUCCESS') from None
                obj={}
            return (r.status,obj,r.getheader('Location'))
        finally:c.close()

def require(resp,code,label):
    if resp[0]!=code:raise Refuse(label+'_HTTP_'+str(resp[0]))
    if not isinstance(resp[1],dict):raise Refuse(label+'_SHAPE_INVALID')
    return resp[1]

def bearer(client,rs,brand):
    m=rs['tenants'][brand]['management']
    domain=DOMAINS[brand]
    scopes=('internal_application_mgt_create','internal_application_mgt_view','internal_application_mgt_client_secret_view')
    form={'grant_type':'client_credentials','scope':' '.join(scopes)}
    data=require(client.call('POST',f'/t/{domain}/oauth2/token',auth=auth_basic(m['clientId'],m['clientSecret']),form=form),200,'TOKEN_'+brand)
    actual=set(str(data.get('scope','')).split())
    if data.get('token_type','').lower()!='bearer' or not data.get('access_token') or not set(scopes).issubset(actual):
        raise Refuse('M2M_SCOPES_NOT_GRANTED_'+brand)
    return 'Bearer '+data['access_token']

def collection(obj):
    if isinstance(obj,list):return obj
    if not isinstance(obj,dict):raise Refuse('APP_COLLECTION_INVALID')
    for field in ('applications','Applications','list'):
        if isinstance(obj.get(field),list):
            xs=obj[field]
            if isinstance(obj.get('totalResults'),int) and obj['totalResults']>len(xs):raise Refuse('APP_LIST_INCOMPLETE')
            return xs
    if obj.get('totalResults')==0 and obj.get('count',0)==0:return []
    raise Refuse('APP_COLLECTION_SHAPE')

def inventory(client,brand,token,name):
    root=f'/t/{DOMAINS[brand]}/api/server/v1/applications'
    q=urllib.parse.urlencode({'limit':'100','offset':'0','filter':f'name eq {name}'})
    xs=collection(require(client.call('GET',root+'?'+q,auth=token),200,'APP_INVENTORY_'+brand))
    found=[x for x in xs if isinstance(x,dict) and x.get('name')==name]
    if len(found)>1:raise Refuse('DUPLICATE_APPLICATION_NAME_'+brand)
    return found[0] if found else None

def callback_from_protocol(protocol):
    callbacks=protocol.get('callbackURLs')
    if not isinstance(callbacks,list):raise Refuse('OIDC_CALLBACKS_NOT_EXPOSED')
    return callbacks

def check_app(client,brand,channel,token,node):
    appid=node.get('id');domain=DOMAINS[brand]
    if not ID.fullmatch(str(appid or '')):raise Refuse('APP_ID_INVALID_'+brand+'_'+channel)
    root=f'/t/{domain}/api/server/v1/applications/{urllib.parse.quote(appid,safe="")}'
    app=require(client.call('GET',root,auth=token),200,'APP_READBACK_'+brand+'_'+channel)
    if app.get('id')!=appid or app.get('name')!=node['name'] or app.get('description')!=node['description'] or app.get('isManagementApp') is not False:
        raise Refuse('APP_REMOTE_IDENTITY_MISMATCH_'+brand+'_'+channel)
    protocol=require(client.call('GET',root+'/inbound-protocols/oidc',auth=token),200,'OIDC_READBACK_'+brand+'_'+channel)
    if not isinstance(protocol.get('clientId'),str) or not protocol.get('clientId') or not isinstance(protocol.get('clientSecret'),str) or not protocol.get('clientSecret'):
        raise Refuse('OIDC_CREDENTIALS_NOT_EXPOSED_'+brand+'_'+channel)
    if set(protocol['clientSecret']) == {'*'} or 'REDACTED' in protocol['clientSecret'].upper():
        raise Refuse('OIDC_SECRET_MASKED_'+brand+'_'+channel)
    if callback_from_protocol(protocol)!=[node['callback']]:raise Refuse('OIDC_CALLBACK_MISMATCH_'+brand+'_'+channel)
    if protocol.get('publicClient') is not False:raise Refuse('OIDC_NOT_CONFIDENTIAL_'+brand+'_'+channel)
    if 'authorization_code' not in protocol.get('grantTypes',[]):raise Refuse('OIDC_CODE_GRANT_MISSING_'+brand+'_'+channel)
    if protocol.get('subject',{}).get('subjectType')!='pairwise':raise Refuse('OIDC_PAIRWISE_NOT_CONFIGURED_'+brand+'_'+channel)
    if protocol.get('subject',{}).get('sectorIdentifierUri') not in (None,''):
        raise Refuse('OIDC_UNEXPECTED_SECTOR_URI_'+brand+'_'+channel)
    if protocol.get('pkce',{}).get('mandatory') is not True:
        raise Refuse('OIDC_PKCE_NOT_MANDATORY_'+brand+'_'+channel)
    if node.get('clientId') and node['clientId']!=protocol['clientId']:raise Refuse('OIDC_CLIENT_ID_DRIFT')
    node['clientId']=protocol['clientId'];node['clientSecret']=protocol['clientSecret']
    return {'appIdRecorded':True,'callback':'PORT_4400_VERIFIED','pairwise':'APP_CONFIGURED_NO_SECTOR_URI','browser':'NOT_VERIFIED'}

def discovery(client,brand):
    domain=DOMAINS[brand]
    # WSO2's issuer and signing key location must come from metadata, not guesses.
    path=f'/t/{domain}/oauth2/token/.well-known/openid-configuration'
    status,doc,_=client.call('GET',path)
    if status!=200:raise Refuse('OIDC_DISCOVERY_HTTP_'+str(status)+'_'+brand)
    issuer=doc.get('issuer')
    if not isinstance(issuer,str) or not issuer.startswith(f'{BASE}/t/{domain}/'):
        raise Refuse('OIDC_DISCOVERY_ISSUER_MISMATCH_'+brand)
    jwks=doc.get('jwks_uri')
    if not isinstance(jwks,str) or not jwks.startswith(BASE+'/'):
        raise Refuse('OIDC_DISCOVERY_JWKS_MISMATCH_'+brand)
    return issuer

def default_state(ts,rs):
    return {'schema':'identity.wso2.ciam.v10.oidc.v1','base':BASE,'bffOrigin':BFF_ORIGIN,
            'tenants':{b:{'domain':d,'tenantId':ts['tenants'][b]['tenantId'],
                            'managementAppId':rs['tenants'][b]['management']['id'],
                            'clients':{}} for b,d in DOMAINS.items()},
            'acceptance':'NOT_VERIFIED'}

def check_state(s,ts,rs):
    expect=default_state(ts,rs)
    if s.get('schema')!=expect['schema'] or s.get('base')!=BASE or s.get('bffOrigin')!=BFF_ORIGIN:
        raise Refuse('OIDC_JOURNAL_CONTEXT_DRIFT')
    for b in DOMAINS:
        for k in ('domain','tenantId','managementAppId'):
            if s.get('tenants',{}).get(b,{}).get(k)!=expect['tenants'][b][k]:raise Refuse('OIDC_JOURNAL_OWNER_DRIFT_'+b)
        if not isinstance(s['tenants'][b].get('clients'),dict):raise Refuse('OIDC_JOURNAL_CLIENTS_INVALID')
    return s

def run(client,ts,rs,s,mode,save):
    tokens={b:bearer(client,rs,b) for b in DOMAINS}
    # Metadata checked before any application write.
    issuers={b:discovery(client,b) for b in DOMAINS}
    if issuers['aurora']==issuers['brisa']:raise Refuse('TENANT_ISSUERS_IDENTICAL')
    # Inventory *all four* before the first write. An unjournaled name collision
    # in Brisa must not leave Aurora half-provisioned.
    existing_apps={}
    for b in DOMAINS:
        for c in CHANNELS:
            remote=inventory(client,b,tokens[b],NAME(b,c))
            journal=s['tenants'][b]['clients'].get(c)
            if remote and journal is None:
                raise Refuse('UNJOURNALED_APP_COLLISION_'+b+'_'+c)
            if remote and journal and journal.get('id') and remote.get('id')!=journal['id']:
                raise Refuse('REMOTE_APP_ID_DRIFT_'+b+'_'+c)
            existing_apps[(b,c)]=remote
    if mode=='plan':
        return {'stage':'V10_OIDC','mode':'READ_ONLY_PLUS_OAUTH_TOKEN','clientsPlanned':4,
                'tenantBearerAuthorization':'VERIFIED_BOTH','issuers':'DISTINCT_BOTH',
                'registeredCallbackOrigin':BFF_ORIGIN,'remoteResourceWrites':0,
                'pairwiseSectorDocument':'NOT_IN_THIS_STAGE'}
    if mode!='apply' or os.environ.get('WSO2_CIAM_V10_OIDC_CONFIRM')!=CONFIRM:
        raise Refuse('OIDC_WRITE_CONFIRMATION_REQUIRED')
    out={}
    for b in DOMAINS:
        for c in CHANNELS:
            brandnode=s['tenants'][b]['clients']
            token=tokens[b]; name=NAME(b,c)
            node=brandnode.get(c)
            existing=existing_apps[(b,c)]
            if node is None:
                node={'state':'prepared','name':name,'description':'v10-managed:'+str(uuid.uuid4()),
                      'callback':CALLBACK(b,c),'channel':c,'domain':DOMAINS[b]}
                brandnode[c]=node;save()
            if any(node.get(k)!=v for k,v in (('name',name),('callback',CALLBACK(b,c)),('channel',c),('domain',DOMAINS[b]))):
                raise Refuse('OIDC_APP_JOURNAL_DRIFT_'+b+'_'+c)
            if node['state']=='prepared':
                if existing:raise Refuse('PREPARED_APP_REMOTE_COLLISION_'+b+'_'+c)
                node['state']='create-started';save()
                payload={'name':name,'description':node['description'], 'isManagementApp':False,
                         'accessUrl':BFF_ORIGIN+'/',
                         'inboundProtocolConfiguration':{'oidc':{
                            'grantTypes':['authorization_code','refresh_token'],
                            'publicClient':False,
                            'callbackURLs':[node['callback']],
                            'pkce':{'mandatory':True,'supportPlainTransformAlgorithm':False},
                            'subject':{'subjectType':'pairwise'},
                            'accessToken':{'type':'JWT','userAccessTokenExpiryInSeconds':1800,
                                           'applicationAccessTokenExpiryInSeconds':1800}}}}
                resp=client.call('POST',f'/t/{DOMAINS[b]}/api/server/v1/applications',auth=token,data=payload)
                if resp[0]!=201:raise Refuse('OIDC_CREATE_HTTP_'+str(resp[0])+'_'+b+'_'+c+'_DO_NOT_RETRY')
                appid=resp[1].get('id') or str(resp[2] or '').split('?')[0].rstrip('/').split('/')[-1]
                if not ID.fullmatch(str(appid)):raise Refuse('OIDC_APP_ID_MISSING_'+b+'_'+c+'_DO_NOT_RETRY')
                node['id']=appid;node['state']='created';save()
            elif node['state']=='create-started':
                if not existing or not ID.fullmatch(str(existing.get('id',''))):
                    raise Refuse('OIDC_CREATE_OUTCOME_UNCERTAIN_'+b+'_'+c+'_DO_NOT_RETRY')
                if existing.get('description')!=node.get('description'):
                    # app list often omits descriptions: detail GET is required.
                    detail=require(client.call('GET',f'/t/{DOMAINS[b]}/api/server/v1/applications/{existing["id"]}',auth=token),200,'UNCERTAIN_APP_READ_'+b+'_'+c)
                    if detail.get('description')!=node['description']:
                        raise Refuse('UNCERTAIN_APP_NOT_OWNED_'+b+'_'+c)
                node['id']=existing['id']
                # readback validates exact client & callback before journaling recovery
                check_app(client,b,c,token,node)
                node['state']='verified';save()
            else:
                if node['state'] not in ('created','verified'):
                    raise Refuse('UNKNOWN_APP_STATE_'+b+'_'+c)
            result=check_app(client,b,c,token,node)
            node['state']='verified';save()
            out[f'{b}-{c}']=result
    ids=[s['tenants'][b]['clients'][c]['clientId'] for b in DOMAINS for c in CHANNELS]
    if len(set(ids))!=4:raise Refuse('DUPLICATE_OIDC_CLIENT_IDS')
    s['issuers']=issuers
    s['acceptance']='FOUR_OIDC_REGISTERED_BROWSER_NOT_VERIFIED_PAIRWISE_SECTOR_PENDING';save()
    return {'stage':'V10_OIDC','mode':'APPLIED','clients':out,
            'oidcClients':'FOUR_REGISTERED_AND_READBACK_VERIFIED',
            'pairwiseSectorDocument':'NOT_CONFIGURED',
            'browserAuthentication':'NOT_VERIFIED','acceptance':'RESOURCE_ONLY'}

def status(s):
    return {'stage':'V10_OIDC','base':BASE,'callbackOrigin':BFF_ORIGIN,
            'clients':{f'{b}-{c}':s.get('tenants',{}).get(b,{}).get('clients',{}).get(c,{}).get('state','NOT_STARTED')
                       for b in DOMAINS for c in CHANNELS},
            'pairwiseSectorDocument':'NOT_CONFIGURED',
            'browserAuthentication':'NOT_VERIFIED',
            'acceptance':s.get('acceptance','NOT_VERIFIED')}

def bridge_manifest(s):
    if any(s['tenants'][b]['clients'].get(c,{}).get('state')!='verified' for b in DOMAINS for c in CHANNELS):
        raise Refuse('FOUR_OIDC_APPS_NOT_VERIFIED')
    result={'schema':'identity.wso2.ciam.v10.bff.v1','brands':{}}
    for b in DOMAINS:
        result['brands'][b]={'issuer':s['issuers'][b],'tenantDomain':DOMAINS[b],'clients':{}}
        for c in CHANNELS:
            n=s['tenants'][b]['clients'][c]
            result['brands'][b]['clients'][c]={'clientId':n['clientId'],'clientSecret':n['clientSecret'],
                'callback':n['callback'],'tenantDomain':DOMAINS[b]}
    return result

def publish_bff(s,repo):
    repo=Path(repo).expanduser().resolve()
    if (not (repo/'services/identity-bff/src/server.js').is_file()
            or not (repo/'wso2-lab.sh').is_file()
            or not (repo/'deploy/ciam-v10/cli.py').is_file()
            or (repo/'var').is_symlink()):
        raise Refuse('UNEXPECTED_BFF_REPOSITORY')
    d=repo/'var/wso2'
    if d.is_symlink() or not d.is_dir() or (stat.S_IMODE(d.stat().st_mode)&0o022):
        raise Refuse('BFF_PRIVATE_DIRECTORY_UNSAFE')
    out=d/'identity-bff-v10.private.json'
    want=bridge_manifest(s)
    if out.exists() or out.is_symlink():
        have=read_private(out)
        if have!=want:raise Refuse('BFF_MANIFEST_EXISTS_DIFFERENT_REFUSED')
    else:atomic_save(out,want)
    if CERT.is_symlink():raise Refuse('PINNED_CERT_SYMLINK')
    if CERT.exists():
        cert=read_pem(CERT)
    else:
        cert=ssl.get_server_certificate(('localhost',9444))
        fd=os.open(CERT,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(cert);f.flush();os.fsync(f.fileno())
    return {'bffManifest':'PRIVATE_NEW_V10_FILE_VERIFIED','wso2Certificate':'LOCAL_PINNED',
            'startCommand':'python3 bootstrap.py start-bff --repo '+str(repo)}

def read_pem(p):
    if p.is_symlink() or not p.is_file() or stat.S_IMODE(p.stat().st_mode)!=0o600 or p.stat().st_uid!=os.getuid():
        raise Refuse('CERT_FILE_UNSAFE')
    return p.read_text()

def start_bff(s,repo):
    report=publish_bff(s,repo)
    repo=Path(repo).resolve()
    port_check=__import__('socket').socket()
    try:
        port_check.settimeout(0.5)
        if port_check.connect_ex(('127.0.0.1',4400))==0:raise Refuse('PORT_4400_IN_USE_REFUSED')
    finally:port_check.close()
    env=os.environ.copy()
    env.update({'IDENTITY_MODE':'live-wso2','PORT':'4400','PUBLIC_ORIGIN':BFF_ORIGIN,
                'ALLOW_INSECURE_LOCAL':'true','BIND_HOST':'127.0.0.1',
                'WSO2_BFF_PRIVATE_MANIFEST':str(repo/'var/wso2/identity-bff-v10.private.json'),
                'NODE_EXTRA_CA_CERTS':str(CERT),'NODE_ENV':'development'})
    logfile=PRIVATE/'bff-v10.log';pidfile=PRIVATE/'bff-v10.pid'
    if pidfile.exists() or pidfile.is_symlink():raise Refuse('PIDFILE_EXISTS_REFUSED')
    fd=os.open(logfile,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try:
        proc=subprocess.Popen(['node','services/identity-bff/src/server.js'],cwd=repo,env=env,
                              stdin=subprocess.DEVNULL,stdout=fd,stderr=subprocess.STDOUT,start_new_session=True)
    finally:os.close(fd)
    fd=os.open(pidfile,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as f:f.write(str(proc.pid)+'\n');f.flush();os.fsync(f.fileno())
    return {**report,'bffProcess':'START_REQUESTED','pidRecorded':True,'browserAuth':'NOT_VERIFIED',
            'health':'CHECK http://127.0.0.1:4400/api/identity/me'}

def main():
    cmd=sys.argv[1] if len(sys.argv)>1 else 'plan'
    if cmd not in ('plan','apply','status','bridge-bff','start-bff'):raise Refuse('EXPECTED_plan_apply_status_bridge-bff_start-bff')
    if Path.cwd().resolve()!=ROOT.resolve():raise Refuse('RUN_ONLY_IN_V10_DIRECTORY')
    ts,rs=read_context()
    s=read_private(OIDC) if OIDC.exists() or OIDC.is_symlink() else default_state(ts,rs)
    check_state(s,ts,rs)
    if cmd=='status':result=status(s)
    elif cmd in ('bridge-bff','start-bff'):
        if len(sys.argv)!=4 or sys.argv[2]!='--repo':raise Refuse('EXPECTED_--repo_PATH')
        result=publish_bff(s,sys.argv[3]) if cmd=='bridge-bff' else start_bff(s,sys.argv[3])
    else:
        client=HTTPS()
        if cmd=='apply':
            if LOCK.exists() or LOCK.is_symlink():raise Refuse('EXISTING_OIDC_LOCK_REFUSED')
            fd=os.open(LOCK,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try:result=run(client,ts,rs,s,cmd,lambda:atomic_save(OIDC,s))
            finally:os.close(fd);LOCK.unlink()
        else:result=run(client,ts,rs,s,cmd,lambda:None)
    print(json.dumps(result,indent=2))
if __name__=='__main__':
    try:main()
    except (Refuse,OSError,ValueError,KeyError,ssl.SSLError,http.client.HTTPException) as e:
        print('CIAM_V10_OIDC_STOP: '+(str(e) if isinstance(e,Refuse) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
