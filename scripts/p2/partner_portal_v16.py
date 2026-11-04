#!/usr/bin/env python3
"""P2.24 V16: one approved Aurora partner portal OIDC registration during bootstrap.

One management POST maximum; durable prior intent; exact independent GET readback.
Never shares apps, assigns roles, grants scopes, provisions users, or touches Brisa.
An existing intent MUST be resolved GET-only, never replayed.
"""
from __future__ import annotations
import contextlib,fcntl,hashlib,importlib.util,json,os,re,stat,sys,urllib.parse
from pathlib import Path

TENANT='aurora.identity.test'
NAME='P2 Aurora Returns Partner Business Portal'
DESCRIPTION='P2.24 dedicated Aurora Returns partner portal registration; no sharing, business scopes or delegated privileges.'
BASE=f'/t/{TENANT}/api/server/v1/applications'
SCHEMA='p2.24.aurora.partner-portal.v16'
JOURNAL='p2-aurora-partner-business-portal-v16.private.json'
LOCK='p2-aurora-partner-business-portal-v16.lock'
PARTNER_FP='a9c40a10acabab52'
ROOT_FP='4548812d1a94a3ff'
APPROVAL='APPROVE_V16_AURORA_PARTNER_PORTAL_REGISTER_ONLY'
MAX_APPS=4000

class Stop(Exception):pass
def need(ok,code):
    if not ok:raise Stop(code)
def safe(e):
    return str(e) if type(e) is Stop and re.fullmatch(r'[A-Z][A-Z0-9_]{3,100}',str(e)) else 'V16_UNEXPECTED_ERROR_CHECK_PRIVATE_JOURNAL'
def fp(x):return hashlib.sha256(x.encode('utf8')).hexdigest()[:16]
def report(status,code,**kw):
    result=dict(phase='P2.24',tenant=TENANT,status=status,code=code,
                managementWrites=0,sharingPerformed=False,usersCreated=False,
                rolesGranted=False,businessAuthorizationVerified=False,
                delegatedAdministrationVerified=False)
    result.update(kw)
    return result
def load(path,key):
    need(path.is_file() and not path.is_symlink(),'V16_DEPENDENCY_MISSING')
    spec=importlib.util.spec_from_file_location(key,path)
    need(spec and spec.loader,'V16_DEPENDENCY_INVALID')
    mod=importlib.util.module_from_spec(spec)
    try:spec.loader.exec_module(mod)
    except Exception:raise Stop('V16_DEPENDENCY_IMPORT_FAILED')
    return mod

@contextlib.contextmanager
def locked(private):
    fd=os.open(private/LOCK,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid()
             and stat.S_IMODE(s.st_mode)==0o600,'V16_LOCK_UNSAFE')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:raise Stop('V16_CONCURRENT_BOOTSTRAP_BLOCKED')
        yield
    finally:
        try:fcntl.flock(fd,fcntl.LOCK_UN)
        finally:os.close(fd)

def secure_callback(raw):
    """Only one static, already registered, non-regex BFF URI; no wildcard."""
    need(isinstance(raw,str) and 12<=len(raw)<=1024 and
         not any(c in raw for c in ('*','\\','\r','\n',' ','#','?')) and
         not raw.startswith('regexp='),'V16_CALLBACK_NOT_EXACT')
    u=urllib.parse.urlsplit(raw)
    need(not u.username and not u.password and not u.query and not u.fragment and
         u.hostname in ('localhost','127.0.0.1') and
         (u.scheme=='https' or u.scheme=='http') and
         u.port is not None and 1024 <= u.port <= 65535 and
         u.port not in (9443,9444) and
         u.path.startswith('/') and u.path!='/','V16_CALLBACK_ORIGIN_UNVERIFIED')
    need('callback' in u.path.lower() and
         all(x not in u.path for x in ('..','//','%',';')),
         'V16_CALLBACK_ROUTE_UNVERIFIED')
    return raw

def callback_in_project(repo,uri):
    """Require actual BFF route source mention; no use of frontend-only redirects."""
    path=urllib.parse.urlsplit(uri).path
    basedir=repo/'services/identity-bff'
    need(basedir.is_dir() and not basedir.is_symlink(),'V16_BFF_SOURCE_MISSING')
    matches=[]
    for directory,subdirs,files in os.walk(basedir,followlinks=False):
        subdirs[:]=[d for d in subdirs if d not in
                     ('node_modules','dist','test','tests','coverage','.git','build')
                     and not (Path(directory)/d).is_symlink()]
        for filename in sorted(files):
            f=Path(directory)/filename
            if f.is_symlink() or f.suffix not in ('.js','.mjs','.ts','.json'):continue
            if f.stat().st_size>350_000:continue
            text=f.read_text(encoding='utf8',errors='replace')
            if uri in text or path in text:matches.append(f)
    need(bool(matches),'V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF')
    return fp(path)

def matching_aurora_web(m,http,admin,repo,apps):
    """Do not invent a partner callback. Reuse an exact, existing Aurora BFF URI.

    This V16 registration alone does not wire the new client into BFF routing.
    The currently implemented callback's client binding remains unchanged.
    """
    candidates=[]
    for row in apps:
        label=row.get('name','')
        if not isinstance(label,str) or not re.search(r'\baurora\b',label,re.I) or not re.search(r'\bweb\b',label,re.I):continue
        app_id=row['id']
        code,detail,_=http.call('GET',f'{BASE}/{app_id}',basic=admin)
        need(code==200 and isinstance(detail,dict) and detail.get('id')==app_id and
             detail.get('name')==label and detail.get('isManagementApp') is False,
             'V16_SOURCE_APPLICATION_UNVERIFIED')
        code,oidc,_=http.call('GET',f'{BASE}/{app_id}/inbound-protocols/oidc',basic=admin)
        need(code==200 and isinstance(oidc,dict),'V16_SOURCE_OIDC_UNVERIFIED')
        grants=oidc.get('grantTypes')
        if not isinstance(grants,list) or 'authorization_code' not in grants:continue
        uris=oidc.get('callbackURLs')
        need(isinstance(uris,list) and len(uris)==1,'V16_EXISTING_AURORA_WEB_CALLBACK_AMBIGUOUS')
        uri=secure_callback(uris[0]);path_fp=callback_in_project(repo,uri)
        candidates.append((app_id,uri,path_fp))
    need(len(candidates)==1,'V16_EXACTLY_ONE_AURORA_WEB_CALLBACK_REQUIRED')
    return candidates[0]

def spec_for(uri):
    return {'name':NAME,'description':DESCRIPTION,'isManagementApp':False,
            'inboundProtocolConfiguration':{'oidc':{
              'grantTypes':['authorization_code'], 'callbackURLs':[uri],
              'publicClient':False,
              'pkce':{'mandatory':True,'supportPlainTransformAlgorithm':False}}}}

def spec_fp(uri):
    return fp(json.dumps(spec_for(uri),sort_keys=True,separators=(',',':')))

def strict_app_inventory(m,http,admin):
    apps=m.inventory(http,BASE,'applications',admin)
    need(len(apps)<=MAX_APPS,'V16_APPLICATION_INVENTORY_OVERSIZE')
    names=[];seen=set()
    for row in apps:
        need(isinstance(row,dict) and isinstance(row.get('id'),str) and
             bool(m.UUID.fullmatch(row['id'])) and isinstance(row.get('name'),str) and
             row['id'] not in seen,'V16_APPLICATION_INVENTORY_INVALID')
        seen.add(row['id'])
        if row['name']==NAME:names.append(row['id'])
    need(len(names)<=1,'V16_PORTAL_APP_NAME_DUPLICATE')
    return apps,names

def exact_readback(m,http,admin,app_id,uri):
    need(isinstance(app_id,str) and bool(m.UUID.fullmatch(app_id)), 'V16_APP_ID_INVALID')
    status,doc,_=http.call('GET',f'{BASE}/{app_id}',basic=admin)
    need(status==200 and isinstance(doc,dict) and doc.get('id')==app_id and
         doc.get('name')==NAME and doc.get('description')==DESCRIPTION and
         doc.get('isManagementApp') is False and doc.get('applicationEnabled') is not False,
         'V16_APPLICATION_DETAIL_MISMATCH')
    status,oidc,_=http.call('GET',f'{BASE}/{app_id}/inbound-protocols/oidc',basic=admin)
    need(status==200 and isinstance(oidc,dict), 'V16_OIDC_READBACK_UNAVAILABLE')
    need(oidc.get('callbackURLs')==[uri] and
         oidc.get('grantTypes')==['authorization_code'] and
         oidc.get('publicClient') is False and
         isinstance(oidc.get('clientId'),str) and len(oidc['clientId'])>=4 and
         isinstance(oidc.get('pkce'),dict) and
         oidc['pkce'].get('mandatory') is True and
         oidc['pkce'].get('supportPlainTransformAlgorithm') is False,
         'V16_OIDC_CONFIGURATION_NOT_EXACT')
    status,authz,_=http.call('GET',f'{BASE}/{app_id}/authorized-apis',basic=admin)
    need(status==200 and authz==[],'V16_UNEXPECTED_API_AUTHORIZATION')
    # Do not interpret missing /share or /shared-apps metadata as no sharing.
    return {'applicationFingerprint':m.hash_id(app_id),'callbackFingerprint':fp(uri)}

def parse_id(m,body,location):
    body_id=body.get('id') if isinstance(body,dict) else None
    loc_id=None
    if location:
        need(isinstance(location,str) and len(location)<=1024,'V16_CREATE_LOCATION_UNSAFE')
        u=urllib.parse.urlsplit(location)
        need(not u.query and not u.fragment and not u.username and not u.password and
             ((not u.scheme and not u.netloc) or
              (u.scheme=='https' and u.netloc=='localhost:9444')) and
             u.path.startswith(BASE+'/') and u.path.count('/')==(BASE+'/').count('/'),
             'V16_CREATE_LOCATION_FOREIGN')
        loc_id=u.path.rsplit('/',1)[-1]
    for ident in (body_id,loc_id):
        if ident is not None:need(isinstance(ident,str) and bool(m.UUID.fullmatch(ident)),
                                 'V16_CREATE_RESPONSE_ID_INVALID')
    need(not (body_id and loc_id and body_id!=loc_id),'V16_CREATE_IDENTITIES_CONFLICT')
    return body_id or loc_id

def evidence(repo,private):
    v13=load(repo/'scripts/p2/partner_v13.py','v16_partner_v13')
    v15=load(repo/'scripts/p2/partner_business_plan_v15.py','v16_partner_v15')
    base=v15.inspect(repo,private)
    need(base.get('status')=='PENDING' and base.get('managementWrites')==0 and
         base.get('partnerFingerprint')==PARTNER_FP and
         base.get('businessAuthorizationVerified') is False,
         'V16_PRIOR_READ_ONLY_EVIDENCE_INVALID')
    v12=v13.import_v12(repo)
    m,_,_=v12.sources(repo)
    m.secure_dir(private)
    m.runtime_guard(repo,private)
    partner=m.read_json_private(private/v13.PARTNER_JOURNAL)
    need(partner.get('state')=='VERIFIED' and
         m.hash_id(partner.get('details',{}).get('organizationId',''))==PARTNER_FP and
         partner.get('details',{}).get('parentFingerprint')==ROOT_FP,
         'V16_PARTNER_JOURNAL_DRIFT')
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/'p2-local-wso2-tls-pinned.pem'))
    apps,matches=strict_app_inventory(m,http,admin)
    src_id,uri,path_fp=matching_aurora_web(m,http,admin,repo,apps)
    return m,http,admin,apps,matches,src_id,uri,path_fp

def journal_valid(m,record,uri,source_id):
    need(isinstance(record,dict) and record.get('schema')==SCHEMA and
         record.get('tenant')==TENANT and record.get('name')==NAME and
         record.get('state') in ('INTENT','VERIFIED') and
         record.get('partnerFingerprint')==PARTNER_FP and
         record.get('rootFingerprint')==ROOT_FP and
         record.get('callbackFingerprint')==fp(uri) and
         record.get('callbackPathFingerprint')==fp(urllib.parse.urlsplit(uri).path) and
         record.get('sourceApplicationId')==source_id and
         record.get('specFingerprint')==spec_fp(uri) and
         isinstance(record.get('baselineIds'),list) and
         len(record['baselineIds'])==len(set(record['baselineIds'])) and
         len(record['baselineIds'])<=MAX_APPS,
         'V16_JOURNAL_UNTRUSTED_OR_CHANGED')

def reconcile(m,http,admin,apps,matches,record,uri):
    baseline=set(record['baselineIds']);current={a['id'] for a in apps}
    if record['state']=='VERIFIED':
        app_id=record.get('applicationId')
        need(isinstance(app_id,str) and app_id not in baseline and
             baseline.issubset(current), 'V16_JOURNAL_BASELINE_CHECK')
        need(app_id in current and len(matches)==1 and matches[0]==app_id,
             'V16_VERIFIED_APP_NO_LONGER_UNIQUE')
        info=exact_readback(m,http,admin,app_id,uri)
        return report('VERIFIED','V16_PORTAL_ALREADY_REGISTERED_AND_REVERIFIED',
                      journalState='VERIFIED',**info)
    need(record['state']=='INTENT','V16_JOURNAL_STATE_INVALID')
    delta=current-baseline
    code='V16_CREATE_OUTCOME_UNRESOLVED_NO_RETRY'
    if baseline.issubset(current) and len(delta)==1 and len(matches)==1 and matches[0] in delta:
        try:
            exact_readback(m,http,admin,matches[0],uri)
            code='V16_EXACT_NEW_APP_OBSERVED_GET_ONLY_FINISH_AVAILABLE'
        except Exception:pass
    return report('RECONCILIATION_ONLY',code,journalState='INTENT',
                  observedSingleExactCandidate=(code.startswith('V16_EXACT_')))

def apply_once(m,http,admin,private,apps,uri,source_id,path_fp):
    baseline=sorted(a['id'] for a in apps)
    initial={'schema':SCHEMA,'state':'INTENT','tenant':TENANT,'name':NAME,
             'partnerFingerprint':PARTNER_FP,'rootFingerprint':ROOT_FP,
             'callbackFingerprint':fp(uri),'callbackPathFingerprint':path_fp,
             'sourceApplicationId':source_id,'specFingerprint':spec_fp(uri),
             'baselineIds':baseline,'managementWriteIntentCount':1}
    m.exclusive_json(private/JOURNAL,initial)  # Durable intent BEFORE POST.
    try:status,body,location=http.call('POST',BASE,basic=admin,data=spec_for(uri))
    except Exception:raise Stop('V16_CREATE_POST_OUTCOME_UNKNOWN_NO_RETRY')
    need(status==201,'V16_CREATE_HTTP_UNEXPECTED_NO_RETRY')
    response_id=parse_id(m,body,location)
    current,matches=strict_app_inventory(m,http,admin)
    delta={r['id'] for r in current}-set(baseline)
    need(set(baseline).issubset({r['id'] for r in current}) and len(delta)==1 and
         len(matches)==1 and matches[0] in delta and
         (response_id is None or response_id==matches[0]),
         'V16_CREATE_INVENTORY_DELTA_UNVERIFIED_NO_RETRY')
    proof=exact_readback(m,http,admin,matches[0],uri)
    m.replace_json(private/JOURNAL,{**initial,'state':'VERIFIED','applicationId':matches[0],
                                     'applicationFingerprint':proof['applicationFingerprint'],
                                     'sharingVerified':False,'businessAuthorizationVerified':False})
    return report('VERIFIED','V16_PORTAL_CREATED_ONCE_AND_READBACK_VERIFIED',
                  managementWrites=1,journalState='VERIFIED',**proof)

def main(args):
    command='ensure' if args==['ensure','--approve='+APPROVAL] else (
            'status' if args==['status'] else (
            'reconcile' if args==['reconcile'] else (
            'finish' if args==['finish','--readback-only'] else None)))
    need(command is not None,'V16_USE_STATUS_ENSURE_RECONCILE_FINISH')
    repo=Path.cwd().resolve()
    need((repo/'scripts/p2/partner_business_plan_v15.py').is_file() and
         (repo/'scripts/ciam-v10.sh').is_file(),'V16_RUN_FROM_REPOSITORY_ROOT')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or
                 str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    # Recheck all the V13–V15 read-only guards every supported bootstrap.
    with locked(private):
        m,http,admin,apps,matches,source_id,uri,path_fp=evidence(repo,private)
        jpath=private/JOURNAL
        if jpath.exists() or jpath.is_symlink():
            record=m.read_json_private(jpath)
            journal_valid(m,record,uri,source_id)
            result=reconcile(m,http,admin,apps,matches,record,uri)
            if (command=='finish' and record['state']=='INTENT' and
                result['code']=='V16_EXACT_NEW_APP_OBSERVED_GET_ONLY_FINISH_AVAILABLE'):
                app_id=matches[0]
                proof=exact_readback(m,http,admin,app_id,uri)
                m.replace_json(jpath,{**record,'state':'VERIFIED','applicationId':app_id,
                                      'applicationFingerprint':proof['applicationFingerprint'],
                                      'sharingVerified':False,'businessAuthorizationVerified':False,
                                      'reconciledBy':'GET_ONLY_V16_FINISH'})
                return report('VERIFIED','V16_GET_ONLY_FINALIZATION_COMPLETE',journalState='VERIFIED',**proof)
            if command=='ensure' and record['state']=='INTENT':
                raise Stop('V16_CREATE_INTENT_EXISTS_RECONCILE_NO_RETRY')
            return result
        need(not matches,'V16_UNOWNED_NAME_COLLISION_NO_ADOPTION')
        need(command!='finish','V16_NO_JOURNAL_TO_FINISH')
        if command in ('status','reconcile'):
            return report('PLAN_ONLY','V16_APPROVED_PORTAL_READY_FOR_ONE_CREATE',
                          journalState='ABSENT',callbackFingerprint=fp(uri),
                          callbackPathFingerprint=path_fp,
                          sourceAppFingerprint=fp(source_id),
                          existingApplicationsCount=len(apps))
        return apply_once(m,http,admin,private,apps,uri,source_id,path_fp)

if __name__=='__main__':
    try:
        res=main(sys.argv[1:])
        print(json.dumps(res,sort_keys=True,indent=2),flush=True)
    except Exception as e:
        print(json.dumps(report('BLOCKED',safe(e),
              managementWrites='UNKNOWN_CHECK_PRIVATE_JOURNAL',
              noAutomaticRetry=True),sort_keys=True,indent=2),flush=True)
        sys.exit(2)
