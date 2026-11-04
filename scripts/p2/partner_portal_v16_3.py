#!/usr/bin/env python3
"""V16.3 approved Aurora-only, one-time OIDC app registration with a distinct BFF callback.

V16 and V16.1 are retained untouched for recovery / audit; V16.3 replaces only
normal startup routing. A V16 legacy journal is a hard blocker; no migration.
No sharing, API scopes, users, roles, or secret rotation are authorized here.
"""
from __future__ import annotations
import hashlib,importlib.util,json,os,re,sys,urllib.parse
from pathlib import Path

TENANT='aurora.identity.test'
SCHEMA='p2.24.aurora.partner-portal.v16.3'
ROUTE='/auth/aurora-partner-web/callback'
LOGIN_ROUTE='/auth/aurora-partner-web/login'
NAME='P2 Aurora Returns Partner Business Portal'
APPROVAL='APPROVE_V16_AURORA_PARTNER_PORTAL_REGISTER_ONLY'
CLIENT_FILE='p2-aurora-partner-portal-client-v16-3.private.json'

class Halt(Exception):pass
def need(ok,code):
    if not ok:raise Halt(code)
def sha(x):return hashlib.sha256(x.encode('utf-8')).hexdigest()[:16]
def report(status,code,**kwargs):
    return {**dict(phase='P2.24',tenant=TENANT,status=status,code=code,
                managementWrites=0,sharingPerformed=False,rolesGranted=False,
                usersCreated=False,businessAuthorizationVerified=False,
                delegatedAdministrationVerified=False),**kwargs}
def dynamic_load(path,name):
    need(path.is_file() and not path.is_symlink(),'V16_3_DEPENDENCY_MISSING')
    spec=importlib.util.spec_from_file_location(name,path)
    need(spec and spec.loader,'V16_3_DEPENDENCY_INVALID')
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def route_proof(repo):
    """Proof is the new explicit path in a separately tested handler and installed dispatch.

    This static proof is only one prerequisite; BFF tests check actual behavior,
    and WSO2 GET still checks exact persisted callback before completion.
    """
    server=repo/'services/identity-bff/src/server.js'
    handler=repo/'services/identity-bff/src/partner-portal-route.js'
    for path in (server,handler):
        need(path.is_file() and not path.is_symlink(),'V16_3_BFF_ROUTE_SOURCE_MISSING')
        need(path.stat().st_size<100_000,'V16_3_BFF_ROUTE_SOURCE_OVERSIZE')
    src=server.read_text();h=handler.read_text()
    need(src.count("from './partner-portal-route.js'")==1 and
         src.count('await handlePartnerPortalAuth(')==1 and
         h.count("'/auth/aurora-partner-web/callback'")>=1 and
         h.count("'/auth/aurora-partner-web/login'")>=1 and
         'readAuthorizationResponse' in h and 'verifyIdToken' in h and
         'exchangeAuthorizationCode' in h and 'inspectAccessToken' in h,
         'V16_3_CALLBACK_ROUTE_UNPROVEN')
    return sha(ROUTE)

def derive_callback(v16,source_uri):
    origin=v16.secure_callback(source_uri)
    u=urllib.parse.urlsplit(origin)
    need(u.path in ('/auth/aurora-web/callback',),
         'V16_3_EXISTING_SOURCE_CALLBACK_WRONG_CHANNEL')
    out=urllib.parse.urlunsplit((u.scheme,u.netloc,ROUTE,'',''))
    v16.secure_callback(out)
    need(out!=source_uri,'V16_3_CALLBACK_MUST_BE_DISTINCT')
    return out

def context(repo,private,v16,v161):
    # V15 probes real WSO2 data but only returns read-only PENDING evidence.
    v15=dynamic_load(repo/'scripts/p2/partner_business_plan_v15.py','v163_v15')
    proof=v15.inspect(repo,private)
    need(proof.get('status')=='PENDING' and proof.get('managementWrites')==0 and
         proof.get('partnerFingerprint')==v16.PARTNER_FP and
         proof.get('businessAuthorizationVerified') is False,
         'V16_3_V15_PARTNER_EVIDENCE_NOT_VERIFIED')
    v13=dynamic_load(repo/'scripts/p2/partner_v13.py','v163_v13')
    v12=v13.import_v12(repo)
    m,_,_=v12.sources(repo)
    m.secure_dir(private);m.runtime_guard(repo,private)
    partner=m.read_json_private(private/v13.PARTNER_JOURNAL)
    need(partner.get('state')=='VERIFIED' and
         m.hash_id(partner.get('details',{}).get('organizationId',''))==v16.PARTNER_FP and
         partner.get('details',{}).get('parentFingerprint')==v16.ROOT_FP,
         'V16_3_PARTNER_JOURNAL_DRIFT')
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/'p2-local-wso2-tls-pinned.pem'))
    apps,names=v16.strict_app_inventory(m,http,admin)
    # Independent source of the established Aurora Web origin. This method
    # confirms exactly one registered source client, without guessing its URI.
    (source_id,source_uri),_=v161.existing_callback_info(repo,private,v16)
    callback=derive_callback(v16,source_uri)
    route_fp=route_proof(repo)
    need(route_fp==sha(urllib.parse.urlsplit(callback).path),
         'V16_3_CALLBACK_ROUTE_MISMATCH')
    return m,http,admin,apps,names,source_id,callback,route_fp

def journal_spec(v16,callback):
    return sha(json.dumps(v16.spec_for(callback),sort_keys=True,separators=(',',':')))

def verify_journal(v16,m,rec,callback,source_id):
    need(type(rec) is dict and rec.get('schema')==SCHEMA and
         rec.get('tenant')==TENANT and rec.get('name')==NAME and
         rec.get('state') in ('INTENT','VERIFIED') and
         rec.get('partnerFingerprint')==v16.PARTNER_FP and
         rec.get('rootFingerprint')==v16.ROOT_FP and
         rec.get('sourceApplicationId')==source_id and
         rec.get('callbackFingerprint')==sha(callback) and
         rec.get('callbackPathFingerprint')==sha(ROUTE) and
         rec.get('specFingerprint')==journal_spec(v16,callback) and
         isinstance(rec.get('baselineIds'),list) and
         len(rec['baselineIds'])==len(set(rec['baselineIds'])) and
         len(rec['baselineIds'])<=v16.MAX_APPS and
         all(isinstance(x,str) and bool(m.UUID.fullmatch(x)) for x in rec['baselineIds']),
         'V16_3_JOURNAL_OR_APPROVAL_DRIFT')

def exact(v16,m,http,admin,app_id,callback):
    # Reuse the verified V16 readback gates; no additional management writes.
    return v16.exact_readback(m,http,admin,app_id,callback)

def find_verified(v16,m,http,admin,apps,matches,rec,callback):
    baseline=set(rec['baselineIds'])
    ids={a['id'] for a in apps}
    if rec['state']=='VERIFIED':
        app_id=rec.get('applicationId')
        need(isinstance(app_id,str) and bool(m.UUID.fullmatch(app_id)) and
             app_id not in baseline and baseline.issubset(ids) and
             app_id in ids and matches==[app_id],
             'V16_3_VERIFIED_REMOTE_APP_DRIFT')
        details=exact(v16,m,http,admin,app_id,callback)
        return report('VERIFIED','V16_3_PORTAL_ALREADY_REGISTERED_READBACK_ONLY',
                      journalState='VERIFIED',partnerLoginEnabled=False,**details)
    delta=ids-baseline
    possible=baseline.issubset(ids) and len(delta)==1 and len(matches)==1 and matches[0] in delta
    if possible:
        try:
            details=exact(v16,m,http,admin,matches[0],callback)
            return report('RECONCILIATION_ONLY','V16_3_EXACT_REMOTE_CREATE_READBACK_FINISH_AVAILABLE',
                          journalState='INTENT',candidateFingerprint=details['applicationFingerprint'])
        except Exception:pass
    return report('RECONCILIATION_ONLY','V16_3_CREATE_OUTCOME_UNKNOWN_NEVER_RETRY',journalState='INTENT')

def create_once(v16,m,http,admin,private,apps,source_id,callback):
    baseline=sorted(a['id'] for a in apps)
    record={'schema':SCHEMA,'state':'INTENT','tenant':TENANT,'name':NAME,
            'partnerFingerprint':v16.PARTNER_FP,'rootFingerprint':v16.ROOT_FP,
            'callbackFingerprint':sha(callback),'callbackPathFingerprint':sha(ROUTE),
            'sourceApplicationId':source_id,'specFingerprint':journal_spec(v16,callback),
            'baselineIds':baseline,'managementWriteIntentCount':1,
            'sharingVerified':False,'businessAuthorizationVerified':False}
    m.exclusive_json(private/v16.JOURNAL,record)   # Durable fsynced intent BEFORE POST.
    try:code,body,location=http.call('POST',v16.BASE,basic=admin,data=v16.spec_for(callback))
    except Exception:raise Halt('V16_3_POST_OUTCOME_UNKNOWN_NO_RETRY')
    need(code==201,'V16_3_CREATE_HTTP_UNEXPECTED_NO_RETRY')
    response_id=v16.parse_id(m,body,location)
    current,matches=v16.strict_app_inventory(m,http,admin)
    delta={a['id'] for a in current}-set(baseline)
    need(set(baseline).issubset({a['id'] for a in current}) and len(delta)==1 and
         len(matches)==1 and matches[0] in delta and
         (response_id is None or response_id==matches[0]),
         'V16_3_POST_REMOTE_INVENTORY_UNCERTAIN_NO_RETRY')
    details=exact(v16,m,http,admin,matches[0],callback)
    m.replace_json(private/v16.JOURNAL,{**record,'state':'VERIFIED',
             'applicationId':matches[0],'applicationFingerprint':details['applicationFingerprint']})
    return report('VERIFIED','V16_3_PORTAL_CREATED_ONCE_AND_READBACK_VERIFIED',
                  managementWrites=1,journalState='VERIFIED',
                  partnerLoginEnabled=False,**details)

def main(args,repo=None,private=None):
    commands={('bootstrap',):'bootstrap',('status',):'status',
              ('reconcile',):'reconcile',('finish','--readback-only'):'finish'}
    need(tuple(args) in commands,'V16_3_COMMAND_INVALID')
    command=commands[tuple(args)]
    repo=(repo or Path.cwd()).resolve()
    need((repo/'scripts/ciam-v10.sh').is_file() and
         (repo/'scripts/p2/partner_portal_v16_1.py').is_file(),
         'V16_3_REPOSITORY_ROOT_MISSING')
    private=private or Path(os.environ.get('P2_PRIVATE_DIR') or
               str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    v161=dynamic_load(repo/'scripts/p2/partner_portal_v16_1.py','v163_v161')
    v16=v161.load_v16(repo)  # Maintains V16.1 exact original V16 digest pin.
    with v16.locked(private):
        m,http,admin,apps,matches,source_id,callback,path_fp=context(repo,private,v16,v161)
        journal=private/v16.JOURNAL
        if journal.exists() or journal.is_symlink():
            rec=m.read_json_private(journal)
            verify_journal(v16,m,rec,callback,source_id)
            result=find_verified(v16,m,http,admin,apps,matches,rec,callback)
            if rec['state']=='INTENT':
                if command=='bootstrap':raise Halt('V16_3_CREATE_INTENT_BLOCKS_AUTOMATIC_RETRY')
                if command=='finish' and result['code']=='V16_3_EXACT_REMOTE_CREATE_READBACK_FINISH_AVAILABLE':
                    app_id=matches[0]
                    details=exact(v16,m,http,admin,app_id,callback)
                    m.replace_json(journal,{**rec,'state':'VERIFIED','applicationId':app_id,
                          'applicationFingerprint':details['applicationFingerprint']})
                    return report('VERIFIED','V16_3_GET_ONLY_FINALIZATION_COMPLETE',
                                  journalState='VERIFIED',partnerLoginEnabled=False,**details)
                return result
            need(command!='finish','V16_3_NO_INTENT_TO_FINALIZE')
            return result
        need(command!='finish','V16_3_NO_JOURNAL_TO_FINALIZE')
        need(not matches,'V16_3_UNOWNED_APP_NAME_COLLISION')
        if command in ('status','reconcile'):
            return report('PLAN_ONLY','V16_3_APPROVED_DISTINCT_CALLBACK_READY',
                          journalState='ABSENT',callbackFingerprint=sha(callback),
                          callbackPathFingerprint=path_fp,applicationCount=len(apps),
                          partnerLoginEnabled=False)
        return create_once(v16,m,http,admin,private,apps,source_id,callback)

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),sort_keys=True,indent=2))
    except Exception as exc:
        code=str(exc) if isinstance(exc,Halt) or re.fullmatch(r'V16_[A-Z0-9_]+',str(exc)) else 'V16_3_BLOCKED_CHECK_PRIVATE_JOURNAL'
        print(json.dumps(report('BLOCKED',code,managementWrites='UNKNOWN_CHECK_PRIVATE_JOURNAL',
                               noAutomaticRetry=True),sort_keys=True,indent=2))
        sys.exit(2)
