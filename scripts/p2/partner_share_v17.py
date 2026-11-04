#!/usr/bin/env python3
"""P2.24 V17: approved Aurora-only partner portal sharing, with no roles.

Only POST /t/aurora.identity.test/api/server/v1/applications/share with the
exact independently verified V16.3 application and V13 partner. An fsynced
private intent is recorded before the one asynchronous request. Later starts
never repeat that request; they only inspect two independent WSO2 GET views.
"""
from __future__ import annotations
import base64,hashlib,importlib.util,json,os,re,ssl,sys,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path

TENANT='aurora.identity.test'
SCHEMA='p2.24.aurora.partner-only-application-share.v17'
POLICY='SELECTED_ORG_ONLY'
ROLE_MODE='NONE'
APP_NAME='P2 Aurora Returns Partner Business Portal'
APP_FP='7b4495d1ff5af7fd'
PARTNER_FP='a9c40a10acabab52'
ROOT_FP='4548812d1a94a3ff'
CALLBACK_FP='3673f8ef2a1f66e1'
JOURNAL='p2-aurora-partner-only-share-v17.private.json'
SHARE_URL=f'/t/{TENANT}/api/server/v1/applications/share'
BASE=f'/t/{TENANT}/api/server/v1/applications'
MAX_MAPPINGS=1000

class Refuse(Exception):pass
def need(yes,code):
    if not yes:raise Refuse(code)
def fp(value):return hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]
def report(status,code,**extras):
    return {**dict(phase='P2.24',tenant=TENANT,status=status,code=code,
                   managementWritesAttempted=0,sharingVerified=False,
                   partnerLoginEnabled=False,rolesGranted=False,usersCreated=False,
                   businessAuthorizationVerified=False,delegatedAdministrationVerified=False),**extras}
def load(path,name):
    need(path.is_file() and not path.is_symlink(),'V17_DEPENDENCY_MISSING')
    spec=importlib.util.spec_from_file_location(name,path)
    need(spec is not None and spec.loader is not None,'V17_DEPENDENCY_INVALID')
    mod=importlib.util.module_from_spec(spec)
    try:spec.loader.exec_module(mod)
    except Exception:raise Refuse('V17_DEPENDENCY_IMPORT_FAILED')
    return mod

def body_for(app_id,partner_id):
    """No wildcard, future-child inheritance, admin role or extra organization."""
    return {'applicationId':app_id,'organizations':[
        {'orgId':partner_id,'policy':POLICY,'roleSharing':{'mode':ROLE_MODE}}
    ]}

def journal_template(app_id,partner_id,payload):
    return dict(schema=SCHEMA,state='INTENT',tenant=TENANT,
                applicationId=app_id,partnerId=partner_id,
                applicationFingerprint=APP_FP,partnerFingerprint=PARTNER_FP,
                rootFingerprint=ROOT_FP,callbackFingerprint=CALLBACK_FP,
                payloadFingerprint=fp(json.dumps(payload,sort_keys=True,separators=(',',':'))),
                policy=POLICY,roleMode=ROLE_MODE,
                managementWriteIntentCount=1,postAcknowledged=False)

def verify_journal(rec,template):
    need(type(rec) is dict and rec.get('state') in ('INTENT','VERIFIED') and
         all(rec.get(k)==v for k,v in template.items() if k not in ('state','postAcknowledged')) and
         type(rec.get('postAcknowledged')) is bool and
         (rec['state']=='INTENT' or rec['postAcknowledged'] is True),
         'V17_PRIVATE_JOURNAL_DRIFT')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

def post_once(cafile,admin,app_id,partner_id):
    """One HTTP POST with a hard-coded, tenant-pinned destination and body.

    This purpose-limited transport deliberately cannot POST application update,
    global sharing, app registration, or any other management endpoint.
    """
    need(type(admin) is tuple and len(admin)==2 and
         admin[0]==f'admin@{TENANT}' and isinstance(admin[1],str) and bool(admin[1]),
         'V17_TENANT_ADMIN_AUTHORITY_UNVERIFIED')
    need(bool(re.fullmatch(r'[0-9a-fA-F-]{36}',app_id)) and
         bool(re.fullmatch(r'[0-9a-fA-F-]{36}',partner_id)),
         'V17_REMOTE_ID_INVALID')
    ctx=ssl.create_default_context(cafile=str(cafile))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                           urllib.request.HTTPSHandler(context=ctx),NoRedirect())
    auth=base64.b64encode((admin[0]+':'+admin[1]).encode()).decode('ascii')
    payload=body_for(app_id,partner_id)
    request=urllib.request.Request('https://localhost:9444'+SHARE_URL,
            data=json.dumps(payload,sort_keys=True,separators=(',',':')).encode('utf-8'),
            headers={'Authorization':'Basic '+auth,'Accept':'application/json',
                     'Content-Type':'application/json'},method='POST')
    try:
        with opener.open(request,timeout=18) as response:
            status=response.status;raw=response.read(65537)
    except Exception:raise Refuse('V17_POST_OUTCOME_UNKNOWN_NO_RETRY')
    need(len(raw)<=65536,'V17_POST_RESPONSE_OVERSIZE_NO_RETRY')
    need(status==202,'V17_POST_NOT_ACCEPTED_OUTCOME_UNKNOWN_NO_RETRY')
    if raw.strip():
        try:ack=json.loads(raw)
        except (ValueError,UnicodeError):raise Refuse('V17_POST_ACK_UNPARSEABLE_NO_RETRY')
        need(type(ack) is dict and ack.get('status')=='Processing',
             'V17_POST_ACK_NOT_PROCESSING_NO_RETRY')
    return 202

def role_none(sharing):
    if not isinstance(sharing,dict):return False
    role=sharing.get('roleSharing')
    if isinstance(role,list):
        if len(role)!=1:return False
        role=role[0]
    return (isinstance(role,dict) and role.get('mode')==ROLE_MODE and
            (role.get('roles') in (None,[])))

def classify(shares,global_mode,mappings,app_id,partner_id,root_id):
    """Classify two COMPLETE readbacks; never infer empty from missing data."""
    need(shares is None or isinstance(shares,list),'V17_SHARE_ROWS_INVALID')
    need(mappings is None or isinstance(mappings,list),'V17_SHARED_APPS_ROWS_INVALID')
    if global_mode is not None:
        need(isinstance(global_mode,dict),'V17_GLOBAL_SHARING_MODE_INVALID')
        need(global_mode.get('policy')==POLICY,'V17_BROAD_GLOBAL_SHARING_BLOCKED')
        # With a selected root policy, no implicit role inheritance allowed.
        if 'roleSharing' in global_mode:
            need(role_none(global_mode),'V17_GLOBAL_ROLE_SHARING_UNVERIFIED')
    uncertain_roles=False
    if shares is not None:
        need(len(shares)<=MAX_MAPPINGS,'V17_SHARE_LIST_OVERSIZE')
        ids=set()
        for row in shares:
            need(type(row) is dict and isinstance(row.get('id'),str) and
                 row['id'] not in ids,'V17_SHARE_ROW_DUPLICATE_OR_INVALID')
            ids.add(row['id'])
            need(row['id']==partner_id,'V17_SHARE_WITH_OTHER_ORG_BLOCKED')
            need(row.get('parentId') in (None,root_id) and
                 row.get('status') in (None,'ACTIVE'), 'V17_PARTNER_SHARE_CONTEXT_CHANGED')
            mode=row.get('sharingMode')
            need(isinstance(mode,dict) and mode.get('policy')==POLICY,
                 'V17_SHARE_POLICY_NOT_EXACT')
            need(row.get('roles') in (None,[]), 'V17_SHARED_ROLES_PRESENT_BLOCKED')
            # Only missing/ambiguous role state is PENDING; an explicit non-NONE
            # role mode is a hard privilege-expansion violation.
            role=mode.get('roleSharing')
            role=role[0] if isinstance(role,list) and len(role)==1 else role
            if isinstance(role,dict) and role.get('mode') not in (None,ROLE_MODE):
                raise Refuse('V17_ROLE_SHARING_NOT_NONE_BLOCKED')
            if not role_none(mode):uncertain_roles=True
    if mappings is not None:
        need(len(mappings)<=MAX_MAPPINGS,'V17_SHARED_APPS_LIMIT_EXCEEDED')
        seen=set()
        for row in mappings:
            need(isinstance(row,dict) and isinstance(row.get('applicationId'),str) and
                 isinstance(row.get('organizationId'),str),
                 'V17_SHARED_APPS_ROW_INVALID')
            ident=(row['applicationId'],row['organizationId'])
            need(ident not in seen,'V17_SHARED_APPS_DUPLICATE')
            seen.add(ident)
            # Shared child app IDs can differ from the root application ID.
            need(row['organizationId']==partner_id,
                 'V17_SHARED_APP_OTHER_ORG_BLOCKED')
    if shares is None or mappings is None or uncertain_roles:return 'PENDING'
    if not shares and not mappings:return 'EMPTY'
    if len(shares)==1 and len(mappings)==1:return 'EXACT'
    return 'PENDING'

def snapshot(m,http,admin,v14,app_id,partner_id,root_id):
    """Reuses V14's thoroughly bounded share pagination and V15's second API."""
    need(bool(m.UUID.fullmatch(app_id)) and bool(m.UUID.fullmatch(partner_id)),
         'V17_APP_OR_ORG_UUID_INVALID')
    shares=None;global_mode=None
    try:shares,global_mode=v14.read_shares(m,http,admin,app_id)
    except Exception as e:
        # Omitted organizations must NEVER be treated as empty.
        if str(e) not in ('V14_SHARE_COLLECTION_OMITTED_UNVERIFIED',
                          'WSO2_GET_HTTP_401','WSO2_GET_HTTP_403'):
            raise
    mappings=None
    try:status,doc,_=http.call('GET',f'{BASE}/{app_id}/shared-apps',basic=admin)
    except Exception as e:
        if str(e) not in ('WSO2_GET_HTTP_401','WSO2_GET_HTTP_403'):
            raise
    else:
        need(status==200 and type(doc) is dict,'V17_SHARED_APPS_HTTP_OR_SHAPE_INVALID')
        rows=doc.get('sharedApplications')
        if rows is not None:
            need(type(rows) is list,'V17_SHARED_APPS_COLLECTION_INVALID')
            need(len(rows)<=MAX_MAPPINGS,'V17_SHARED_APPS_COLLECTION_OVERSIZE')
            ids=set()
            for row in rows:
                need(type(row) is dict and isinstance(row.get('applicationId'),str) and
                     bool(m.UUID.fullmatch(row['applicationId'])) and
                     isinstance(row.get('organizationId'),str) and
                     bool(m.UUID.fullmatch(row['organizationId'])),
                     'V17_SHARED_APPS_MAPPING_INVALID')
                pair=row['applicationId'],row['organizationId']
                need(pair not in ids,'V17_SHARED_APPS_MAPPING_DUPLICATE')
                ids.add(pair)
            mappings=rows
    return classify(shares,global_mode,mappings,app_id,partner_id,root_id)

def runtime(repo,private):
    """A complete V16.3 readback is mandatory before ANY sharing operation."""
    v163=load(repo/'scripts/p2/partner_portal_v16_3.py','v17_v163')
    checked=v163.main(['reconcile'],repo=repo,private=private)
    need(checked.get('status')=='VERIFIED' and
         checked.get('code')=='V16_3_PORTAL_ALREADY_REGISTERED_READBACK_ONLY' and
         checked.get('managementWrites')==0 and
         checked.get('applicationFingerprint')==APP_FP and
         checked.get('callbackFingerprint')==CALLBACK_FP and
         checked.get('sharingPerformed') is False,
         'V17_V16_3_PORTAL_READBACK_NOT_VERIFIED')
    v13=load(repo/'scripts/p2/partner_v13.py','v17_v13')
    v12=v13.import_v12(repo);m,_,_=v12.sources(repo)
    m.secure_dir(private);m.runtime_guard(repo,private)
    partner=m.read_json_private(private/v13.PARTNER_JOURNAL)
    need(partner.get('schema')==v13.SCHEMA and partner.get('state')=='VERIFIED',
         'V17_PARTNER_JOURNAL_NOT_VERIFIED')
    data=partner.get('details',{})
    partner_id,root_id=data.get('organizationId'),data.get('parentId')
    need(isinstance(partner_id,str) and isinstance(root_id,str) and
         bool(m.UUID.fullmatch(partner_id)) and bool(m.UUID.fullmatch(root_id)) and
         m.hash_id(partner_id)==PARTNER_FP and m.hash_id(root_id)==ROOT_FP and
         data.get('parentFingerprint')==ROOT_FP,
         'V17_AURORA_PARTNER_IDENTITY_DRIFT')
    v161=load(repo/'scripts/p2/partner_portal_v16_1.py','v17_v161')
    v16=v161.load_v16(repo)
    app_journal=m.read_json_private(private/v16.JOURNAL)
    need(app_journal.get('schema')==v163.SCHEMA and
         app_journal.get('state')=='VERIFIED' and
         app_journal.get('partnerFingerprint')==PARTNER_FP,
         'V17_PORTAL_OWNERSHIP_JOURNAL_DRIFT')
    app_id=app_journal.get('applicationId')
    need(isinstance(app_id,str) and bool(m.UUID.fullmatch(app_id)) and
         m.hash_id(app_id)==APP_FP,
         'V17_PORTAL_APP_IDENTITY_DRIFT')
    # V16.3 verifies exact OIDC settings, no API grants and the true BFF route.
    v14=load(repo/'scripts/p2/partner_access_v14.py','v17_v14')
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/'p2-local-wso2-tls-pinned.pem'))
    return v16,m,http,admin,v14,app_id,partner_id,root_id

def reconcile_snapshot(m,http,admin,v14,app_id,partner_id,root_id):
    # An incomplete GET does not establish either empty sharing or success.
    return snapshot(m,http,admin,v14,app_id,partner_id,root_id)

def apply_or_check(m,http,admin,v14,private,app_id,partner_id,root_id,command,submit=post_once,
                   sleeper=time.sleep):
    payload=body_for(app_id,partner_id)
    template=journal_template(app_id,partner_id,payload)
    file=private/JOURNAL
    if m.safe_private_file(file,required=False):
        rec=m.read_json_private(file)
        verify_journal(rec,template)
        observed=reconcile_snapshot(m,http,admin,v14,app_id,partner_id,root_id)
        if observed=='EXACT':
            if rec['state']=='INTENT':
                m.replace_json(file,{**rec,'state':'VERIFIED','postAcknowledged':True})
                return report('VERIFIED','V17_ASYNC_SHARE_FINISHED_GET_ONLY',
                              journalState='VERIFIED',sharingVerified=True)
            return report('VERIFIED','V17_PARTNER_ONLY_SHARE_REVERIFIED_NO_WRITES',
                          journalState='VERIFIED',sharingVerified=True)
        need(rec['state']!='VERIFIED','V17_VERIFIED_SHARE_REMOTE_DRIFT')
        need(observed in ('EMPTY','PENDING'),'V17_JOURNALED_SHARE_REMOTE_CONFLICT')
        return report('PENDING','V17_ASYNC_SHARE_PENDING_NO_POST_RETRY',
                      journalState='INTENT',nextAction='GET_ONLY_RECONCILIATION',
                      writeIntentPreviouslyRecorded=True)
    state=reconcile_snapshot(m,http,admin,v14,app_id,partner_id,root_id)
    need(state!='EXACT','V17_UNOWNED_EXISTING_APP_SHARING_BLOCKED')
    if state=='PENDING':
        return report('PENDING','V17_PREWRITE_SHARING_EVIDENCE_INCOMPLETE',
                      journalState='ABSENT',nextAction='VERIFY_GA_SHARING_READBACK_NO_WRITES')
    need(state=='EMPTY','V17_PREWRITE_SHARING_NOT_EMPTY')
    if command!='bootstrap':
        return report('PLAN_ONLY','V17_EXACT_PARTNER_SHARE_READY',
                      journalState='ABSENT',approvedPolicy=POLICY,
                      roleSharingMode=ROLE_MODE)
    m.exclusive_json(file,template) # Durable fsynced intent BEFORE only POST.
    try:submit(private/'p2-local-wso2-tls-pinned.pem',admin,app_id,partner_id)
    except Exception:
        # Since intent is durable, no automatic second POST is possible.
        raise Refuse('V17_POST_OUTCOME_UNCERTAIN_NEVER_RETRY')
    # The remote endpoint returns HTTP 202; it is NOT completion evidence.
    for i in range(4):
        observed=reconcile_snapshot(m,http,admin,v14,app_id,partner_id,root_id)
        if observed=='EXACT':
            m.replace_json(file,{**template,'state':'VERIFIED','postAcknowledged':True})
            return report('VERIFIED','V17_PARTNER_ONLY_SHARE_COMPLETED_AND_READBACK_VERIFIED',
                          journalState='VERIFIED',managementWritesAttempted=1,
                          sharingVerified=True,approvedPolicy=POLICY,roleSharingMode=ROLE_MODE)
        need(observed in ('EMPTY','PENDING'),'V17_ASYNC_SHARING_CONFLICT')
        if i<3:sleeper(0.6)
    return report('PENDING','V17_POST_ACCEPTED_ASYNC_READBACK_PENDING_NO_RETRY',
                  journalState='INTENT',managementWritesAttempted=1,
                  nextAction='GET_ONLY_RECONCILIATION')

def main(args,repo=None,private=None):
    need(args in (['bootstrap'],['status'],['reconcile']), 'V17_COMMAND_INVALID')
    repo=(repo or Path.cwd()).resolve(strict=True)
    need((repo/'scripts/ciam-v10.sh').is_file() and
         (repo/'scripts/p2/partner_portal_v16_3.py').is_file(),
         'V17_REPOSITORY_ROOT_INVALID')
    private=private or Path(os.environ.get('P2_PRIVATE_DIR') or
        str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    v16,m,http,admin,v14,app_id,partner_id,root_id=runtime(repo,private)
    with v16.locked(private):
        return apply_or_check(m,http,admin,v14,private,app_id,partner_id,root_id,args[0])

if __name__=='__main__':
    try:
        print(json.dumps(main(sys.argv[1:]),sort_keys=True,indent=2),flush=True)
    except Exception as e:
        code=str(e) if isinstance(e,Refuse) and re.fullmatch(r'V17_[A-Z0-9_]+',str(e)) else 'V17_BLOCKED_CHECK_PRIVATE_JOURNAL'
        print(json.dumps(report('BLOCKED',code,managementWritesAttempted='UNKNOWN_CHECK_PRIVATE_JOURNAL',
                               noAutomaticRetry=True),sort_keys=True,indent=2),flush=True)
        sys.exit(2)
