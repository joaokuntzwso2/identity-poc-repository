#!/usr/bin/env python3
"""P2.24 V18: once-only ordinary partner directory seed, conditioned on verified sharing.

No migration, no role/permission grant, no privileged group, no person/email invention.
Root/Brisa/Carbon endpoints are never used for SCIM. No retry after a write intent.
An independently authorized, partner-bound SCIM M2M is required before any mutation.
"""
from __future__ import annotations
import base64,contextlib,hashlib,importlib.util,json,os,re,secrets,ssl,stat,sys,urllib.error,urllib.parse,urllib.request
from pathlib import Path

TENANT='aurora.identity.test'
BASE='https://localhost:9444'
ACTOR_FILE='p2-aurora-partner-directory-actor.private.json'
V17_JOURNAL='p2-aurora-partner-only-share-v17.private.json'
V17_SHA='fea42472a4a91d4d04c368131ae4e569b5dc1aa8ce8eb5fe8040ccee344f6a53'
ROOT_FP='4548812d1a94a3ff'
PARTNER_FP='a9c40a10acabab52'
APP_FP='7b4495d1ff5af7fd'
SCHEMA='p2.24.aurora.partner-directory.v18'
ACTOR_SCHEMA='p2.24.aurora.partner-directory-actor.v18'
# V18_ORGANIZATION_SCOPE_CONTRACT_V36: GA's organization Groups view scope covers GET/list.
USER_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:User'
GROUP_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:Group'
SCOPES=tuple(sorted((
  'internal_org_user_mgt_list','internal_org_user_mgt_view','internal_org_user_mgt_create',
  'internal_org_group_mgt_view','internal_org_group_mgt_create')))
MEMBERS=(('p2-aurora-returns-operator','ReturnsOperator','AuroraReturnsOperators'),
         ('p2-aurora-returns-reviewer','ReturnsReviewer','AuroraReturnsReviewers'))
UUID=re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')
MAX=1000
class Stop(Exception):pass
def need(ok,code):
    if not ok:raise Stop(code)
def fingerprint(value):return hashlib.sha256(value.encode()).hexdigest()[:16]
def report(status,code,**extra):
    result=dict(phase='P2.24',tenant=TENANT,status=status,code=code,
                managementWritesAttempted=0,partnerLoginEnabled=False,
                delegatedAdministrationVerified=False,businessAuthorizationVerified=False,
                rolesGranted=False,partnerDirectoryVerified=False)
    result.update(extra)
    return result
def load_v17(repo):
    path=repo/'scripts/p2/partner_share_v17.py'
    need(path.is_file() and not path.is_symlink() and
         hashlib.sha256(path.read_bytes()).hexdigest()==V17_SHA,'V18_V17_SOURCE_PIN_DRIFT')
    spec=importlib.util.spec_from_file_location('v18_pinned_v17',path)
    need(spec is not None and spec.loader is not None,'V18_SOURCE_LOAD_INVALID')
    mod=importlib.util.module_from_spec(spec)
    try:spec.loader.exec_module(mod)
    except Exception:raise Stop('V18_SOURCE_LOAD_FAILED') from None
    return mod

def private_read(m,path):
    need(m.safe_private_file(path,required=False),'V18_PRIVATE_ACTOR_FILE_INVALID')
    return m.read_json_private(path)

def actor_check(m,http,admin,record,partner):
    need(type(record) is dict and record.get('schema')==ACTOR_SCHEMA and
         record.get('tenant')==TENANT and record.get('partnerId')==partner and
         record.get('partnerFingerprint')==PARTNER_FP and
         record.get('rootFingerprint')==ROOT_FP and
         type(record.get('authorizedScopes')) is list and
         sorted(record['authorizedScopes'])==list(SCOPES) and
         record.get('grantTypes')==['client_credentials'] and
         type(record.get('clientId')) is str and 4<=len(record['clientId'])<=512 and
         type(record.get('clientSecret')) is str and 8<=len(record['clientSecret'])<=4096 and
         type(record.get('applicationId')) is str and UUID.fullmatch(record['applicationId']),
         'V18_ACTOR_SPEC_INVALID')
    app=record['applicationId'];prefix=f'/t/{TENANT}/api/server/v1/applications'
    code,detail,_=http.call('GET',f'{prefix}/{app}',basic=admin)
    need(code==200 and type(detail) is dict and detail.get('id')==app and
         detail.get('isManagementApp') is True and
         detail.get('name')=='P2 Aurora Returns Partner Directory M2M' and
         detail.get('applicationEnabled') is not False,
         'V18_ACTOR_APPLICATION_NOT_VERIFIED')
    code,oidc,_=http.call('GET',f'{prefix}/{app}/inbound-protocols/oidc',basic=admin)
    need(code==200 and type(oidc) is dict and
         oidc.get('grantTypes')==['client_credentials'] and
         oidc.get('publicClient') is False and oidc.get('clientId')==record['clientId'],
         'V18_ACTOR_OAUTH_NOT_VERIFIED')
    code,authz,_=http.call('GET',f'{prefix}/{app}/authorized-apis',basic=admin)
    need(code==200 and type(authz) is list and len(authz)==2,
         'V18_ACTOR_SCIM_AUTHORIZATION_UNVERIFIED')
    groups={};allscopes=[]
    for a in authz:
        need(type(a) is dict and type(a.get('id')) is str and UUID.fullmatch(a['id']) and
             a.get('policyId',a.get('policyIdentifier'))=='RBAC' and
             type(a.get('authorizedScopes')) is list,
             'V18_ACTOR_POLICY_INVALID')
        names=[]
        for scope in a['authorizedScopes']:
            need(type(scope) is dict and type(scope.get('name')) is str,
                 'V18_ACTOR_SCOPE_SHAPE_INVALID')
            names.append(scope['name'])
        need(len(names) in (2,3) and len(set(names))==len(names) and a['id'] not in groups,
             'V18_ACTOR_SCOPE_RESOURCE_AMBIGUOUS')
        groups[a['id']]=names;allscopes+=names
    expected_users={s for s in SCOPES if s.startswith('internal_org_user_mgt_')}
    expected_groups={s for s in SCOPES if s.startswith('internal_org_group_mgt_')}
    need(sorted(allscopes)==list(SCOPES) and len(set(allscopes))==len(SCOPES) and
         {frozenset(x) for x in groups.values()}==
         {frozenset(expected_users),frozenset(expected_groups)},
         'V18_ACTOR_EXCESS_OR_MISSING_PERMISSION')
    return record['clientId'],record['clientSecret']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

class Scim:
    def __init__(self,cafile,partner,token,opener=None):
        need(UUID.fullmatch(partner) and type(token) is str and 25<=len(token)<=8192 and
             not any(x.isspace() for x in token),'V18_SCIM_AUTH_INVALID')
        self.partner=partner;self.token=token
        if opener is None:
            ctx=ssl.create_default_context(cafile=str(cafile))
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                 urllib.request.HTTPSHandler(context=ctx),NoRedirect())
        self.opener=opener
    def request(self,method,resource,body=None):
        need(method in ('GET','POST') and type(resource) is str and
             (resource.startswith('Users') or resource.startswith('Groups')) and
             not any(c in resource for c in ('..','\\','#','//','\n','\r',';')) and
             (resource in ('Users','Groups') or
              re.fullmatch(r'(?:Users|Groups)/[0-9a-fA-F-]{36}',resource) or
              re.fullmatch(r'(?:Users|Groups)\?startIndex=[0-9]{1,5}&count=[0-9]{1,3}',resource)),
             'V18_SCIM_ENDPOINT_INVALID')
        need((method=='GET')==(body is None) and
             (method=='GET' or resource in ('Users','Groups')),
             'V18_SCIM_WRITE_BOUNDARY_INVALID')
        raw=json.dumps(body,separators=(',',':')).encode() if body is not None else None
        req=urllib.request.Request(f'{BASE}/t/{TENANT}/o/scim2/{resource}',data=raw,method=method,
             headers={'Authorization':'Bearer '+self.token,'Accept':'application/scim+json',
                      'Content-Type':'application/scim+json'})
        try:
            with self.opener.open(req,timeout=16) as response:
                status=response.status;payload=response.read(65537)
        except urllib.error.HTTPError as ex:
            # A POST could have reached WSO2 even with HTTP 4xx/5xx.
            raise Stop('V18_SCIM_POST_OUTCOME_UNCERTAIN_NO_RETRY' if method=='POST'
                       else 'V18_SCIM_GET_HTTP_UNVERIFIED') from None
        except Exception:
            raise Stop('V18_SCIM_POST_OUTCOME_UNCERTAIN_NO_RETRY' if method=='POST'
                       else 'V18_SCIM_GET_UNAVAILABLE') from None
        need(len(payload)<=65536,'V18_SCIM_RESPONSE_OVERSIZE')
        try:result=json.loads(payload) if payload else {}
        except Exception:raise Stop('V18_SCIM_RESPONSE_NOT_JSON') from None
        need(type(result) is dict,'V18_SCIM_RESPONSE_NOT_OBJECT')
        return status,result

def actor_token(cafile,partner,client,secret,opener=None):
    need(UUID.fullmatch(partner),'V18_PARTNER_INVALID')
    if opener is None:
        context=ssl.create_default_context(cafile=str(cafile))
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
             urllib.request.HTTPSHandler(context=context),NoRedirect())
    basic=base64.b64encode((client+':'+secret).encode()).decode()
    body=urllib.parse.urlencode({'grant_type':'client_credentials','scope':' '.join(SCOPES)}).encode()
    req=urllib.request.Request(f'{BASE}/t/{TENANT}/o/{partner}/oauth2/token',data=body,
           headers={'Authorization':'Basic '+basic,
                    'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},
           method='POST')
    try:
        with opener.open(req,timeout=16) as response:
            need(response.status==200,'V18_OAUTH_NOT_200')
            raw=response.read(65537)
    except Exception:raise Stop('V18_OAUTH_UNAVAILABLE_OR_UNAUTHORIZED') from None
    need(len(raw)<=65536,'V18_OAUTH_RESPONSE_OVERSIZE')
    try:token=json.loads(raw)
    except Exception:raise Stop('V18_OAUTH_RESPONSE_INVALID') from None
    need(type(token) is dict and str(token.get('token_type','')).lower()=='bearer' and
         type(token.get('scope')) is str and sorted(token['scope'].split())==list(SCOPES) and
         type(token.get('access_token')) is str,
         'V18_OAUTH_ISSUED_SCOPE_MISMATCH')
    access=token['access_token']
    need(len(access)>=25 and not any(x.isspace() for x in access),
         'V18_OAUTH_ACCESS_INVALID')
    # This is a direct response over the already pinned WSO2 TLS channel. The
    # scope and org claims are still checked before any SCIM operation.
    sections=access.split('.')
    need(len(sections)==3,'V18_ORGANIZATION_TOKEN_CLAIMS_UNAVAILABLE')
    try:
        payload=json.loads(base64.urlsafe_b64decode(sections[1]+'='*(-len(sections[1])%4)))
    except Exception:raise Stop('V18_ORGANIZATION_TOKEN_CLAIMS_INVALID') from None
    need(type(payload) is dict and payload.get('org_id')==partner and
         sorted(str(payload.get('scope','')).split())==list(SCOPES) and
         payload.get('iss') and TENANT in str(payload.get('iss')),
         'V18_ISSUED_TOKEN_NOT_PARTNER_BOUND')
    return access

def full_list(scim,resource):
    out=[];seen=set();idx=1;total=None
    for _ in range(20):
        status,doc=scim.request('GET',f'{resource}?startIndex={idx}&count=100')
        need(status==200 and type(doc.get('totalResults')) is int and
             0<=doc['totalResults']<=MAX,'V18_SCIM_TOTAL_UNVERIFIED')
        count=doc['totalResults']
        if total is None:total=count
        need(count==total,'V18_SCIM_COUNT_CHANGED')
        rows=doc.get('Resources',[] if count==0 else None)
        need(type(rows) is list and len(rows)<=100,'V18_SCIM_ROWS_INCOMPLETE')
        for row in rows:
            need(type(row) is dict and type(row.get('id')) is str and
                 UUID.fullmatch(row['id']) and row['id'] not in seen,
                 'V18_SCIM_ROWS_AMBIGUOUS')
            seen.add(row['id']);out.append(row)
        if len(out)==total:return out
        need(rows and idx+len(rows)<=total,'V18_SCIM_PAGINATION_INCOMPLETE')
        idx+=len(rows)
    raise Stop('V18_SCIM_TOO_MANY_PAGES')

def match_exact(rows,attr,value):
    matches=[r for r in rows if r.get(attr)==value]
    need(len(matches)<=1,'V18_SCIM_DUPLICATE_TARGET')
    return matches[0] if matches else None

def journal_record(kind,name,partner,**kw):
    return dict(schema=SCHEMA,tenant=TENANT,kind=kind,name=name,partnerId=partner,
                partnerFingerprint=PARTNER_FP,rootFingerprint=ROOT_FP,
                state='INTENT',**kw)

def journal_check(m,file,expected):
    if not m.safe_private_file(file,required=False):return None
    rec=m.read_json_private(file)
    need(type(rec) is dict and rec.get('state') in ('INTENT','VERIFIED') and
         all(rec.get(k)==v for k,v in expected.items() if k!='state'),
         'V18_DIRECTORY_JOURNAL_DRIFT')
    return rec

def seed_one(m,scim,private,kind,name,partner,member=None):
    """At-most-once POST per name, with exclusive 0600 private journal."""
    resource='Users' if kind=='USER' else 'Groups'
    existing=match_exact(full_list(scim,resource),'userName' if kind=='USER' else 'displayName',name)
    safe_name=re.sub('[^a-zA-Z0-9_-]','_',name)
    file=private/f'p2-aurora-partner-directory-v18-{kind.lower()}-{safe_name}.private.json'
    expected=journal_record(kind,name,partner)
    journal=journal_check(m,file,expected)
    if journal is not None:
        need(journal.get('resourceId') is None or
             (type(journal['resourceId']) is str and UUID.fullmatch(journal['resourceId'])),
             'V18_JOURNAL_RESOURCE_ID_INVALID')
        if (existing is not None and journal.get('resourceId')==existing['id'] and
                journal['state']=='VERIFIED'):
            if kind=='USER':
                need(existing.get('active') is False and not existing.get('roles'),
                     'V18_EXISTING_USER_PRIVILEGE_DRIFT')
            else:
                members=existing.get('members')
                need(type(members) is list and len(members)==1 and
                     members[0].get('value')==member and journal.get('memberId')==member,
                     'V18_EXISTING_GROUP_MEMBERSHIP_DRIFT')
            return existing['id'],False
        if existing is not None and journal['state']=='INTENT':
            # No adoption without separately examining the attempted POST.
            raise Stop('V18_UNCERTAIN_WRITE_READBACK_ONLY_NO_RETRY')
        raise Stop('V18_JOURNAL_REMOTE_DRIFT_OR_PENDING_NO_RETRY')
    need(existing is None,'V18_UNOWNED_EXISTING_DIRECTORY_OBJECT')
    if kind=='USER':
        password=secrets.token_urlsafe(42)
        payload={'schemas':[USER_SCHEMA],'userName':name,
                 'name':{'givenName':'Aurora','familyName':'ReturnsSeed'},
                 'active':False,'password':password}
        # Store the initial credential privately before sending a mutation.
        journal={**expected,'initialPassword':password}
    else:
        need(type(member) is str and UUID.fullmatch(member),'V18_GROUP_MEMBER_UNVERIFIED')
        payload={'schemas':[GROUP_SCHEMA],'displayName':name,
                 'members':[{'value':member}]}
        journal={**expected,'memberId':member}
    m.exclusive_json(file,journal)
    try:code,created=scim.request('POST',resource,payload)
    except Exception:raise Stop('V18_POST_OUTCOME_UNCERTAIN_NO_RETRY') from None
    need(code==201 and type(created.get('id')) is str and UUID.fullmatch(created['id']),
         'V18_CREATE_RESPONSE_UNVERIFIED_NO_RETRY')
    code,detail=scim.request('GET',f'{resource}/{created["id"]}')
    need(code==200 and detail.get('id')==created['id'] and
         detail.get('userName' if kind=='USER' else 'displayName')==name,
         'V18_CREATED_READBACK_MISMATCH_NO_RETRY')
    if kind=='USER':
        need(detail.get('active') is False and not detail.get('roles'),
             'V18_USER_MUST_REMAIN_DISABLED_AND_UNPRIVILEGED')
    else:
        members=detail.get('members',[])
        need(type(members) is list and len(members)==1 and
             members[0].get('value')==member,'V18_GROUP_MEMBERSHIP_NOT_EXACT')
    m.replace_json(file,{**journal,'state':'VERIFIED','resourceId':created['id']})
    return created['id'],True

def bootstrap_directory(v17,m,http,admin,v14,private,app,partner,root,*,scim_factory=None,oauth_factory=actor_token):
    journal=private/V17_JOURNAL
    need(m.safe_private_file(journal,required=False),'V18_V17_VERIFIED_SHARING_REQUIRED')
    j=m.read_json_private(journal)
    v17.verify_journal(j,v17.journal_template(app,partner,v17.body_for(app,partner)))
    snapshot=v17.reconcile_snapshot(m,http,admin,v14,app,partner,root)
    if j['state']!='VERIFIED' or snapshot!='EXACT':
        return report('PENDING','V18_SHARING_NOT_VERIFIED_DIRECTORY_WRITES_DISABLED',
                      sharingJournalState=j['state'],sharingEvidence=snapshot,
                      nextAction='RESOLVE_V17_WITHOUT_POST_RETRY')
    actor=private/ACTOR_FILE
    if not m.safe_private_file(actor,required=False):
        return report('PENDING','V18_PARTNER_SCOPED_SCIM_ACTOR_REQUIRED',
                      sharingVerified=True,
                      requiredScopes=list(SCOPES),
                      nextAction='PROVISION_INDEPENDENT_PARTNER_DIRECTORY_ACTOR')
    client,secret=actor_check(m,http,admin,private_read(m,actor),partner)
    cafile=private/'p2-local-wso2-tls-pinned.pem'
    token=oauth_factory(cafile,partner,client,secret)
    scim=(scim_factory or Scim)(cafile,partner,token)
    created=0;accounts=[]
    for username,family,group in MEMBERS:
        user,changed=seed_one(m,scim,private,'USER',username,partner);created+=int(changed)
        # The created accounts are intentionally disabled and have no roles.
        grp,changed=seed_one(m,scim,private,'GROUP',group,partner,user);created+=int(changed)
        accounts.append((user,grp))
    return report('VERIFIED','V18_PARTNER_DIRECTORY_OBJECTS_VERIFIED',
                  partnerDirectoryVerified=True,sharingVerified=True,
                  disabledSeedUsers=2,memberGroups=2,managementWritesAttempted=created,
                  noAdministratorRolesGranted=True,
                  noPartnerLoginActivation=True)

def run(command,repo,private):
    need(command in ('status','bootstrap','reconcile'),'V18_COMMAND_INVALID')
    v17=load_v17(repo)
    v16,m,http,admin,v14,app,partner,root=v17.runtime(repo,private)
    with v16.locked(private):
        j=private/V17_JOURNAL
        need(m.safe_private_file(j,required=False),'V18_V17_JOURNAL_MISSING')
        prior=m.read_json_private(j)
        v17.verify_journal(prior,v17.journal_template(app,partner,v17.body_for(app,partner)))
        state=v17.reconcile_snapshot(m,http,admin,v14,app,partner,root)
        if prior['state']!='VERIFIED' or state!='EXACT':
            return report('PENDING','V18_SHARING_NOT_VERIFIED_DIRECTORY_WRITES_DISABLED',
                          sharingJournalState=prior['state'],sharingEvidence=state,
                          nextAction='RESOLVE_V17_WITHOUT_POST_RETRY')
        if command!='bootstrap':
            return report('PLAN_ONLY','V18_PARTNER_SCIM_ACTOR_AND_DIRECTORY_READBACK_PENDING',
                          sharingVerified=True,requiredScopes=list(SCOPES))
        return bootstrap_directory(v17,m,http,admin,v14,private,app,partner,root)

def main(argv):
    need(argv in (['status'],['bootstrap'],['reconcile']),'V18_COMMAND_INVALID')
    repo=Path.cwd().resolve(strict=True)
    need((repo/'scripts/ciam-v10.sh').is_file(),'V18_REPOSITORY_ROOT_INVALID')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or
                 str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    need(private.is_dir() and not private.is_symlink(),'V18_PRIVATE_DIRECTORY_UNSAFE')
    return run(argv[0],repo,private)

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),sort_keys=True,indent=2),flush=True)
    except Exception as e:
        print(json.dumps(report('BLOCKED',str(e) if type(e) is Stop and
             re.fullmatch(r'V18_[A-Z0-9_]+',str(e)) else 'V18_FAILURE_CHECK_PRIVATE_JOURNAL',
             managementWritesAttempted='UNKNOWN_CHECK_PRIVATE_JOURNAL'),
             sort_keys=True,indent=2),flush=True)
        sys.exit(2)
