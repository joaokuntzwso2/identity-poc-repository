#!/usr/bin/env python3
"""P2.24 V12: one APPROVED, Aurora-only creator M2M registration and API grant.

No partner organization operations, Brisa/Carbon mutation, credential prompts,
WSO2 upgrade or secret printing. Separate plan/apply/reconcile commands.

Remote management POST budget: one APPLICATION create and one authorized-apis.
All outcomes require exact GET verification; every write is journaled BEFORE POST.
An interrupted/ambiguous attempt is NEVER automatically replayed.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import urllib.parse
import urllib.request
import urllib.error

TENANT = 'aurora.identity.test'
SCOPE = 'internal_org_organization_create'
VIEW_SCOPE = 'internal_org_organization_view'
APP_NAME = 'P2 Aurora Partner Creation M2M'
DESCRIPTION = ('P2.24 one-time Aurora partner onboarding: organization creation only; '
               'no delegated administration or business permissions.')
APP_ROOT = f'/t/{TENANT}/api/server/v1/applications'
API_ROOT = f'/t/{TENANT}/api/server/v1/api-resources'
TOKEN_PATH = f'/t/{TENANT}/oauth2/token'
CERT_NAME = 'p2-local-wso2-tls-pinned.pem'
VIEW_JOURNAL = 'p2-aurora-orgview-bootstrap.private.json'
PARTNER_JOURNAL = 'p2-aurora-partner-create.private.json'
CREATOR_JOURNAL = 'p2-aurora-partner-creator-bootstrap.private.json'
CREATOR_CREDS = 'p2-aurora-partner-creator-client.private.json'
LOCK = 'p2-aurora-partner-creator-v12.lock'
SCHEMA = 'p2.24.aurora.creator.v12'
APPROVAL = 'APPROVE_AURORA_CREATOR_M2M_CREATE_ONLY_V12'
EXPECTED_V11_FP = 'c82cb01293aa467d'
EXPECTED_ROOT_FP = '4548812d1a94a3ff'
EXPECTED_CREATE_RESOURCE_FP = '92f29d96655bba10'
EXPECTED_VIEW_APP_FP = '837c9f0ac85efca8'
EXPECTED_PRE_APPS = 7
SUCCESS_PHASE = 'COMPLETE'
MODULE_DIR = Path(__file__).resolve().parent

class Stop(Exception):
    pass

def need(test, code):
    if not test:
        raise Stop(code)

def safe_code(e):
    code = str(e)
    if type(e) is Stop and re.fullmatch(r'[A-Z][A-Z0-9_]{3,90}', code):
        return code
    if type(e).__name__ == 'Block' and re.fullmatch(r'[A-Z][A-Z0-9_]{3,90}', code):
        return code
    return 'CREATOR_V12_UNEXPECTED_FAILURE'

def report(status, code, **fields):
    print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':status,'code':code,
                      'partnerCreated':False, **fields}, sort_keys=True, indent=2), flush=True)

def load_module(path, name):
    need(path.is_file() and not path.is_symlink(), 'V12_DEPENDENCY_SOURCE_MISSING')
    spec=importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None,'V12_DEPENDENCY_IMPORT_INVALID')
    mod=importlib.util.module_from_spec(spec)
    try: spec.loader.exec_module(mod)
    except Exception: raise Stop('V12_DEPENDENCY_IMPORT_FAILED')
    return mod

def sources(repo):
    m=load_module(repo/'scripts/p2/m2m_bootstrap.py','v12_m2m_bootstrap')
    v11=load_module(repo/'scripts/p2/creator_actor_plan_v11.py','v12_creator_plan')
    v10=v11.load_v10()
    need(m.TENANT==TENANT and m.APP_ROOT==APP_ROOT and m.API_ROOT==API_ROOT and
         v11.TENANT==TENANT and v11.ACTOR_NAME==APP_NAME and
         v11.ACTOR_DESCRIPTION==DESCRIPTION and v11.CREATE_SCOPE==SCOPE and
         v10.APP_FP==EXPECTED_VIEW_APP_FP and v10.ROOT_FP==EXPECTED_ROOT_FP and
         v11.EXPECTED_CREATE_RESOURCE_FP==EXPECTED_CREATE_RESOURCE_FP,
         'DEPENDENCY_CONTRACT_DRIFT')
    return m,v10,v11

def no_partner_journal(private):
    path=private/PARTNER_JOURNAL
    need(not path.exists() and not path.is_symlink(), 'PARTNER_CREATION_JOURNAL_ALREADY_PRESENT')

def verify_local(repo, private, m, v10):
    m.secure_dir(private)
    no_partner_journal(private)
    view=m.read_json_private(private/VIEW_JOURNAL)
    v10.verify_journal(m,view)
    v10.verify_certificate(m,private/CERT_NAME)
    m.runtime_guard(repo,private)
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/CERT_NAME))
    proof=m.verified_existing(http,private,admin,view)
    need(isinstance(proof,dict) and proof.get('action')=='ALREADY_VERIFIED'
         and proof.get('remoteManagementWrites')==0
         and proof.get('rootFingerprint')==EXPECTED_ROOT_FP
         and proof.get('applicationFingerprint')==EXPECTED_VIEW_APP_FP,
         'PINNED_VIEW_CLIENT_RECHECK_FAILED')
    return view,admin,http

def create_resource(m,http,admin,view_resource_id):
    """Only 2 exact identifier filters. No unfiltered/partial API-resource adoption."""
    found=[]; view=[]
    for identifier in sorted(m.ALLOWED_API_IDENTIFIERS):
        query=urllib.parse.urlencode({'filter':'identifier eq '+identifier,'limit':'100'})
        status,doc,_=http.call('GET',f'{API_ROOT}?{query}',basic=admin)
        need(status==200,'CREATE_API_RESOURCE_FILTER_FAILED')
        rows=m._complete_filtered_api_resource_page(doc)
        need(len(rows)<=1,'CREATE_API_RESOURCE_FILTER_AMBIGUOUS')
        for row in rows:
            need(isinstance(row,dict) and row.get('identifier')==identifier and
                 isinstance(row.get('id'),str) and m.API_ID.fullmatch(row['id']),
                 'CREATE_API_RESOURCE_SUMMARY_INVALID')
            status,detail,_=http.call('GET',f'{API_ROOT}/{row["id"]}',basic=admin)
            need(status==200 and isinstance(detail,dict) and detail.get('id')==row['id']
                 and detail.get('identifier')==identifier,'CREATE_API_RESOURCE_DETAIL_INVALID')
            scopes=detail.get('scopes')
            need(isinstance(scopes,list) and all(isinstance(s,dict) and
                 isinstance(s.get('name'),str) for s in scopes),
                 'CREATE_API_RESOURCE_SCOPES_INVALID')
            names=[s['name'] for s in scopes]
            need(len(names)==len(set(names)), 'CREATE_API_RESOURCE_DUPLICATE_SCOPES')
            if VIEW_SCOPE in names: view.append(row['id'])
            if SCOPE in names: found.append(row['id'])
    need(view==[view_resource_id], 'PINNED_VIEW_RESOURCE_CHANGED')
    need(len(found)==1 and m.hash_id(found[0])==EXPECTED_CREATE_RESOURCE_FP,
         'CREATE_API_RESOURCE_IDENTITY_CHANGED')
    return found[0]

def strict_inventory(m,http,admin,view_id):
    rows=m.inventory(http,APP_ROOT,'applications',admin)
    need(len(rows)<=4000,'APP_INVENTORY_TOO_LARGE')
    known=set(); views=0; matches=[]
    for row in rows:
        need(isinstance(row,dict) and isinstance(row.get('id'),str)
             and m.UUID.fullmatch(row['id']) and isinstance(row.get('name'),str),
             'APP_INVENTORY_INVALID')
        need(row['id'] not in known,'APP_INVENTORY_DUPLICATE')
        known.add(row['id'])
        if row['id']==view_id: views+=1
        if row['name']==APP_NAME: matches.append(row)
    need(views==1,'VIEW_APPLICATION_MISSING_OR_CHANGED')
    return rows,matches

def preflight(repo,private,m,v10,v11):
    """Full live v11 approval predicate; absolutely NO management POST."""
    need(not (private/CREATOR_JOURNAL).exists() and
         not (private/CREATOR_JOURNAL).is_symlink(),
         'CREATOR_JOURNAL_EXISTS_RECONCILE_NO_RETRY')
    need(not (private/CREATOR_CREDS).exists() and
         not (private/CREATOR_CREDS).is_symlink(),
         'CREATOR_CREDENTIALS_ALREADY_PRESENT')
    evidence=v11.prepare(repo,private,v10,m)
    need(evidence.get('code')=='CREATOR_APP_ABSENT_SEPARATE_APPROVAL_REQUIRED'
         and evidence.get('actorSpecFingerprint')==EXPECTED_V11_FP
         and evidence.get('existingApplicationsCount')==EXPECTED_PRE_APPS
         and evidence.get('creationResourceFingerprint')==EXPECTED_CREATE_RESOURCE_FP
         and evidence.get('rootFingerprint')==EXPECTED_ROOT_FP
         and evidence.get('viewM2MApplicationFingerprint')==EXPECTED_VIEW_APP_FP
         and evidence.get('viewM2MRemainsReadOnly') is True,
         'V11_CREATOR_PLAN_DRIFT')
    return evidence

@contextlib.contextmanager
def operation_lock(private):
    path=private/LOCK
    flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags,0o600)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and
             (s.st_mode&0o777)==0o600 and s.st_nlink==1,
             'CREATOR_LOCK_FILE_UNSAFE')
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError: raise Stop('CONCURRENT_CREATOR_BOOTSTRAP_LOCKED')
        yield
    finally:
        try: fcntl.flock(fd,fcntl.LOCK_UN)
        finally: os.close(fd)

def metadata(m,http,admin,app_id):
    need(isinstance(app_id,str) and m.UUID.fullmatch(app_id),'CREATED_APP_ID_INVALID')
    status,doc,_=http.call('GET',f'{APP_ROOT}/{app_id}',basic=admin)
    need(status==200 and isinstance(doc,dict) and doc.get('id')==app_id,
         'CREATOR_APP_DETAIL_UNVERIFIED')
    need(doc.get('name')==APP_NAME and doc.get('description')==DESCRIPTION and
         doc.get('isManagementApp') is True and doc.get('applicationEnabled') is not False,
         'CREATOR_APP_DESCRIPTION_OR_TYPE_MISMATCH')
    oidc=(doc.get('inboundProtocolConfiguration') or {}).get('oidc') or {}
    if oidc:
        need(oidc.get('grantTypes')==['client_credentials'] and
             oidc.get('publicClient') is False,
             'CREATOR_APP_UNEXPECTED_INBOUND_GRANTS')
    cid,secret=m.get_oidc(http,admin,app_id)
    need(isinstance(cid,str) and isinstance(secret,str) and len(cid)>=4 and
         len(secret)>=8, 'CREATOR_APP_CREDENTIALS_NOT_READABLE')
    return cid,secret

def authz_readback(http,admin,app_id,resource_id, *, expect_empty=False):
    status,doc,_=http.call('GET',f'{APP_ROOT}/{app_id}/authorized-apis',basic=admin)
    need(status==200 and isinstance(doc,list),'CREATOR_AUTHORIZATION_GET_INVALID')
    if expect_empty:
        need(doc==[],'CREATOR_APP_PREAUTHORIZED_OR_UNEXPECTED')
        return False
    need(len(doc)==1 and isinstance(doc[0],dict) and doc[0].get('id')==resource_id,
         'CREATOR_AUTHORIZED_API_NOT_EXACT')
    entry=doc[0]
    need(entry.get('policyId',entry.get('policyIdentifier'))=='RBAC',
         'CREATOR_API_POLICY_NOT_RBAC')
    scopes=entry.get('authorizedScopes')
    need(isinstance(scopes,list) and len(scopes)==1 and
         isinstance(scopes[0],dict) and scopes[0].get('name')==SCOPE,
         'CREATOR_SCOPE_NOT_EXACTLY_CREATE')
    return True

def parse_post_identity(m,body,location):
    """Accept exact relative/absolute Location, reject URL substitution/conflicts."""
    body_id=body.get('id') if isinstance(body,dict) else None
    location_id=None
    if location:
        need(isinstance(location,str) and len(location)<=2048 and
             not any(c in location for c in ('#','\\','\r','\n')),
             'CREATE_LOCATION_UNTRUSTED')
        loc=urllib.parse.urlsplit(location)
        need(not loc.query and not loc.fragment and
             not loc.username and not loc.password,
             'CREATE_LOCATION_UNTRUSTED')
        if loc.scheme or loc.netloc:
            need(loc.scheme=='https' and loc.netloc=='localhost:9444',
                 'CREATE_LOCATION_FOREIGN_ORIGIN')
        need(loc.path.startswith(APP_ROOT+'/') and
             loc.path.count('/')== (APP_ROOT+'/').count('/'),
             'CREATE_LOCATION_FOREIGN_PATH')
        location_id=loc.path.rsplit('/',1)[-1]
        need(bool(m.UUID.fullmatch(location_id)),'CREATE_LOCATION_INVALID_UUID')
    if body_id is not None:
        need(isinstance(body_id,str) and bool(m.UUID.fullmatch(body_id)),
             'CREATE_RESPONSE_INVALID_UUID')
    need(not (body_id and location_id and body_id!=location_id),
         'CREATE_BODY_LOCATION_ID_CONFLICT')
    return body_id or location_id

def candidate_after_create_bound(m,http,admin,prior_ids,view_id,returned_id):
    rows,matches=strict_inventory(m,http,admin,view_id)
    ids={r['id'] for r in rows}
    new=ids-set(prior_ids)
    need(set(prior_ids).issubset(ids) and len(new)==1 and
         len(ids)==len(prior_ids)+1,
         'POST_CREATE_INVENTORY_DELTA_UNVERIFIED_NO_RETRY')
    need(len(matches)==1 and matches[0]['id'] in new,
         'POST_CREATE_CANDIDATE_NOT_UNIQUE_NO_RETRY')
    app_id=matches[0]['id']
    need(returned_id is None or app_id==returned_id,
         'CREATE_RESPONSE_ID_NOT_NEW_OR_MISMATCH')
    return app_id

def request_creator_token(http,client_id,secret):
    need(isinstance(client_id,str) and isinstance(secret,str) and
         len(client_id)>=4 and len(secret)>=8 and ':' not in client_id,
         'OAUTH_CLIENT_CREDENTIALS_INVALID')
    basic=base64.b64encode((client_id+':'+secret).encode()).decode('ascii')
    data=urllib.parse.urlencode({'grant_type':'client_credentials','scope':SCOPE}).encode('ascii')
    req=urllib.request.Request('https://localhost:9444'+TOKEN_PATH,data=data,method='POST',headers={
        'Authorization':'Basic '+basic,'Accept':'application/json',
        'Content-Type':'application/x-www-form-urlencoded'})
    try:
        with http.opener.open(req,timeout=18) as resp:
            need(resp.status==200,'CREATOR_TOKEN_HTTP_NOT_200')
            raw=resp.read(65537)
            need(len(raw)<=65536,'CREATOR_TOKEN_RESPONSE_TOO_LARGE')
            doc=json.loads(raw)
    except urllib.error.HTTPError as e:
        raise Stop(f'CREATOR_TOKEN_HTTP_{e.code}')
    except (urllib.error.URLError,ssl.SSLError,TimeoutError,OSError,ValueError,UnicodeError):
        raise Stop('CREATOR_TOKEN_UNAVAILABLE_OR_INVALID')
    need(isinstance(doc,dict) and isinstance(doc.get('token_type'),str) and
         doc['token_type'].lower()=='bearer','CREATOR_TOKEN_NOT_BEARER')
    scope=doc.get('scope')
    need(isinstance(scope,str) and set(scope.split())=={SCOPE} and
         len(scope.split())==1,'CREATOR_TOKEN_SCOPE_NOT_EXACT')
    token=doc.get('access_token')
    need(isinstance(token,str) and 25<=len(token)<=8192 and
         not any(c.isspace() for c in token),'CREATOR_TOKEN_INVALID')
    return True   # never persist or print powerful create token

def journal_phase(m,private,values):
    m.replace_json(private/CREATOR_JOURNAL,values)

def apply_once(repo,private,m,v10,v11,admin,http):
    """Approved two-mutation flow; no retries. Called only after preflight+lock."""
    view=m.read_json_private(private/VIEW_JOURNAL)
    prior,matches=strict_inventory(m,http,admin,view['appId'])
    need(len(prior)==EXPECTED_PRE_APPS and matches==[],'CREATOR_APP_ALREADY_EXISTS')
    api_id=create_resource(m,http,admin,view['resourceId'])
    need(m.hash_id(api_id)==EXPECTED_CREATE_RESOURCE_FP,'CREATE_RESOURCE_FINGERPRINT_CHANGED')
    # Fresh partner plan immediately before irreversible writes.
    v10.plan_cli(repo,m,private,view)
    initial={'schema':SCHEMA,'phase':'CREATE_INTENT','tenant':TENANT,
             'name':APP_NAME,'description':DESCRIPTION,'scope':SCOPE,
             'actorSpecFingerprint':EXPECTED_V11_FP,'rootFingerprint':EXPECTED_ROOT_FP,
             'resourceId':api_id,'viewAppId':view['appId'],
             'preexistingAppIds':sorted(r['id'] for r in prior),
             'remoteWritesAttempted':1}
    m.exclusive_json(private/CREATOR_JOURNAL,initial)
    payload={'name':APP_NAME,'description':DESCRIPTION,'isManagementApp':True,
             'inboundProtocolConfiguration':{'oidc':{'grantTypes':['client_credentials'],
                                                    'publicClient':False}}}
    # Exactly one CREATE POST, preceded by durable CREATE_INTENT.
    try:
        status,body,location=http.call('POST',APP_ROOT,basic=admin,data=payload)
    except Exception:
        raise Stop('CREATE_APP_POST_OUTCOME_UNKNOWN_NO_RETRY')
    need(status==201,'CREATE_APP_POST_NOT_201_NO_RETRY')
    returned_id=parse_post_identity(m,body,location)
    # Even when Location/body lack an ID, require strict before/after delta,
    # unique new exact-name candidate and independent configuration readback.
    app_id=candidate_after_create_bound(m,http,admin,initial['preexistingAppIds'],
                                        view['appId'],returned_id)
    cid,secret=metadata(m,http,admin,app_id)
    authz_readback(http,admin,app_id,api_id,expect_empty=True)
    m.exclusive_json(private/CREATOR_CREDS,{
        'schema':SCHEMA,'phase':'REGISTERED_UNAUTHORIZED','tenant':TENANT,
        'appId':app_id,'clientId':cid,'clientSecret':secret,
        'grantTypes':['client_credentials'],'scope':SCOPE})
    auth_intent={**initial,'phase':'AUTHORIZATION_INTENT','appId':app_id,
                 'remoteWritesAttempted':2,
                 'createIdentitySource':('RESPONSE_AND_GET' if returned_id else '201_PLUS_EXACT_INVENTORY_DELTA_GET')}
    journal_phase(m,private,auth_intent)
    # Exactly one approved AUTHORIZATION POST; independent GET is authoritative.
    try:
        auth_status,_,_=http.call('POST',f'{APP_ROOT}/{app_id}/authorized-apis',
            basic=admin,data={'id':api_id,'policyIdentifier':'RBAC','scopes':[SCOPE]})
    except Exception:
        # Even a failed HTTP result can coincide with a persisted write; GET only.
        try: authz_readback(http,admin,app_id,api_id)
        except Exception: raise Stop('AUTHORIZATION_POST_UNRESOLVED_NO_RETRY')
        auth_status=None
    # An unexpected 200/204 is not success by itself: only exact GET can prove it.
    authz_readback(http,admin,app_id,api_id)
    metadata(m,http,admin,app_id)
    # Keep completion separate from live privilege; token is ephemeral.
    journal_phase(m,private,{**auth_intent,'phase':'AUTHORIZATION_GET_VERIFIED',
                             'authResponse201':auth_status==201})
    try: request_creator_token(http,cid,secret)
    except Exception: raise Stop('CREATOR_TOKEN_NOT_VERIFIED_JOURNAL_PRESERVED')
    m.replace_json(private/CREATOR_CREDS,{
        'schema':SCHEMA,'phase':'SCOPE_VERIFIED','tenant':TENANT,
        'appId':app_id,'clientId':cid,'clientSecret':secret,
        'grantTypes':['client_credentials'],'authorizedScopes':[SCOPE]})
    journal_phase(m,private,{**auth_intent,'phase':SUCCESS_PHASE,
                             'authResponse201':auth_status==201,
                             'tokenScopeVerified':True,
                             'applicationFingerprint':m.hash_id(app_id)})
    return {'code':'CREATOR_APP_AND_EXACT_CREATE_SCOPE_VERIFIED',
            'status':'VERIFIED','applicationCreatePosts':1,'authorizationPosts':1,
            'managementWritesAttempted':2,'scope':SCOPE,
            'applicationFingerprint':m.hash_id(app_id),'journalPhase':SUCCESS_PHASE,
            'issuedTokenStored':False,'existingViewM2MRemainsReadOnly':True}

def verify_complete(m,private,admin,http):
    record=m.read_json_private(private/CREATOR_JOURNAL)
    need(record.get('schema')==SCHEMA and record.get('phase')==SUCCESS_PHASE and
         record.get('scope')==SCOPE and record.get('tenant')==TENANT and
         record.get('actorSpecFingerprint')==EXPECTED_V11_FP and
         record.get('rootFingerprint')==EXPECTED_ROOT_FP and
         record.get('remoteWritesAttempted')==2 and
         record.get('tokenScopeVerified') is True,
         'CREATOR_JOURNAL_NOT_COMPLETE')
    app_id=record.get('appId'); rid=record.get('resourceId')
    need(isinstance(app_id,str) and m.UUID.fullmatch(app_id) and
         isinstance(rid,str) and m.API_ID.fullmatch(rid) and
         m.hash_id(rid)==EXPECTED_CREATE_RESOURCE_FP,
         'COMPLETED_CREATOR_IDS_INVALID')
    cred=m.read_json_private(private/CREATOR_CREDS)
    need(cred.get('schema')==SCHEMA and cred.get('phase')=='SCOPE_VERIFIED' and
         cred.get('tenant')==TENANT and cred.get('appId')==app_id and
         cred.get('authorizedScopes')==[SCOPE] and
         cred.get('grantTypes')==['client_credentials'],
         'COMPLETED_CREATOR_CREDENTIALS_INVALID')
    cid,secret=metadata(m,http,admin,app_id)
    need(secrets.compare_digest(cid,cred.get('clientId','')) and
         secrets.compare_digest(secret,cred.get('clientSecret','')),
         'CREATOR_CLIENT_SECRET_OR_ID_CHANGED')
    authz_readback(http,admin,app_id,rid)
    request_creator_token(http,cid,secret)
    return {'status':'VERIFIED','code':'EXISTING_CREATOR_READBACK_VERIFIED_NO_WRITES',
            'applicationCreatePosts':0,'authorizationPosts':0,'managementWritesAttempted':0,
            'scope':SCOPE,'applicationFingerprint':m.hash_id(app_id),
            'existingViewM2MRemainsReadOnly':True,'journalPhase':SUCCESS_PHASE,
            'issuedTokenStored':False}

def finish_get_only(m,private,admin,http):
    """Post-failure recovery: exact WSO2 GET + token, LOCAL journal writes only.

    No application-create POST and no API-authorization POST. Only accepts an
    already-persisted authorization, bound to the original write-ahead record.
    """
    record=m.read_json_private(private/CREATOR_JOURNAL)
    need(record.get('schema')==SCHEMA and record.get('phase') in
         ('AUTHORIZATION_INTENT','AUTHORIZATION_GET_VERIFIED') and
         record.get('tenant')==TENANT and record.get('name')==APP_NAME and
         record.get('scope')==SCOPE and record.get('remoteWritesAttempted')==2 and
         record.get('rootFingerprint')==EXPECTED_ROOT_FP and
         record.get('actorSpecFingerprint')==EXPECTED_V11_FP,
         'FINISH_JOURNAL_NOT_AUTHORIZED_STAGE')
    app_id=record.get('appId');rid=record.get('resourceId')
    need(isinstance(app_id,str) and m.UUID.fullmatch(app_id) and
         isinstance(rid,str) and m.API_ID.fullmatch(rid) and
         m.hash_id(rid)==EXPECTED_CREATE_RESOURCE_FP,
         'FINISH_API_OR_APPLICATION_ID_DRIFT')
    prior=record.get('preexistingAppIds')
    view_id=record.get('viewAppId')
    need(isinstance(prior,list) and len(prior)==EXPECTED_PRE_APPS and
         len(prior)==len(set(prior)) and view_id in prior and
         app_id not in prior,'FINISH_BASELINE_INVALID')
    rows,matches=strict_inventory(m,http,admin,view_id)
    need(len(rows)==EXPECTED_PRE_APPS+1 and
         {r['id'] for r in rows}-set(prior)=={app_id} and
         len(matches)==1 and matches[0]['id']==app_id,
         'FINISH_APPLICATION_INVENTORY_CHANGED')
    cid,secret=metadata(m,http,admin,app_id)
    cred=m.read_json_private(private/CREATOR_CREDS)
    need(cred.get('schema')==SCHEMA and cred.get('tenant')==TENANT and
         cred.get('phase')=='REGISTERED_UNAUTHORIZED' and
         cred.get('appId')==app_id and cred.get('grantTypes')==['client_credentials'] and
         isinstance(cred.get('clientId'),str) and
         isinstance(cred.get('clientSecret'),str) and
         secrets.compare_digest(cred['clientId'],cid) and
         secrets.compare_digest(cred['clientSecret'],secret),
         'FINISH_PRIVATE_CREDENTIALS_CHANGED')
    view=m.read_json_private(private/VIEW_JOURNAL)
    need(create_resource(m,http,admin,view['resourceId'])==rid,
         'FINISH_CREATE_API_RESOURCE_DRIFT')
    authz_readback(http,admin,app_id,rid)
    request_creator_token(http,cid,secret)
    m.replace_json(private/CREATOR_CREDS,{
        **cred,'phase':'SCOPE_VERIFIED','authorizedScopes':[SCOPE]})
    journal_phase(m,private,{**record,'phase':SUCCESS_PHASE,
                             'tokenScopeVerified':True,
                             'applicationFingerprint':m.hash_id(app_id),
                             'localFinalizationBy':'GET_ONLY_V12_RECOVERY'})
    return {'status':'VERIFIED','code':'CREATOR_GET_VERIFIED_LOCAL_FINALIZATION_COMPLETE',
            'managementWritesAttempted':0,'applicationCreatePosts':0,
            'authorizationPosts':0,'scope':SCOPE,'journalPhase':SUCCESS_PHASE,
            'applicationFingerprint':m.hash_id(app_id),'issuedTokenStored':False}

def reconcile_only(m,private,admin,http):
    """Pure management GET inspection, no replay POST and no journal modification."""
    record=m.read_json_private(private/CREATOR_JOURNAL)
    need(record.get('schema')==SCHEMA and record.get('tenant')==TENANT and
         record.get('name')==APP_NAME and record.get('scope')==SCOPE and
         record.get('actorSpecFingerprint')==EXPECTED_V11_FP,
         'CREATOR_RECONCILIATION_JOURNAL_INVALID')
    phase=record.get('phase')
    if phase==SUCCESS_PHASE:
        return verify_complete(m,private,admin,http)
    if phase=='CREATE_INTENT':
        pre=record.get('preexistingAppIds')
        need(isinstance(pre,list) and len(pre)==EXPECTED_PRE_APPS,
             'UNVERIFIED_CREATE_BASELINE')
        rows=m.inventory(http,APP_ROOT,'applications',admin)
        matches=[r for r in rows if r.get('name')==APP_NAME]
        delta={r['id'] for r in rows}-set(pre)
        code=('ONE_NEW_CREATOR_CANDIDATE_NEEDS_OWNERSHIP_RECONCILIATION' if
              len(delta)==1 and len(matches)==1 and matches[0].get('id') in delta else
              'CREATE_POST_OUTCOME_UNRESOLVED_NO_RETRY')
        return {'status':'RECONCILIATION_ONLY','code':code,
                'applicationCreatePosts':0,'authorizationPosts':0,
                'managementWritesAttempted':0,'journalPhase':phase}
    need(phase in ('AUTHORIZATION_INTENT','AUTHORIZATION_GET_VERIFIED'),
         'CREATOR_RECONCILIATION_PHASE_UNSUPPORTED')
    app_id=record.get('appId');rid=record.get('resourceId')
    need(isinstance(app_id,str) and m.UUID.fullmatch(app_id) and
         isinstance(rid,str) and m.API_ID.fullmatch(rid),
         'RECONCILIATION_APP_ID_INVALID')
    metadata(m,http,admin,app_id)
    try:
        authz_readback(http,admin,app_id,rid)
    except Stop:
        return {'status':'RECONCILIATION_ONLY','code':'AUTHORIZATION_NOT_EXACT_NO_RETRY',
                'applicationCreatePosts':0,'authorizationPosts':0,
                'managementWritesAttempted':0,'journalPhase':phase}
    return {'status':'RECONCILIATION_ONLY','code':'CREATE_SCOPE_OBSERVED_GET_ONLY_NO_REPLAY',
            'applicationCreatePosts':0,'authorizationPosts':0,
            'managementWritesAttempted':0,'journalPhase':phase}

def main(args):
    command= 'plan' if args==['plan'] else (
             'apply' if args==['apply','--approve='+APPROVAL] else (
             'reconcile' if args==['reconcile'] else (
             'finish' if args==['finish','--readback-only'] else None)))
    need(command is not None,'USE_PLAN_APPLY_RECONCILE_OR_FINISH')
    repo=Path.cwd().resolve()
    need((repo/'scripts/ciam-v10.sh').is_file() and
         (repo/'scripts/p2/creator_actor_plan_v11.py').is_file() and
         (repo/'scripts/p2/m2m_bootstrap.py').is_file(),
         'RUN_FROM_POC_REPOSITORY_ROOT')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or
        str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    m,v10,v11=sources(repo)
    m.secure_dir(private)
    no_partner_journal(private)
    if command=='plan':
        evidence=preflight(repo,private,m,v10,v11)
        return {'status':'PLAN_ONLY','code':'APPROVED_CREATOR_APPLICATION_READY_FOR_APPLY',
                'managementWritesAttempted':0,'applicationCreatePosts':0,'authorizationPosts':0,
                'actorSpecFingerprint':evidence['actorSpecFingerprint'],
                'creationResourceFingerprint':EXPECTED_CREATE_RESOURCE_FP,
                'existingApplicationsCount':evidence['existingApplicationsCount'],
                'existingViewM2MRemainsReadOnly':True}
    with operation_lock(private):
        view,admin,http=verify_local(repo,private,m,v10)
        if command=='reconcile':
            return reconcile_only(m,private,admin,http)
        if command=='finish':
            return finish_get_only(m,private,admin,http)
        journal=private/CREATOR_JOURNAL
        if journal.exists() or journal.is_symlink():
            record=m.read_json_private(journal)
            if record.get('phase')==SUCCESS_PHASE:
                return verify_complete(m,private,admin,http)
            raise Stop('CREATOR_JOURNAL_INCOMPLETE_NO_POST_RETRY')
        preflight(repo,private,m,v10,v11)
        return apply_once(repo,private,m,v10,v11,admin,http)

if __name__=='__main__':
    try:
        result=main(sys.argv[1:])
        report(result.pop('status'),result.pop('code'),**result)
    except Exception as exc:
        report('BLOCKED',safe_code(exc),noAutomaticRetry=True,
               managementWritesAttempted='UNKNOWN_CHECK_PRIVATE_JOURNAL',
               applicationCreatePosts='DO_NOT_RETRY',authorizationPosts='DO_NOT_RETRY')
        sys.exit(2)
