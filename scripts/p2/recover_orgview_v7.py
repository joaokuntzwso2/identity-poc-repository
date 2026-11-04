#!/usr/bin/env python3
"""P2.24: consented, one-time continuation of an uncertain Aurora app create.

NO application creation, deletion, rotation, other-tenant requests or broad grants.
Plan is GET-only. Apply can POST EXACTLY one authorized-apis grant to an
independently fingerprint-pinned existing Aurora application, and POST an OAuth
token request. Any ambiguous mutation outcome locks the journal for review.

The supplied candidate fingerprint and inventory count are live observations
from this particular recovery incident, not generic discovery defaults.
"""
from __future__ import annotations
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import stat
import sys

TENANT = 'aurora.identity.test'
APP_NAME = 'P2 Aurora Organization View M2M'
SCOPE = 'internal_org_organization_view'
FINGERPRINT = '837c9f0ac85efca8'  # GET-only v6 verified candidate
INVENTORY_COUNT = 7                  # GET-only v6 verified complete inventory
CERT_SHA256 = '2ba361a032ffd4b34f7df066de72b61c5e836a09f7a7bd7105eb87b4094d9712'
APP_ROOT = f'/t/{TENANT}/api/server/v1/applications'
API_ROOT = f'/t/{TENANT}/api/server/v1/api-resources'
JOURNAL_NAME = 'p2-aurora-orgview-bootstrap.private.json'
CREDS_NAME = 'p2-aurora-orgview-client.private.json'
TOKEN_NAME = 'p2-aurora-root-token.private.txt'
APPROVAL = 'RECOVER_APPROVED_AURORA_ORGVIEW_SCOPE_ON_PINNED_APPLICATION'

class Halt(Exception): pass

def require(ok, code):
    if not ok: raise Halt(code)

def public_report(status, code, **extra):
    print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':status,
                      'code':code,'originalCreateResponseStillUnverified':True,
                      'candidateBoundToPriorReadback':FINGERPRINT,
                      **extra},indent=2,sort_keys=True),flush=True)

def private_file(module, path):
    module.safe_private_file(path)
    info=path.lstat()
    require(info.st_nlink == 1, 'JOURNAL_HARDLINK_REFUSED')
    return info

def load_module(root):
    source=root/'scripts/p2/m2m_bootstrap.py'
    require(source.is_file() and not source.is_symlink(), 'BOOTSTRAP_SOURCE_MISSING')
    spec=importlib.util.spec_from_file_location('p2_existing_orgview_module',source)
    require(spec is not None and spec.loader is not None, 'BOOTSTRAP_IMPORT_UNAVAILABLE')
    module=importlib.util.module_from_spec(spec)
    try: spec.loader.exec_module(module)
    except Exception: raise Halt('BOOTSTRAP_IMPORT_FAILED')
    require(module.TENANT==TENANT and module.APP_ROOT==APP_ROOT and
            module.API_ROOT==API_ROOT and module.SCOPE==SCOPE and
            module.NAME==APP_NAME and
            module.DESCRIPTION == 'P2.24 dedicated tenant-only organization inventory; no partner/user mutation permissions.',
            'BOOTSTRAP_CONTRACT_DRIFT')
    return module

def read_intent(module, private):
    module.secure_dir(private)
    path=private/JOURNAL_NAME
    private_file(module,path)
    intent=module.read_json_private(path)
    require(intent.get('schema')=='p2.24.aurora.m2m.bootstrap.v1' and
            intent.get('phase')=='CREATE_INTENT' and intent.get('tenant')==TENANT and
            intent.get('appName')==APP_NAME and intent.get('scope')==SCOPE and
            intent.get('remoteWritesAttempted')==0 and
            isinstance(intent.get('resourceId'),str) and
            module.API_ID.fullmatch(intent['resourceId']),
            'CREATE_INTENT_UNEXPECTED_OR_ALREADY_ADVANCED')
    for filename in (CREDS_NAME,TOKEN_NAME):
        q=private/filename
        require(not q.exists() and not q.is_symlink(), 'LATER_BOOTSTRAP_ARTIFACT_PRESENT')
    cert=private/'p2-local-wso2-tls-pinned.pem'
    module.safe_private_file(cert,max_size=16384)
    try:
        der=ssl.PEM_cert_to_DER_cert(cert.read_text('ascii'))
    except (OSError, ValueError, UnicodeError):
        raise Halt('TLS_CERTIFICATE_INVALID')
    require(hashlib.sha256(der).hexdigest()==CERT_SHA256,
            'TLS_CERTIFICATE_PIN_CHANGED')
    return intent,cert

class ReadOnly:
    """Forward only the known Aurora management GETs."""
    def __init__(self, http):
        self.http=http;self.get_count=0
    def call(self,method,path,**kwargs):
        require(method=='GET','WRITE_IN_READ_ONLY_PHASE_REFUSED')
        require(isinstance(path,str) and
                (path==APP_ROOT or path.startswith(APP_ROOT+'/') or path.startswith(APP_ROOT+'?') or
                 path==API_ROOT or path.startswith(API_ROOT+'/') or path.startswith(API_ROOT+'?')),
                'READ_OUTSIDE_APPROVED_AURORA_PATHS')
        require(not any(fragment in path for fragment in ('..','\\','//','#','\n','\r')),
                'UNSAFE_READ_PATH')
        self.get_count+=1
        require(self.get_count<=80,'READ_ONLY_REQUEST_LIMIT')
        return self.http.call('GET',path,**kwargs)

def assess(module,http,admin,intent):
    """Reconstruct candidate binding. Absolutely no management mutations."""
    readonly=ReadOnly(http)
    apps=module.inventory(readonly,APP_ROOT,'applications',admin)
    require(len(apps)==INVENTORY_COUNT,'APPLICATION_INVENTORY_COUNT_DRIFT')
    matches=[x for x in apps if x.get('name')==APP_NAME]
    require(len(matches)==1,'CANDIDATE_NAME_NOT_UNIQUE')
    app_id=matches[0].get('id')
    require(isinstance(app_id,str) and module.UUID.fullmatch(app_id),
            'CANDIDATE_UUID_INVALID')
    require(module.hash_id(app_id)==FINGERPRINT,
            'CANDIDATE_FINGERPRINT_CHANGED')
    status,detail,_=readonly.call('GET',f'{APP_ROOT}/{app_id}',basic=admin)
    require(status==200 and isinstance(detail,dict) and detail.get('id')==app_id,
            'CANDIDATE_DETAIL_NOT_VERIFIED')
    try: module.require_new_app_config(detail)
    except Exception: raise Halt('CANDIDATE_APP_CONFIG_DRIFT')
    require(detail.get('description') == module.DESCRIPTION,
            'CANDIDATE_DESCRIPTION_NOT_EXACT')
    # Read OIDC secrets *before* posting an authorization, or fail with no writes.
    try: cid,secret=module.get_oidc(readonly,admin,app_id)
    except Exception: raise Halt('CANDIDATE_OIDC_SECRET_OR_GRANT_NOT_VERIFIED')
    require(isinstance(cid,str) and isinstance(secret,str) and cid and secret,
            'CANDIDATE_CLIENT_CREDENTIALS_NOT_AVAILABLE')
    status,authorized,_=readonly.call('GET',f'{APP_ROOT}/{app_id}/authorized-apis',basic=admin)
    require(status==200 and isinstance(authorized,list) and len(authorized)==0,
            'CANDIDATE_ALREADY_AUTHORIZED_OR_SHAPE_DRIFT')
    # Confirm journal resource ID against a live *detailed* API resource readback.
    try: resource=module.pick_org_api(readonly,admin)
    except Exception: raise Halt('ORGANIZATION_API_RESOURCE_NOT_VERIFIED')
    require(resource['id']==intent['resourceId'], 'JOURNAL_API_RESOURCE_DRIFT')
    return {'appId':app_id,'resourceId':resource['id'],'cid':cid,'secret':secret,
            'getRequests':readonly.get_count}

def apply_scope(module,http,admin,private,intent,assessed):
    """At most ONE management POST, after durable intent and exact rechecks."""
    journal=private/JOURNAL_NAME
    creds=private/CREDS_NAME
    token_path=private/TOKEN_NAME
    app_id=assessed['appId'];resource_id=assessed['resourceId']
    # Never erase original intent: preserve its digest in the next journal phase.
    original_digest=hashlib.sha256(json.dumps(intent,sort_keys=True,
                                  separators=(',',':')).encode()).hexdigest()
    # Persist client credentials only in owner-only private file, before write intent.
    module.exclusive_json(creds, {'tenantDomain':TENANT,'clientId':assessed['cid'],
                'clientSecret':assessed['secret'],'grantTypes':['client_credentials'],
                'state':'REGISTERED_UNAUTHORIZED','appId':app_id,
                'recoveredCandidateFingerprint':FINGERPRINT})
    module.replace_json(journal,{'schema':'p2.24.aurora.m2m.bootstrap.v1',
              'phase':'AUTHORIZATION_INTENT','tenant':TENANT,'appName':APP_NAME,
              'appId':app_id,'resourceId':resource_id,'scope':SCOPE,
              'remoteWritesAttempted':1,'previousCreateIntentDigest':original_digest,
              'recoveryCase':'PINNED_SINGLE_APPLICATION_AFTER_UNVERIFIED_CREATE_RESPONSE'})
    # NO CREATE APP POST. Only authorized-apis on the exact already-observed UUID.
    status,_,_=http.call('POST',f'{APP_ROOT}/{app_id}/authorized-apis',basic=admin,
             data={'id':resource_id,'policyIdentifier':'RBAC','scopes':[SCOPE]})
    require(status==201,'AUTHORIZATION_POST_RESULT_UNVERIFIED_NO_RETRY')
    status,authz,_=http.call('GET',f'{APP_ROOT}/{app_id}/authorized-apis',basic=admin)
    require(status==200,'AUTHORIZATION_READBACK_FAILED_NO_RETRY')
    try: module.exact_authorization(authz,resource_id)
    except Exception: raise Halt('AUTHORIZATION_NOT_EXACTLY_ORG_VIEW_NO_RETRY')
    module.replace_json(creds,{'tenantDomain':TENANT,'clientId':assessed['cid'],
            'clientSecret':assessed['secret'],'grantTypes':['client_credentials'],
            'authorizedScopes':[SCOPE],'state':'SCOPE_VERIFIED','appId':app_id,
            'recoveredCandidateFingerprint':FINGERPRINT})
    # Only the standard OAuth token request follows (not management mutation).
    try: token=module.oauth_token(http,assessed['cid'],assessed['secret'])
    except Exception: raise Halt('OAUTH_TOKEN_ISSUANCE_UNVERIFIED_NO_RETRY')
    try: root=module.root_readback(http,token)
    except Exception: raise Halt('AURORA_ROOT_READBACK_UNVERIFIED_NO_RETRY')
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    try: fd=os.open(token_path,flags,0o600)
    except OSError: raise Halt('PRIVATE_TOKEN_FILE_WRITE_BLOCKED_NO_RETRY')
    with os.fdopen(fd,'w') as f:
        f.write(token);f.flush();os.fsync(f.fileno())
    module.fsync_directory(private)
    module.replace_json(journal,{'schema':'p2.24.aurora.m2m.bootstrap.v1',
               'phase':'COMPLETE','tenant':TENANT,'appName':APP_NAME,
               'appId':app_id,'resourceId':resource_id,'scope':SCOPE,
               'rootId':root,'remoteWritesAttempted':2,
               'previousCreateIntentDigest':original_digest,
               'recoveryCase':'PINNED_SINGLE_APPLICATION_AFTER_UNVERIFIED_CREATE_RESPONSE'})
    return {'applicationFingerprint':FINGERPRINT,'rootFingerprint':module.hash_id(root),
            'tokenFileReady':True,'managementAuthorizationPosts':1,
            'applicationCreatePosts':0}

def main(args):
    if args==['plan']: mode='plan'
    elif args==['apply','--approve='+APPROVAL]: mode='apply'
    else: raise Halt('USE_PLAN_OR_APPROVED_RECOVERY_APPLY')
    root=Path.cwd().resolve()
    require((root/'scripts/ciam-v10.sh').is_file() and
            (root/'scripts/p2/cli.mjs').is_file(), 'RUN_FROM_REPOSITORY_ROOT')
    module=load_module(root)
    private=Path(os.environ.get('P2_PRIVATE_DIR') or
         Path.home()/'wso2-ciam-v10/private').expanduser().absolute()
    intent,cert=read_intent(module,private)
    # Exact GA image, v2 authority version, tenant API GET preflight.
    module.runtime_guard(root,private)
    admin=module.read_existing_authority_admin(root)
    http=module.Http(str(cert))
    if mode=='plan':
        state=assess(module,http,admin,intent)
        return ('PLAN_ONLY','EXISTING_AURORA_APP_PINNED_READY_FOR_SCOPE',
                {'applicationFingerprint':FINGERPRINT,'inventoryCount':INVENTORY_COUNT,
                 'getRequests':state['getRequests'],'managementAuthorizationPosts':0,
                 'applicationCreatePosts':0})
    # Hold a nonblocking OS lock on the existing journal to stop concurrent apply.
    descriptor=os.open(private/JOURNAL_NAME,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        try: fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError: raise Halt('RECOVERY_ALREADY_RUNNING')
        current=module.read_json_private(private/JOURNAL_NAME)
        require(current==intent,'JOURNAL_CHANGED_BEFORE_APPLY')
        assessed=assess(module,http,admin,intent)  # fresh GETs directly before write
        result=apply_scope(module,http,admin,private,intent,assessed)
        return ('VERIFIED','RECOVERED_EXISTING_APP_SCOPE_AND_ROOT_VERIFIED',result)
    finally:
        try: fcntl.flock(descriptor,fcntl.LOCK_UN)
        finally: os.close(descriptor)

if __name__=='__main__':
    phase='apply' if len(sys.argv)>1 and sys.argv[1]=='apply' else 'plan'
    try:
        status,code,extra=main(sys.argv[1:])
        public_report(status,code,**extra)
        sys.exit(0)
    except Halt as e:
        public_report('BLOCKED',str(e),noAutomaticRetry=True)
        sys.exit(2)
    except Exception as e:
        # Existing management adapter raises Block with sanitized error codes;
        # never serialize exception details or response bodies.
        code=str(e) if e.__class__.__name__=='Block' else 'UNEXPECTED_RECOVERY_FAILURE'
        if not code or len(code)>120 or not all(c.isupper() or c.isdigit() or c=='_' for c in code):
            code='RECOVERY_BLOCKED_SANITIZED'
        public_report('BLOCKED',code,noAutomaticRetry=True)
        sys.exit(2)
