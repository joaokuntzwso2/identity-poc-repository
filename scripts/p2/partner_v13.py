#!/usr/bin/env python3
"""P2.24 V13: approved once-only Aurora partner creation inside normal bootstrap.

On first start, one org POST is allowed after all prior v8-v12 proofs pass.
Subsequent starts perform fresh GET readback with zero management writes.
Interrupted/mismatched writes stay locked; no POST retry or silent adoption.
No user input, token output, Brisa/Carbon changes, delegated roles or upgrades.
"""
from __future__ import annotations
import base64
import contextlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

TENANT='aurora.identity.test'
SCOPE='internal_org_organization_create'
PARTNER_NAME='Aurora Returns & Fulfillment Partner'
PARTNER_HANDLE='aurora-returns-fulfillment'
PARTNER_JOURNAL='p2-aurora-partner-create.private.json'
SCHEMA='p2.24.aurora.partner.v13'
ROOT_FP='4548812d1a94a3ff'
CREATOR_FP='74d6e3c13c5106c4'
PARTNER_APPROVAL='P2_V13_AURORA_RETURNS_ONE_CREATE_APPROVED'
VIEW_JOURNAL='p2-aurora-orgview-bootstrap.private.json'
CREATOR_CREDENTIALS='p2-aurora-partner-creator-client.private.json'
VIEW_TOKEN='p2-aurora-root-token.private.txt'
LOCK='p2-aurora-partner-v13.lock'

class Stop(Exception): pass

def require(ok, code):
    if not ok: raise Stop(code)

def safe_code(e):
    val=str(e)
    if type(e) is Stop and re.fullmatch(r'[A-Z][A-Z0-9_]{3,90}',val): return val
    return 'V13_UNEXPECTED_FAILURE_CHECK_PRIVATE_JOURNAL'

def output(status, code, **details):
    print(json.dumps(dict(phase='P2.24',tenant=TENANT,status=status,code=code,
                          **details),indent=2,sort_keys=True),flush=True)

def import_v12(repo):
    path=repo/'scripts/p2/creator_m2m_v12.py'
    require(path.is_file() and not path.is_symlink(),'V12_CREATOR_BOOTSTRAP_REQUIRED')
    spec=importlib.util.spec_from_file_location('p2_v13_prior_creator',path)
    require(spec is not None and spec.loader is not None,'V12_MODULE_INVALID')
    module=importlib.util.module_from_spec(spec)
    try: spec.loader.exec_module(module)
    except Exception: raise Stop('V12_MODULE_IMPORT_FAILED')
    require(module.TENANT==TENANT and module.SCOPE==SCOPE and
            module.CREATOR_JOURNAL=='p2-aurora-partner-creator-bootstrap.private.json',
            'V12_CREATOR_CONTRACT_CHANGED')
    return module

@contextlib.contextmanager
def lock(private):
    path=private/LOCK
    fd=os.open(path,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and
                (s.st_mode&0o777)==0o600 and s.st_nlink==1,
                'V13_LOCK_UNSAFE')
        try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError: raise Stop('V13_BOOTSTRAP_ALREADY_RUNNING')
        yield
    finally:
        try: fcntl.flock(fd,fcntl.LOCK_UN)
        finally: os.close(fd)

def tokens(v12, m, http, private, need_creator=False):
    """Read view token; mint powerful create token only during first-time ensure."""
    m.safe_private_file(private/VIEW_TOKEN,max_size=8192)
    view=(private/VIEW_TOKEN).read_text('utf8').strip()
    require(25<=len(view)<=8192 and not any(c.isspace() for c in view),
            'V13_VIEW_TOKEN_INVALID')
    if not need_creator: return view,None
    v12cred=m.read_json_private(private/CREATOR_CREDENTIALS)
    require(v12cred.get('tenant')==TENANT and v12cred.get('phase')=='SCOPE_VERIFIED' and
            v12cred.get('authorizedScopes')==[SCOPE] and
            v12cred.get('grantTypes')==['client_credentials'],
            'V13_CREATOR_CREDENTIALS_UNVERIFIED')
    cid=v12cred.get('clientId'); secret=v12cred.get('clientSecret')
    require(isinstance(cid,str) and 4<=len(cid)<=512 and ':' not in cid and
            isinstance(secret,str) and 8<=len(secret)<=4096,
            'V13_CREATOR_CREDENTIALS_INVALID')
    basic=base64.b64encode((cid+':'+secret).encode('utf8')).decode('ascii')
    req=urllib.request.Request('https://localhost:9444/t/aurora.identity.test/oauth2/token',
           data=urllib.parse.urlencode({'grant_type':'client_credentials','scope':SCOPE}).encode(),
           method='POST',headers={'Authorization':'Basic '+basic,
                                  'Content-Type':'application/x-www-form-urlencoded',
                                  'Accept':'application/json'})
    try:
        with http.opener.open(req,timeout=18) as res:
            require(res.status==200,'V13_CREATOR_TOKEN_HTTP_NOT_200')
            raw=res.read(65537)
        require(len(raw)<=65536,'V13_TOKEN_RESPONSE_TOO_LARGE')
        doc=json.loads(raw)
    except urllib.error.HTTPError as e: raise Stop(f'V13_CREATOR_TOKEN_HTTP_{e.code}')
    except (urllib.error.URLError,ssl.SSLError,TimeoutError,OSError,ValueError,UnicodeError):
        raise Stop('V13_CREATOR_TOKEN_UNAVAILABLE')
    require(isinstance(doc,dict) and isinstance(doc.get('token_type'),str) and
            doc['token_type'].lower()=='bearer' and
            isinstance(doc.get('scope'),str) and doc['scope'].split()==[SCOPE],
            'V13_CREATOR_SCOPE_NOT_EXACTLY_GRANTED')
    create=doc.get('access_token')
    require(isinstance(create,str) and 25<=len(create)<=8192 and
            not any(c.isspace() for c in create),'V13_CREATE_TOKEN_INVALID')
    return view,create

def node_call(repo,private,mode,root_id,view_token,create_token=None,partner_id=None):
    """No tokens in process arguments, environment or stdout; pass via stdin pipe."""
    data={'mode':mode,'rootId':root_id,'viewToken':view_token}
    if create_token is not None:
        data['creatorToken']=create_token
        data['approval']=PARTNER_APPROVAL
        data['intentPath']=str(private/PARTNER_JOURNAL)
    if partner_id is not None: data['partnerId']=partner_id
    env={**os.environ,'NODE_EXTRA_CA_CERTS':str(private/'p2-local-wso2-tls-pinned.pem')}
    try:
        proc=subprocess.run(['node','scripts/p2/partner_io_v13.mjs'],
                            input=json.dumps(data),capture_output=True,text=True,
                            env=env,cwd=repo,timeout=90,check=False)
    except (OSError,subprocess.TimeoutExpired):
        raise Stop('V13_ORG_IO_UNAVAILABLE_OR_TIMED_OUT_NO_RETRY')
    try:
        result=json.loads(proc.stdout if proc.returncode==0 else proc.stderr)
    except (TypeError,ValueError): raise Stop('V13_ORG_IO_RESPONSE_INVALID_NO_RETRY')
    require(isinstance(result,dict),'V13_ORG_IO_RESPONSE_INVALID_NO_RETRY')
    if proc.returncode!=0:
        code=result.get('code')
        if isinstance(code,str) and re.fullmatch(r'[A-Z][A-Z0-9_]{3,90}',code):
            raise Stop(code)
        raise Stop('V13_ORG_IO_REFUSED_NO_RETRY')
    return result

def verify_prereqs(repo, private, v12):
    m,v10,_=v12.sources(repo)
    m.secure_dir(private)
    view=m.read_json_private(private/VIEW_JOURNAL)
    v10.verify_journal(m,view)
    v10.verify_certificate(m,private/'p2-local-wso2-tls-pinned.pem')
    m.runtime_guard(repo,private)
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/'p2-local-wso2-tls-pinned.pem'))
    observed=m.verified_existing(http,private,admin,view)
    require(observed.get('action')=='ALREADY_VERIFIED' and
            observed.get('remoteManagementWrites')==0 and
            observed.get('rootFingerprint')==ROOT_FP and
            observed.get('applicationFingerprint')==v12.EXPECTED_VIEW_APP_FP,
            'V13_VIEW_CLIENT_READBACK_FAILED')
    verified=v12.verify_complete(m,private,admin,http)
    require(verified.get('status')=='VERIFIED' and verified.get('scope')==SCOPE and
            verified.get('managementWritesAttempted')==0 and
            verified.get('applicationFingerprint')==CREATOR_FP,
            'V13_CREATOR_CLIENT_READBACK_FAILED')
    root_id=view.get('rootId')
    require(isinstance(root_id,str) and m.UUID.fullmatch(root_id) and
            m.hash_id(root_id)==ROOT_FP,'V13_AURORA_ROOT_DRIFT')
    return m, http, root_id

def inspect_journal(m,private):
    path=private/PARTNER_JOURNAL
    if not path.exists() and not path.is_symlink(): return None
    record=m.read_json_private(path)
    require(record.get('schema')==SCHEMA and record.get('state') in ('INTENT','VERIFIED') and
            record.get('details',{}).get('parentFingerprint')==ROOT_FP and
            record.get('details',{}).get('name')==PARTNER_NAME and
            record.get('details',{}).get('orgHandle')==PARTNER_HANDLE and
            record.get('details',{}).get('creatorAppFingerprint')==CREATOR_FP,
            'V13_PARTNER_JOURNAL_IDENTITY_DRIFT')
    return record

def main(args):
    require(args in (['ensure'],['plan'],['reconcile'],['verify']),
            'V13_COMMAND_REQUIRED_ENSURE_PLAN_RECONCILE_VERIFY')
    mode=args[0]
    repo=Path.cwd().resolve()
    require((repo/'scripts/ciam-v10.sh').is_file() and
            (repo/'scripts/p2/guarded-org.mjs').is_file() and
            (repo/'scripts/p2/partner_io_v13.mjs').is_file(),
            'V13_RUN_FROM_PROJECT_ROOT')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or
                 str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    v12=import_v12(repo)
    with lock(private):
        m,http,root=verify_prereqs(repo,private,v12)
        record=inspect_journal(m,private)
        view,_=tokens(v12,m,http,private,need_creator=False)
        if record is not None:
            if record['state']=='INTENT':
                if mode!='reconcile': raise Stop('V13_UNCERTAIN_PARTNER_WRITE_RECONCILE_NO_RETRY')
                result=node_call(repo,private,'reconcile',root,view)
                return dict(status='RECONCILIATION_ONLY',
                            code=('V13_SINGLE_PARTNER_OBSERVED_MANUAL_OWNERSHIP_REVIEW' if
                                  result.get('action')=='ALREADY_PRESENT' else
                                  'V13_PARTNER_NOT_OBSERVED_INTENT_REMAINS_LOCKED'),
                            organizationFingerprint=result.get('organizationFingerprint'),
                            managementWrites=0,partnerCreated=False,journalState='INTENT')
            partner_id=record['details'].get('organizationId')
            require(isinstance(partner_id,str) and m.UUID.fullmatch(partner_id),
                    'V13_COMPLETED_PARTNER_ID_INVALID')
            read=node_call(repo,private,'verify',root,view,partner_id=partner_id)
            require(read.get('action')=='EXACT_CHILD_VERIFIED' and
                    read.get('organizationFingerprint')==m.hash_id(partner_id),
                    'V13_PARTNER_LIVE_READBACK_DRIFT')
            return dict(status='VERIFIED',code='V13_PARTNER_ALREADY_CREATED_AND_REVERIFIED',
                        managementWrites=0,partnerCreated=False,journalState='VERIFIED',
                        organizationFingerprint=m.hash_id(partner_id))
        require(mode in ('plan','ensure'), 'V13_NO_JOURNAL_CANNOT_VERIFY_OR_RECONCILE')
        plan=node_call(repo,private,'plan',root,view)
        require(plan.get('parentFingerprint')==ROOT_FP, 'V13_ORG_PLAN_ROOT_DRIFT')
        require(plan.get('action')=='CREATE',
                'V13_PARTNER_EXISTS_WITHOUT_OWNERSHIP_JOURNAL_NO_ADOPTION')
        if mode!='ensure':
            return dict(status='PLAN_ONLY',code='V13_PARTNER_READY_FOR_SINGLE_APPROVED_CREATE',
                        managementWrites=0,partnerCreated=False,
                        parentFingerprint=ROOT_FP)
        _,create=tokens(v12,m,http,private,need_creator=True)
        details=dict(parentId=root,parentFingerprint=ROOT_FP,name=PARTNER_NAME,
                     orgHandle=PARTNER_HANDLE,creatorAppFingerprint=CREATOR_FP,
                     remoteWritesAttempted=1,approval=PARTNER_APPROVAL)
        # Exactly one exclusive/fsync write-ahead journal before any org POST.
        m.exclusive_json(private/PARTNER_JOURNAL,dict(schema=SCHEMA,state='INTENT',details=details))
        result=node_call(repo,private,'create',root,view,create_token=create)
        require(result.get('action')=='CREATED_AND_VERIFIED' and
                isinstance(result.get('id'),str) and m.UUID.fullmatch(result['id']) and
                result.get('organizationFingerprint')==m.hash_id(result['id']) and
                result.get('parentFingerprint')==ROOT_FP,
                'V13_CREATE_RESPONSE_UNVERIFIED_NO_RETRY')
        # Independent second GET before marking journal complete.
        check=node_call(repo,private,'verify',root,view,partner_id=result['id'])
        require(check.get('action')=='EXACT_CHILD_VERIFIED' and
                check.get('organizationFingerprint')==m.hash_id(result['id']),
                'V13_CREATED_PARTNER_SECOND_READBACK_FAILED')
        m.replace_json(private/PARTNER_JOURNAL,
            dict(schema=SCHEMA,state='VERIFIED',details={**details,
                 'organizationId':result['id'],'state':'ACTIVE','readbackVerified':True}))
        return dict(status='VERIFIED',code='V13_PARTNER_CREATED_ONCE_AND_READBACK_VERIFIED',
                    managementWrites=1,partnerCreated=True,journalState='VERIFIED',
                    organizationFingerprint=m.hash_id(result['id']))

if __name__=='__main__':
    try:
        result=main(sys.argv[1:])
        status=result.pop('status'); code=result.pop('code')
        output(status,code,**{k:v for k,v in result.items() if v is not None})
    except Exception as exc:
        output('BLOCKED',safe_code(exc),noAutomaticRetry=True,
               managementWrites='UNKNOWN_CHECK_PRIVATE_JOURNAL',partnerCreated='UNVERIFIED')
        sys.exit(2)
