#!/usr/bin/env python3
"""Guarded WSO2 IS 7.3 Aurora-only conditional TOTP application flow.

Default command is read-only ``plan``. WSO2 PATCH requires a separate, explicit
operator approval and a new live-precondition check, and is journaled before each
single operation. No automatic retry after uncertain writes. Never manipulates
secrets, roles, OIDC grants, APIs, users, business cases, or Brisa configuration.

The configured ACR is merely a policy label; actual signed TOTP AMR/auth_time
and interactive approval acceptance remain independently mandatory.
"""
from __future__ import annotations
import argparse
import contextlib
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DOMAINS = {'aurora':'aurora.identity.test','brisa':'brisa.identity.test'}
CHANNELS = ('web','app')
ACR = 'urn:ciampoc:assurance:totp:v1'
SCRIPT = REPO / 'deploy/ciam-v10/p010/aurora-acr-totp-adaptive.js'
SCRIPT_SHA256 = '93b4f16d657a32968acfc6549fffacb2a9828ba08b729c0fd1c964482665c7ab'
PRIVATE = Path.home() / 'wso2-ciam-v10/private'
JOURNAL = PRIVATE / 'p010-aurora-mfa-policy.private.json'
LOCK = PRIVATE / 'p010-aurora-mfa-policy.lock'
CONFIRM = 'APPROVE_ONLY_AURORA_WEB_APP_CONDITIONAL_TOTP'
HEX = re.compile(r'^[a-f0-9]{64}$')
UUID = re.compile(r'^[a-zA-Z0-9_-]{5,256}$')

class Refused(Exception):pass

def require(condition, why):
    if not condition:raise Refused(why)

def canon(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def digest(obj):return hashlib.sha256(canon(obj)).hexdigest()
def sha_text(text):return hashlib.sha256(text.encode()).hexdigest()

def get_script():
    require(SCRIPT.is_file() and not SCRIPT.is_symlink() and SCRIPT.stat().st_size < 10000,
            'SCRIPT_MISSING_OR_UNSAFE')
    script = SCRIPT.read_text()
    require(sha_text(script)==SCRIPT_SHA256,'UNREVIEWED_SCRIPT_HASH_DRIFT')
    require("var CIAM_APPROVAL_ACR = '"+ACR+"';" in script and
            'executeStep(1' in script and 'executeStep(2' in script and
            'context.selectedAcr = CIAM_APPROVAL_ACR;' in script and
            '..' not in script, 'SCRIPT_CONTENT_INVALID')
    return script

def imported(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    require(spec and spec.loader and path.is_file(), 'BOOTSTRAP_MODULE_MISSING')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def get_modules():
    oidc=imported('ciam_p010_oidc',REPO/'deploy/ciam-v10/oidc/bootstrap.py')
    resources=imported('ciam_p010_resources',REPO/'deploy/ciam-v10/resources/bootstrap.py')
    cap=imported('ciam_p010_capability',HERE/'ciam-p010-totp-capability.py')
    require(oidc.BASE=='https://localhost:9444' and resources.BASE=='https://localhost:9444',
            'WSO2_ENDPOINT_NOT_PINNED')
    return oidc,resources,cap

def check_sequence(seq, state, script=None):
    require(isinstance(seq,dict), 'AUTHENTICATION_SEQUENCE_MISSING')
    expected_type='DEFAULT' if state=='before' else 'USER_DEFINED'
    require(seq.get('type')==expected_type, 'AUTHENTICATION_SEQUENCE_TYPE_DRIFT')
    steps=seq.get('steps')
    require(isinstance(steps,list) and len(steps)==(1 if state=='before' else 2),
            'AUTHENTICATION_STEPS_DRIFT')
    require(seq.get('requestPathAuthenticators',[]) in ([],None),
            'REQUEST_PATH_AUTHENTICATORS_UNEXPECTED')
    require(seq.get('subjectStepId',1)==1 and seq.get('attributeStepId',1)==1,
            'SUBJECT_OR_ATTRIBUTE_STEP_DRIFT')
    require(isinstance(steps[0],dict) and steps[0].get('id')==1 and
            isinstance(steps[0].get('options'),list) and len(steps[0]['options'])==1,
            'BASIC_AUTH_STEP_DRIFT')
    basic=steps[0]['options'][0]
    require(isinstance(basic,dict) and basic.get('idp')=='LOCAL' and
            basic.get('authenticator')=='BasicAuthenticator', 'BASIC_AUTH_OPTION_DRIFT')
    if state=='before':
        require(seq.get('script') in (None,''),'UNOWNED_CONDITIONAL_SCRIPT_PRESENT')
    else:
        step=steps[1]
        require(isinstance(step,dict) and step.get('id')==2 and
                step.get('options')==[{'idp':'LOCAL','authenticator':'totp'}],
                'TOTP_STEP_DRIFT')
        require(seq.get('script')==script,'INSTALLED_SCRIPT_DRIFT')

def after_sequence(before, script):
    check_sequence(before,'before')
    # Preserve supported sequence metadata, and do not touch other app fields.
    after={k:v for k,v in before.items() if k not in ('type','steps','script')}
    after.update({'type':'USER_DEFINED',
                  'steps':[before['steps'][0], {'id':2,'options':[{'idp':'LOCAL','authenticator':'totp'}]}],
                  'subjectStepId':1,'attributeStepId':1,'script':script})
    check_sequence(after,'after',script)
    return after

def app_snapshot(app):
    keys=('id','name','associatedRoles','claimConfiguration','advancedConfigurations',
          'provisioningConfigurations','inboundProtocolConfiguration','applicationEnabled')
    return {key:app.get(key) for key in keys}

def check_app(app, protocol, node, *, channel, brand, seq_state, script):
    require(isinstance(app,dict) and isinstance(protocol,dict), 'APPLICATION_GET_INVALID')
    require(node.get('state')=='verified' and UUID.fullmatch(str(node.get('id',''))) and
            app.get('id')==node['id'] and app.get('name')==node['name'] and
            app.get('associatedRoles',{}).get('allowedAudience')=='APPLICATION',
            'APP_ID_OR_AUDIENCE_DRIFT_'+brand+'_'+channel)
    require(protocol.get('clientId')==node.get('clientId') and
            protocol.get('callbackURLs')==[node.get('callback')] and
            'authorization_code' in protocol.get('grantTypes',[]) and
            protocol.get('pkce',{}).get('mandatory') is True and
            protocol.get('pkce',{}).get('supportPlainTransformAlgorithm') is False,
            'APP_OIDC_CONFIG_DRIFT_'+brand+'_'+channel)
    check_sequence(app.get('authenticationSequence'),seq_state,script)

def read_app(client,domain,appid,auth):
    root=f'/t/{domain}/api/server/v1/applications/{quote(appid,safe="")}'
    st,app,etag=client.call('GET',root,auth=auth)
    require(st==200 and isinstance(app,dict),'APP_GET_FAILED_'+str(st))
    st2,protocol,_=client.call('GET',root+'/inbound-protocols/oidc',auth=auth)
    require(st2==200 and isinstance(protocol,dict),'APP_PROTOCOL_GET_FAILED_'+str(st2))
    return app,protocol,etag,root

class GuardedClient:
    def __init__(self,tls):
        self.tls=tls
        self.get_count=0
        self.patch_count=0
    def call(self,method,path,*,auth,data=None,form=None,etag=None):
        require(form is None and method in ('GET','PATCH') and isinstance(path,str) and
                '\\' not in path and '..' not in path and '#' not in path, 'HTTP_METHOD_OR_PATH_DENIED')
        require(isinstance(auth,str) and auth.startswith('Basic '), 'MISSING_TENANT_OWNER_AUTH')
        valid_get = bool(re.fullmatch(r'/t/(?:aurora\.identity\.test|brisa\.identity\.test)/api/server/v1/applications/[A-Za-z0-9_-]{5,256}(?:/inbound-protocols/oidc)?',path))
        valid_get |= bool(re.fullmatch(r'/t/(?:aurora\.identity\.test|brisa\.identity\.test)/api/server/v1/(?:authenticators|configs/authenticators\?type=LOCAL)',path))
        valid_patch = bool(re.fullmatch(r'/t/aurora\.identity\.test/api/server/v1/applications/[A-Za-z0-9_-]{5,256}',path))
        if method=='GET':
            require(valid_get and data is None and etag is None, 'GET_OUT_OF_SCOPE')
            self.get_count+=1
        else:
            require(valid_patch and isinstance(data,dict) and set(data)=={'authenticationSequence'},
                    'PATCH_OUT_OF_SCOPE')
            check_sequence(data['authenticationSequence'],'after',get_script())
            self.patch_count+=1
        headers={'Authorization':auth,'Accept':'application/json'}
        body=None
        if method=='PATCH':
            headers['Content-Type']='application/json'
            if etag:
                require(isinstance(etag,str) and 0<len(etag)<=150 and '\r' not in etag and '\n' not in etag,
                        'BAD_ETAG')
                headers['If-Match']=etag
            body=canon(data)
        conn=http.client.HTTPSConnection('localhost',9444,context=self.tls,timeout=15)
        try:
            conn.request(method,path,body=body,headers=headers)
            r=conn.getresponse()
            raw=r.read(300001)
            require(len(raw)<=300000,'WSO2_RESPONSE_OVERSIZED')
            require(not (300<=r.status<400),'WSO2_REDIRECT_DENIED')
            try:payload=json.loads(raw) if raw else None
            except (ValueError,UnicodeDecodeError):payload=None
            return r.status,payload,r.getheader('ETag')
        finally:conn.close()

def read_journal():
    if not JOURNAL.exists():return None
    require(not JOURNAL.is_symlink() and stat.S_IMODE(JOURNAL.stat().st_mode)==0o600 and
            JOURNAL.stat().st_size<100000,'JOURNAL_PERMISSION_OR_SIZE_UNSAFE')
    obj=json.loads(JOURNAL.read_text())
    require(isinstance(obj,dict) and obj.get('schema')=='ciam.p010.aurora.mfa.v1',
            'JOURNAL_SCHEMA_DRIFT')
    return obj

def atomic_json(path,obj):
    require(path.parent==PRIVATE and PRIVATE.is_dir() and not PRIVATE.is_symlink(),
            'UNSAFE_PRIVATE_STATE_ROOT')
    f=tempfile.NamedTemporaryFile(prefix='.p010-',suffix='.json',dir=PRIVATE,delete=False)
    try:
        os.fchmod(f.fileno(),0o600)
        f.write(canon(obj));f.flush();os.fsync(f.fileno());f.close()
        os.replace(f.name,path)
    finally:
        try:os.unlink(f.name)
        except FileNotFoundError:pass

def lock():
    require(PRIVATE.is_dir() and not PRIVATE.is_symlink() and
            not (PRIVATE.stat().st_mode & 0o077), 'PRIVATE_DIRECTORY_PERMISSIONS_UNSAFE')
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR,0o600)
    require(stat.S_IMODE(os.fstat(fd).st_mode)==0o600,'LOCK_PERMISSIONS_UNSAFE')
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd

def survey(client, oidc, resources, cap, *, script, journal=None):
    tenants=oidc.read_private(oidc.TENANTS)
    apps=oidc.read_private(oidc.OIDC)
    require(apps.get('schema')=='identity.wso2.ciam.v10.oidc.v1' and
            tenants.get('domains')==DOMAINS and apps.get('base')=='https://localhost:9444',
            'PRIVATE_JOURNAL_CONTEXT_DRIFT')
    result={};live={}
    for brand,domain in DOMAINS.items():
        owner=tenants['tenants'][brand]['owner']
        require(tenants['tenants'][brand]['domain']==domain and owner['username']==resources.OWNER,
                'TENANT_OWNER_DRIFT_'+brand)
        auth=resources.basic(resources.OWNER+'@'+domain,owner['password'])
        require(cap.probe(client,domain,auth)['totpEnabled'] is True,'ENABLED_TOTP_NOT_ATTESTED_'+brand)
        result[brand]={};live[brand]={}
        for ch in CHANNELS:
            node=apps['tenants'][brand]['clients'][ch]
            a,p,etag,path=read_app(client,domain,node['id'],auth)
            state='before'
            if brand=='aurora' and journal and journal.get('roles',{}).get(ch,{}).get('state')=='verified':
                state='after'
            check_app(a,p,node,channel=ch,brand=brand,seq_state=state,script=script)
            digest_before=digest({'app':app_snapshot(a),'protocol':p,'sequence':a['authenticationSequence']})
            result[brand][ch]={'state':state,'applicationIdSha256':sha_text(node['id']),
                'sequenceSha256':digest(a['authenticationSequence']),
                'preconditionSha256':digest_before,'etagPresent':bool(etag)}
            live[brand][ch]={'app':a,'protocol':p,'node':node,'etag':etag,'path':path,'auth':auth,
                             'preconditionSha256':digest_before}
    return result,live

def plan_from_snapshot(summary, script):
    pending=[f'aurora:{ch}' for ch in CHANNELS if summary['aurora'][ch]['state']=='before']
    data={'stage':'P010_AURORA_TOTP_GUARDED_POLICY_V4','status':'READY_FOR_EXPLICIT_APPROVAL' if pending else 'ALL_TWO_AURORA_POLICY_READBACK_VERIFIED',
          'pending':pending,'aurora':summary['aurora'],'brisa':summary['brisa'],
          'scriptSha256':sha_text(script),'approvalAcr':ACR,
          'remoteWrites':0,'brisaWrites':0,'liveTotpChallengeAttested':False,
          'sellerEnrollmentAttested':False,'signedAmrAndAuthTimeAttested':False,
          'conditionalWriteEnforcement':'NOT_ATTESTED_UNLESS_SERVER_SUPPORTS_ETAG'}
    data['planSha256']=digest(data)
    return data

def execute(client,oidc,resources,cap,script, *, approved=False, allow_no_etag=False):
    fd=lock()
    try:
        stored=read_journal()
        summary,live=survey(client,oidc,resources,cap,script=script,journal=stored)
        output=plan_from_snapshot(summary,script)
        if not approved:return output
        require(stored is None or stored.get('scriptSha256')==sha_text(script),
                'JOURNAL_SCRIPT_DRIFT')
        require(stored is None or all(stored.get('roles',{}).get(ch,{}).get('state')=='verified' for ch in
                CHANNELS if summary['aurora'][ch]['state']=='after'), 'UNJOURNALED_ROLE_ADOPTION_REFUSED')
        require(stored is None or all(stored.get('roles',{}).get(ch,{}).get('state') not in
                ('write-started','uncertain') for ch in CHANNELS), 'UNCERTAIN_WRITE_REQUIRES_OPERATOR_REVIEW')
        if stored is None:
            stored={'schema':'ciam.p010.aurora.mfa.v1','scriptSha256':sha_text(script),
                    'appIdsSha256':{ch:summary['aurora'][ch]['applicationIdSha256'] for ch in CHANNELS},
                    'roles':{ch:{'state':'pending'} for ch in CHANNELS}}
            atomic_json(JOURNAL,stored)
        for ch in CHANNELS:
            # Full fresh survey before every remote mutation; post-write journal is never a substitute.
            summary,live=survey(client,oidc,resources,cap,script=script,journal=stored)
            role=stored['roles'][ch]
            require(summary['aurora'][ch]['applicationIdSha256']==stored['appIdsSha256'][ch],
                    'JOURNAL_APPLICATION_ID_DRIFT')
            if role['state']=='verified':continue
            require(role['state']=='pending' and summary['aurora'][ch]['state']=='before',
                    'JOURNAL_STATE_DRIFT')
            current=live['aurora'][ch]
            require(current['etag'] or allow_no_etag,'NO_ETAG_NEEDS_EXPLICIT_ACK')
            payload={'authenticationSequence':after_sequence(current['app']['authenticationSequence'],script)}
            role.update({'state':'write-started','beforeSha256':current['preconditionSha256'],
                         'expectedAfterSequenceSha256':digest(payload['authenticationSequence'])})
            atomic_json(JOURNAL,stored)
            try:
                status,_,_=client.call('PATCH',current['path'],auth=current['auth'],data=payload,
                                       etag=current['etag'])
                require(status==200,'WSO2_PATCH_RESPONSE_UNEXPECTED_'+str(status))
                # Read only that app and assert every unrelated security field unchanged.
                app2,proto2,_,_=read_app(client,DOMAINS['aurora'],current['node']['id'],current['auth'])
                check_app(app2,proto2,current['node'],channel=ch,brand='aurora',seq_state='after',script=script)
                require(app_snapshot(app2)==app_snapshot(current['app']) and proto2==current['protocol'] and
                        digest(app2['authenticationSequence'])==role['expectedAfterSequenceSha256'],
                        'WSO2_POST_WRITE_SCOPE_OR_READBACK_DRIFT')
            except Exception:
                role['state']='uncertain'
                atomic_json(JOURNAL,stored)
                raise Refused('UNCERTAIN_WSO2_PATCH_STOP_NO_RETRY_'+ch)
            role['state']='verified'
            atomic_json(JOURNAL,stored)
        final_summary,_=survey(client,oidc,resources,cap,script=script,journal=stored)
        result=plan_from_snapshot(final_summary,script)
        require(not result['pending'],'FINAL_POLICY_READBACK_INCOMPLETE')
        result.update({'status':'ALL_TWO_AURORA_POLICY_READBACK_VERIFIED','remoteWritesThisRun':client.patch_count,
                       'liveTotpChallengeAttested':False})
        return result
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('plan','apply-approved','verify'))
    p.add_argument('--confirm',default='')
    p.add_argument('--acknowledge-no-etag',action='store_true')
    args=p.parse_args()
    require((REPO/'.git').is_dir(),'NOT_IN_CHECKOUT')
    script=get_script();oidc,resources,cap=get_modules()
    tls=oidc.HTTPS().context
    client=GuardedClient(tls)
    require(args.mode!='apply-approved' or args.confirm==CONFIRM,
            'EXPLICIT_AURORA_POLICY_APPROVAL_REQUIRED')
    require(args.mode=='apply-approved' or (not args.confirm and not args.acknowledge_no_etag),
            'NO_APPROVAL_FLAGS_ALLOWED_ON_GET_ONLY_MODE')
    result=execute(client,oidc,resources,cap,script,
                   approved=args.mode=='apply-approved',allow_no_etag=args.acknowledge_no_etag)
    if args.mode=='verify':
        require(not result['pending'],'AURORA_POLICY_NOT_YET_INSTALLED')
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (Refused,KeyError,TypeError,ValueError,AttributeError,IOError,OSError) as e:
        print('REFUSED:',str(e) if isinstance(e,Refused) else type(e).__name__,file=sys.stderr)
        sys.exit(2)
