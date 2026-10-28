#!/usr/bin/env python3
"""WSO2 7.3 four-client authentication policy snapshot; GET requests ONLY.

Uses local 0600 v10 tenant/OIDC journals. Does not print private credentials,
authentication script source, user identifiers or client IDs.
"""
import hashlib, importlib.util, json, sys
from pathlib import Path
from urllib.parse import quote

REPO=Path(__file__).resolve().parents[1]

class ReadbackRefused(Exception): pass

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    if not spec or not spec.loader:raise ReadbackRefused('BOOTSTRAP_NOT_INSTALLED')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

def summarize(app,protocol,app_id,name,callback,client_id,expected_domain):
    if app.get('id')!=app_id or app.get('name')!=name or app.get('associatedRoles',{}).get('allowedAudience')!='APPLICATION':
        raise ReadbackRefused('APP_IDENTITY_OR_AUDIENCE_DRIFT')
    if protocol.get('clientId')!=client_id or protocol.get('callbackURLs')!=[callback] or \
       'authorization_code' not in protocol.get('grantTypes',[]) or protocol.get('pkce',{}).get('mandatory') is not True or \
       protocol.get('pkce',{}).get('supportPlainTransformAlgorithm') is not False:
        raise ReadbackRefused('OIDC_CLIENT_CALLBACK_PKCE_DRIFT')
    if not callback.startswith('http://127.0.0.1:4400/auth/'):
        raise ReadbackRefused('UNEXPECTED_CALLBACK_ORIGIN')
    seq=app.get('authenticationSequence')
    if seq is not None and not isinstance(seq,dict):raise ReadbackRefused('SEQUENCE_INVALID')
    seq=seq or {}
    script=seq.get('script')
    if script is not None and not isinstance(script,str):raise ReadbackRefused('SEQUENCE_SCRIPT_INVALID')
    steps=seq.get('steps')
    if steps is not None and not isinstance(steps,list):raise ReadbackRefused('SEQUENCE_STEPS_INVALID')
    summary=[]
    for step in (steps or []):
        if not isinstance(step,dict):raise ReadbackRefused('SEQUENCE_STEP_INVALID')
        entries=[]
        for el in step.get('options') or []:
            if not isinstance(el,dict):raise ReadbackRefused('AUTHENTICATOR_OPTION_INVALID')
            name=el.get('authenticator')
            if not isinstance(name,str) or len(name)>120:raise ReadbackRefused('AUTHENTICATOR_NAME_INVALID')
            entries.append(name)
        summary.append({'id':step.get('id'),'authenticators':entries})
    # The presence of a TOTP authenticator option is not proof of mandatory MFA.
    return {'registeredApplicationVerified':True,'callbackVerified':True,
      'codeAndPkceS256Verified':True,'roleAudience':'APPLICATION',
      'sequenceType':seq.get('type'),'sequenceSteps':summary,
      'conditionalScriptPresent':bool(script),
      'conditionalScriptSha256':hashlib.sha256(script.encode()).hexdigest() if script else None,
      'mandatoryTotpForRequestedAcrAttested':False,
      'acrAmrFromActualSignedIdTokenAttested':False}

class GetOnly:
    def __init__(self, transport):self.transport=transport;self.requests=0
    def call(self, method,path,*,auth=None,data=None,form=None):
        if method!='GET' or data is not None or form is not None:
            raise ReadbackRefused('ONLY_GET_ALLOWED')
        self.requests+=1
        return self.transport.call(method,path,auth=auth)

def main():
    if not (REPO/'.git').exists():raise ReadbackRefused('RUN_IN_REPOSITORY_CHECKOUT')
    oidc=load('ciam_v10_oidc_policy_readback',REPO/'deploy/ciam-v10/oidc/bootstrap.py')
    resources=load('ciam_v10_resources_policy_readback',REPO/'deploy/ciam-v10/resources/bootstrap.py')
    tenant=oidc.read_private(oidc.TENANTS)
    journal=oidc.read_private(oidc.OIDC)
    if journal.get('schema')!='identity.wso2.ciam.v10.oidc.v1' or journal.get('base')!=oidc.BASE:
        raise ReadbackRefused('OIDC_JOURNAL_CONTEXT_INVALID')
    client=GetOnly(oidc.HTTPS());report={}
    for brand,domain in oidc.DOMAINS.items():
        owner=tenant['tenants'][brand]['owner']
        if owner['username']!=resources.OWNER or tenant['tenants'][brand]['domain']!=domain:
            raise ReadbackRefused('TENANT_OWNER_DRIFT_'+brand)
        auth=resources.basic(resources.OWNER+'@'+domain,owner['password'])
        report[brand]={}
        for channel in oidc.CHANNELS:
            node=journal['tenants'][brand]['clients'][channel]
            if node.get('state')!='verified' or node.get('domain')!=domain or not oidc.ID.fullmatch(node.get('id','')):
                raise ReadbackRefused('CLIENT_JOURNAL_UNVERIFIED_'+brand+'_'+channel)
            appid=node['id']
            root=f'/t/{domain}/api/server/v1/applications/{quote(appid,safe="")}'
            app=oidc.require(client.call('GET',root,auth=auth),200,'APP_'+brand+'_'+channel)
            protocol=oidc.require(client.call('GET',root+'/inbound-protocols/oidc',auth=auth),200,'OIDC_'+brand+'_'+channel)
            report[brand][channel]=summarize(app,protocol,appid,node['name'],node['callback'],node['clientId'],domain)
    result={'stage':'P010_WSO2_APP_ASSURANCE_READBACK','mode':'GET_ONLY',
      'remoteWrites':0,'getRequests':client.requests,'tenants':report,
      'decision':'TOTP_ACR_POLICY_AND_SIGNED_AMR_AUTH_TIME_REQUIRE_LIVE_BROWSER_ATTESTATION',
      'note':'Application authentication sequence alone does not prove that a seller performed TOTP'}
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (ReadbackRefused, KeyError, TypeError, ValueError, OSError) as e:
        print('REFUSED:',str(e) if isinstance(e,ReadbackRefused) else type(e).__name__,file=sys.stderr)
        sys.exit(2)
