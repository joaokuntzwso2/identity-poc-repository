#!/usr/bin/env python3
"""GET-only, deterministic and non-actionable Aurora TOTP authentication flow plan.
The WSO2 application readback is performed using existing authenticated journals.
No WSO2 application update, credential changes, TOTP enrollment or synthetic claims.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
TARGETS = ('web', 'app')
class Refused(Exception): pass

def canon(node):
    return json.dumps(node,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('utf-8')

def digest(node): return hashlib.sha256(canon(node)).hexdigest()

def plan(readback):
    if (not isinstance(readback,dict) or readback.get('stage') != 'P010_WSO2_APP_ASSURANCE_READBACK' or
        readback.get('remoteWrites') != 0 or readback.get('mode') != 'GET_ONLY'):
        raise Refused('POLICY_READBACK_NOT_GENUINE_GET_ONLY')
    tenants=readback.get('tenants')
    if not isinstance(tenants,dict) or set(tenants) != {'aurora','brisa'}:
        raise Refused('TENANT_LAYOUT_CHANGED')
    actions=[]
    for brand in ('aurora','brisa'):
        node=tenants[brand]
        if not isinstance(node,dict) or set(node) != set(TARGETS):
            raise Refused('APPLICATION_CHANNEL_LAYOUT_CHANGED_'+brand)
        for channel in TARGETS:
            row=node[channel]
            if (not isinstance(row,dict) or any(row.get(k) is not True for k in (
                'registeredApplicationVerified','callbackVerified','codeAndPkceS256Verified'))
                or row.get('roleAudience') != 'APPLICATION'):
                raise Refused('CLIENT_POLICY_VERIFICATION_DRIFT_'+brand+'_'+channel)
            if row.get('mandatoryTotpForRequestedAcrAttested') is not False or row.get('acrAmrFromActualSignedIdTokenAttested') is not False:
                raise Refused('ASSURANCE_ATTESTATION_STATUS_CHANGED_'+brand+'_'+channel)
            # Refuse to propose blindly overwriting any script or existing non-default flow.
            if row.get('conditionalScriptPresent') or row.get('conditionalScriptSha256') is not None:
                raise Refused('EXISTING_ADAPTIVE_SCRIPT_REQUIRES_SEPARATE_REVIEW_'+brand+'_'+channel)
            if row.get('sequenceType') != 'DEFAULT' or row.get('sequenceSteps') != [
                {'id':1,'authenticators':['BasicAuthenticator']}]:
                raise Refused('EXISTING_LOGIN_FLOW_DRIFT_'+brand+'_'+channel)
            if brand == 'aurora':
                actions.append({'tenant':brand,'channel':channel,
                  'scope':'APPLICATION_AUTHENTICATION_SEQUENCE_ONLY',
                  'before':{'sequenceType':'DEFAULT', 'steps':[{'id':1,'authenticators':['BasicAuthenticator']}]},
                  'candidateDesign':{'step1':'BasicAuthenticator','step2':'totp',
                    'step2Condition':'ONLY_WHEN_REQUESTED_STEP_UP_ACR',
                    'selectedAcr':'ONLY_AFTER_SUCCESSFUL_STEP_2',
                    'defaultLogin':'RETAIN_BASIC_ONLY'},
                  'preserve':['applicationId','clientId','clientSecret','callbackURLs','grantTypes','pkce','authorizedAPIs','roles','memberships'],
                  'totpAuthenticatorPresenceVerified':False,
                  'acrSemanticsLiveVerified':False,'amrClaimReleaseVerified':False,
                  'liveSellerEnrollmentVerified':False,
                  'explicitWs02WriteApprovalRequired':True})
    if len(actions)!=2:raise Refused('EXPECTED_TWO_AURORA_APP_CHANGES')
    snapshot={b:{ch:{'sequenceType':tenants[b][ch]['sequenceType'],
      'steps':tenants[b][ch]['sequenceSteps'],
      'scriptSha256':tenants[b][ch]['conditionalScriptSha256']} for ch in TARGETS}
      for b in ('aurora','brisa')}
    result={'stage':'P010_AURORA_TOTP_CONDITIONAL_READ_ONLY_PROPOSAL',
       'status':'EXPLICIT_APPROVAL_AND_AUTHENTICATOR_CAPABILITY_VERIFICATION_REQUIRED',
       'remoteWrites':0,'changesProposed':2, 'brisaChangesProposed':0,
       'changes':actions, 'preconditionSha256':digest(snapshot),
       'safetyRequirements':['VERIFY_TOTP_AUTHENTICATOR_AVAILABLE_IN_WSO2_7_3_GA',
          'CONFIRM_ACR_POLICY_VALUE_FROM_WSO2_POLICY_CONFIGURATION',
          'CONFIRM_SIGNED_ID_TOKEN_AMR_AND_AUTH_TIME_FROM_REAL_SUCCESSFUL_TOTP',
          'ENROLL_AURORA_SELLER_INTERACTIVELY',
          'APPROVE_GUARDED_WRITE_PLAN_SEPARATELY',
          'READBACK_EACH_CHANGED_SEQUENCE_BEFORE_ACCEPTANCE'],
       'writesAllowedByThisTool':False,
       'loginOrTotpSuccessClaimed':False}
    result['planSha256']=digest({'stage':result['stage'],'changes':actions,'precondition':result['preconditionSha256']})
    return result

def main():
    report=subprocess.run([sys.executable,str(HERE/'ciam-p010-wso2-auth-policy-readback.py')],
      cwd=REPO, capture_output=True, text=True,timeout=65,check=False)
    if report.returncode!=0:raise Refused('READ_ONLY_WSO2_POLICY_READBACK_FAILED')
    if len(report.stdout)>200000:raise Refused('READBACK_OVERSIZE')
    output=plan(json.loads(report.stdout))
    print(json.dumps(output,indent=2,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (Refused,KeyError,TypeError,ValueError,subprocess.TimeoutExpired,OSError) as e:
        # Never show raw HTTP errors, passwords, token values or JSON in exception text.
        print('REFUSED:',str(e) if isinstance(e,Refused) else type(e).__name__,file=sys.stderr)
        sys.exit(2)
