#!/usr/bin/env python3
"""P0.10 operator-assisted live gate. No WSO2 management writes or code edits.

The only process change allowed is the existing guarded BFF restart; configuration
is passed via that command's environment and verified by fresh application readback.
Actual assurance is proved ONLY by the signed callback + live business acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ACR = 'urn:ciampoc:assurance:totp:v1'
AMR = 'totp'  # Expected WSO2 built-in authenticator method; not proof until signed callback.
AUD = 'urn:ciampoc:service-requests:v1'
CONFIRM = 'RESTART_ONLY_VERIFIED_V10_BFF_4400_FOR_P010'
LIVE_CONFIRM = 'INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE'
CLIENTS = ('aurora-web', 'aurora-app', 'brisa-web', 'brisa-app')
REQUIRED = (
    'scripts/ciam-p010-aurora-adaptive.py',
    'scripts/ciam-p010-totp-capability.py',
    'scripts/ciam-p008-p010-preflight.mjs',
    'scripts/ciam-p010-interactive-acceptance.mjs',
    'services/identity-bff/src/approval-stepup-p010.js',
    'services/identity-bff/src/server.js',
    'deploy/ciam-v10/oidc/bootstrap.py',
    'deploy/ciam-v10/bff/restart.py',
    'scripts/ciam-v10.sh',
)

class Stop(Exception):
    pass


def validate_repo(root):
    root = Path(root)
    if root.is_symlink() or not (root / '.git').is_dir() or not (root / 'wso2-lab.sh').is_file():
        raise Stop('IDENTITY_REPO_ROOT_REQUIRED')
    for rel in REQUIRED:
        p = root / rel
        if not p.is_file() or p.is_symlink():
            raise Stop('MISSING_OR_SYMLINK_' + rel)
    return root


def run_json(argv, root, env=None):
    result = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True,
                            timeout=90, check=False)
    # Never print raw stdout/stderr; subprocesses might print sensitive data.
    if result.returncode:
        raise Stop('PRECONDITION_COMMAND_FAILED_' + Path(argv[1] if len(argv)>1 else argv[0]).name)
    try:
        obj = json.loads(result.stdout)
    except ValueError:
        raise Stop('PRECONDITION_NONJSON_RESPONSE') from None
    if not isinstance(obj, dict):
        raise Stop('PRECONDITION_INVALID_SHAPE')
    return obj


def gate(verify, capability, four):
    if verify.get('status') != 'ALL_TWO_AURORA_POLICY_READBACK_VERIFIED' or verify.get('pending') != [] or verify.get('brisaWrites') != 0:
        raise Stop('AURORA_TWO_POLICY_READBACK_NOT_VERIFIED')
    for channel in ('web','app'):
        if verify.get('aurora', {}).get(channel, {}).get('state') != 'after':
            raise Stop('AURORA_POLICY_NOT_APPLIED_' + channel)
    for channel in ('web','app'):
        if verify.get('brisa', {}).get(channel, {}).get('state') != 'before':
            raise Stop('BRISA_AUTH_POLICY_DRIFT_' + channel)
    if verify.get('approvalAcr') != ACR or verify.get('liveTotpChallengeAttested') is True:
        raise Stop('APPROVAL_ASSURANCE_UNEXPECTED_OR_UNTRUSTED')
    if capability.get('tenants', {}).get('aurora', {}).get('totpEnabled') is not True:
        raise Stop('AURORA_TOTP_AUTHENTICATOR_NOT_ENABLED')
    if four.get('fourClientsReadyForInteractiveLogin') is not True:
        raise Stop('FOUR_CLIENTS_NOT_READY')
    cs = four.get('clients')
    if not isinstance(cs, dict) or set(cs) != set(CLIENTS):
        raise Stop('FOUR_CLIENTS_SET_INVALID')
    for key in CLIENTS:
        row = cs[key]
        if not all(row.get(k) is True for k in ('runtimeConfigured','runtimeDiscoveryVerified',
                'wso2RegistrationVerified','callbackVerified','codeAndPkceS256Verified',
                'applicationRoleAudienceVerified','readyForInteractiveLogin')):
            raise Stop('OIDC_CLIENT_NOT_READY_' + key)
    return {
        'stage': 'P010_SELLER_LIVE_GATE_V5',
        'status': 'POLICY_REGISTRATION_TOTP_CAPABILITY_READBACK_VERIFIED',
        'auroraPolicyReadbackVerified': True,
        'brisaUnchanged': True,
        'fourClientsReadyForInteractiveLogin': True,
        'sellerTotpEnrollmentVerified': False,
        'signedAmrAcrAuthTimeVerified': False,
        'positiveApprovalVerified': False,
        'expectedTotpMethodNotYetAttested': AMR,
        'approvalAcr': ACR,
        'wso2Writes': 0,
        'businessWrites': 0,
        'nextGate': 'GUARDED_LOCAL_BFF_RESTART_THEN_OPERATOR_TOTP_CHALLENGE'
    }


def preflight(root):
    verify = run_json([sys.executable,'scripts/ciam-p010-aurora-adaptive.py','verify'], root)
    capability = run_json([sys.executable,'scripts/ciam-p010-totp-capability.py'], root)
    four = run_json(['node','scripts/ciam-p008-p010-preflight.mjs'], root)
    return gate(verify,capability,four)


def restart_env(env):
    new = dict(env)
    new.update({
        'WSO2_CASES_API_AUDIENCE': AUD,
        'WSO2_CASES_SCOPES_ENABLED': '1',
        'WSO2_TOTP_STEPUP_ACR': ACR,
        'WSO2_TOTP_STEPUP_AMR': AMR,
        'WSO2_CIAM_V10_BFF_RESTART_CONFIRM': 'RESTART_ONLY_VERIFIED_V10_BFF_4400',
    })
    return new


def runtime_plan_ok(obj):
    if (obj.get('decision') != 'MAY_RESTART_WITH_EXPLICIT_CONFIRMATION' or
       obj.get('port4400Listening') is not True or
       obj.get('exactProcessOwnershipVerified') is not True):
        raise Stop('V10_BFF_PROCESS_NOT_EXACTLY_VERIFIED')


def restart_bff(root, report, env, confirm):
    if confirm != CONFIRM:
        raise Stop('SCOPED_BFF_RESTART_CONFIRMATION_REQUIRED')
    plan = run_json(['./scripts/ciam-v10.sh','bff-runtime-plan'],root,env)
    runtime_plan_ok(plan)
    restarted = run_json(['./scripts/ciam-v10.sh','bff-restart'],root,restart_env(env))
    if restarted.get('stage')!='CIAM_V10_BFF_RESTARTED_IN_LIVE_MODE' or restarted.get('identityMode')!='live-wso2':
        raise Stop('RESTART_OUTCOME_UNVERIFIED_NO_RETRY')
    after = preflight(root)
    return {'stage':'P010_SELLER_BFF_ASSURANCE_ENV_RESTART',
            'status':'EXACT_LOCAL_V10_BFF_RESTARTED_WITH_EXPECTED_ASSURANCE_MAPPING',
            'auroraPolicyReadbackVerified':after['auroraPolicyReadbackVerified'],
            'assuranceClaimsFromRealTotpAttested': False,
            'bffSessionsInvalidated':True,'wso2Writes':0,'businessWrites':0,
            'nextGate':'OPERATOR_COMPLETES_REAL_WSO2_TOTP_AND_BUSINESS_APPROVAL'}


def run_live(root, env, confirm):
    if confirm != LIVE_CONFIRM:
        raise Stop('EXPLICIT_PERSISTENT_CASE_WRITE_AND_INTERACTIVE_TOTP_CONFIRMATION_REQUIRED')
    # Preflight does not prove successful login; the browser runner performs that proof.
    preflight(root)
    live_env = dict(env)
    live_env['CIAM_P010_LIVE_CONFIRM'] = LIVE_CONFIRM
    # No credential, token, or TOTP material is placed into environment here.
    result = subprocess.run(['node','scripts/ciam-p010-interactive-acceptance.mjs'],cwd=root,
                 env=live_env,timeout=1200,check=False)
    if result.returncode:
        raise Stop('LIVE_BROWSER_ACCEPTANCE_NOT_PASSED_INSPECT_PRIVATE_EVIDENCE')
    return {'stage':'P010_SELLER_LIVE_ACCEPTANCE_DRIVER',
            'status':'BROWSER_DRIVER_EXITED_ZERO_REVIEW_SANITIZED_EVIDENCE',
            'wso2ManagementWrites':0,'persistentCaseWriteOptIn':True}


def main(argv=None, cwd=None, env=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('plan','configure-bff','run-live'))
    parser.add_argument('--confirm',default='')
    args=parser.parse_args(argv)
    root=validate_repo(cwd or Path.cwd())
    context = env if env is not None else os.environ
    result=preflight(root)
    if args.action=='configure-bff': result=restart_bff(root,result,context,args.confirm)
    elif args.action=='run-live': result=run_live(root,context,args.confirm)
    print(json.dumps(result,indent=2))
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except (Stop,OSError,subprocess.TimeoutExpired) as e:
        print('P010_SAFE_STOP: '+(str(e) if isinstance(e,Stop) else type(e).__name__),file=sys.stderr)
        sys.exit(2)
