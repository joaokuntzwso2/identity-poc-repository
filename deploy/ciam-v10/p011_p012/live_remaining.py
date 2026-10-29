"""Validate real, independently referenced P0.11 negative-browser artifacts.

A source-matched unit test, browser data alone, or an unreferenced JSON file NEVER
passes a live gate. The full matrix remains blocked until all mandatory scenarios
can be executed and attributed. This module deliberately does not synthesize them.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
try:
    from . import core
except ImportError:
    import core

UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
ALLOWED = {
    'canceled-mfa': 'LIVE_CANCELED_MFA',
    'expired-stepup-transaction': 'LIVE_EXPIRED_STEPUP_TRANSACTION',
    'self-approval': 'LIVE_SELF_APPROVAL',
    'expired-session': 'LIVE_EXPIRED_SESSION',
}
BLOCKED = {
    'LIVE_STALE_MFA': 'SIGNED_STALE_MFA_NOT_VERIFIED_WITH_REAL_ID_TOKEN',
    'LIVE_ACCESS_TOKEN_REVOCATION': 'PROVIDER_BOUND_TOKEN_REVOCATION_NOT_APPROVED_OR_TESTED',
    'LIVE_SSO_LOGOUT': 'WSO2_GLOBAL_SSO_LOGOUT_NOT_IMPLEMENTED_OR_PROVEN',
    'LIVE_WSO2_OUTAGE': 'CONTROLLED_WSO2_OUTAGE_NOT_APPROVED_OR_TESTED',
}

def valid_observation(obj, scenario, sha, runtime, now):
    if not isinstance(obj,dict) or obj.get('schema')!='ciam.p011.negative-browser.v32':return False
    if scenario not in ALLOWED or obj.get('scenario')!=scenario or obj.get('status')!='PASS':return False
    if obj.get('evidenceClass')!='LIVE_AUTHENTICATION' or obj.get('operatorInteraction') is not True:return False
    if obj.get('sourceGitSha')!=sha or obj.get('runtimeIdentity')!=runtime or not runtime:return False
    try:
        age=(now-core.parse_date(obj['at'])).total_seconds()
        if not (0<=age<=4500 if scenario=='expired-session' else 0<=age<=1800):return False
    except (ValueError, TypeError, KeyError, AttributeError):return False
    checks=obj.get('checks')
    if not isinstance(checks,dict):return False
    if scenario!='expired-session' and not UUID.fullmatch(str(obj.get('caseId',''))):return False
    if scenario=='expired-session':
        return type(checks.get('idleSeconds')) is int and checks['idleSeconds']>=3600 and checks.get('authenticatedAfterIdle') is False and obj.get('caseId') is None
    if checks.get('caseStillOpen') is not True:return False
    if scenario=='self-approval':return type(checks.get('selfApprovalHttp')) is int and checks['selfApprovalHttp']==403
    if scenario=='canceled-mfa':return checks.get('realProviderCancelCallback') is True
    if scenario=='expired-stepup-transaction':
        ttl=checks.get('transactionTtlSeconds')
        return type(ttl) is int and 60<=ttl<=600 and type(checks.get('pendingElapsedSeconds')) is int and checks['pendingElapsedSeconds']>=ttl+8 and checks.get('realCodeCallback') is True and type(checks.get('callbackHttp')) is int and checks['callbackHttp']==400
    return False

def attestable(inspection:Path, wrapper:dict, scenario:str, sha:str, runtime:str, now):
    """Verify immutable-looking checksum+private file permissions and current identity.

    SHA256 detects accidental changes; it is not a digital signature. Evidence is
    trusted only when produced by this repository's guarded operator CLI.
    """
    if not isinstance(wrapper,dict) or core.verify_evidence(wrapper,sha,runtime,now) is not None:
        return False
    if wrapper.get('status')!='PASS' or wrapper.get('evidenceClass')!='LIVE_AUTHENTICATION':return False
    if wrapper.get('testId')!=ALLOWED.get(scenario):return False
    refs=wrapper.get('references')
    if not isinstance(refs,list) or len(refs)!=1:return False
    ref=refs[0]
    if not isinstance(ref,dict) or not isinstance(ref.get('artifact'),str) or not re.fullmatch(r'p011-live-negative-v32-[A-Za-z0-9-]+\.json',ref['artifact']):return False
    if not isinstance(ref.get('sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',ref['sha256']):return False
    try:
        raw=core.read_private(inspection/ref['artifact'])
        if core.digest(raw)!=ref['sha256']:return False
        return valid_observation(json.loads(raw),scenario,sha,runtime,now)
    except (OSError,ValueError,TypeError):return False

def evaluate(inspection:Path,sha:str,runtime:str,now):
    results={key:'BLOCKED' for key in ALLOWED}
    if inspection.is_dir() and runtime:
        for p in sorted(inspection.glob('p011-security-attested-*.json'),reverse=True)[:120]:
            try:
                row=json.loads(core.read_private(p))
                scenario=next((s for s,g in ALLOWED.items() if row.get('testId')==g),None)
                if scenario and results[scenario]!='PASS' and attestable(inspection,row,scenario,sha,runtime,now):
                    results[scenario]='PASS'
            except (OSError,ValueError,TypeError,AttributeError):continue
    rows=[]
    for scenario,gate in ALLOWED.items():
        rows.append((gate,results[scenario],'REAL_LIVE_EVIDENCE',
            'CURRENT_REAL_BROWSER_SCENARIO_VERIFIED' if results[scenario]=='PASS' else 'FRESH_SOURCE_RUNTIME_MATCHED_SCENARIO_REQUIRED','LIVE_AUTHENTICATION'))
    for gate,reason in BLOCKED.items():rows.append((gate,'BLOCKED','REAL_LIVE_EVIDENCE',reason,'LIVE_AUTHENTICATION'))
    return rows
