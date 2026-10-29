"""Precisely scoped live-browser security gates; no simulated evidence can pass.

The complete matrix is NOT complete while MFA cancel/staleness, WSO2 token
revocation, self-approval, RP-initiated SSO logout and live outage aren't tested.
"""
from __future__ import annotations

# Gate, field in sanitized P010 artifact, expected, evidence class.
OBSERVED = (
    ('LIVE_CALLBACK_REPLAY_DENIAL','callbackReplayHttp',400,'BROWSER_E2E'),
    ('LIVE_UNISSUED_STATE_DENIAL','unsolicitedCallbackHttp',400,'BROWSER_E2E'),
    ('LIVE_BFF_LOGOUT','logoutHttp',200,'BROWSER_E2E'),
    ('LIVE_BFF_LOGOUT_SESSION_DESTROYED','customerSessionDestroyed',True,'BROWSER_E2E'),
    ('LIVE_CROSS_SESSION_ISOLATION','sellerSessionIndependent',True,'BROWSER_E2E'),
    ('LIVE_BFF_LOGOUT_NO_GLOBAL_SSO_CLAIM','wso2GlobalLogoutClaimed',False,'BROWSER_E2E'),
)

# Explicit TODOs intentionally require distinct, fresh, real security evidence.
# No one can mark the aggregate as PASS just by populating fields in a JSON file.
DEFERRED = (
    ('LIVE_CANCELED_MFA','REAL_WSO2_CANCELED_MFA_NOT_EXECUTED'),
    ('LIVE_STALE_MFA','REAL_SIGNED_MFA_FRESHNESS_NOT_EXECUTED'),
    ('LIVE_ACCESS_TOKEN_REVOCATION','PROVIDER_REVOCATION_APPROVAL_AND_LIVE_PROOF_REQUIRED'),
    ('LIVE_SELF_APPROVAL','SEPARATE_AUTHORIZED_SELF_APPROVAL_FIXTURE_REQUIRED'),
    ('LIVE_SSO_LOGOUT','BFF_LOGOUT_NOT_EQUIVALENT_TO_WSO2_GLOBAL_LOGOUT'),
    ('LIVE_WSO2_OUTAGE','CONTROLLED_OUTAGE_NOT_APPROVED'),
    ('LIVE_EXPIRED_SESSION','REAL_SESSION_EXPIRY_NOT_OBSERVED'),
)

def assess(observed:object,live_attested:bool):
    """Return (gate_id,status,expected,reason,evidence_class) with no user values."""
    data=observed if isinstance(observed,dict) else {}
    rows=[]
    for gate,field,expected,kind in OBSERVED:
        if not live_attested: status,reason='BLOCKED','NO_CURRENT_ATTESTED_BROWSER_RUN'
        elif field not in data or data[field] is None:
            status,reason='BLOCKED','LIVE_SECURITY_OBSERVATION_MISSING'
        elif type(data[field]) is not type(expected) or data[field]!=expected:
            status,reason='FAIL','LIVE_SECURITY_CHECK_MISMATCH'
        else: status,reason='PASS','FRESH_LIVE_SECURITY_OBSERVATION_VERIFIED'
        rows.append((gate,status,expected,reason,kind))
    return rows


def deferred():
    return [(gate,'BLOCKED','REAL_LIVE_EVIDENCE',reason,'LIVE_AUTHENTICATION') for gate,reason in DEFERRED]
