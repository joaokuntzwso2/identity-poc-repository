"""Status-only assertions from the existing real P010 browser journey.

This is not a substitute for WSO2 login, MFA, or the full negative matrix.
"""
from __future__ import annotations

# Keep in sync with scripts/ciam-p011-negative-observations.mjs.
REQUIRED = (
    ('LIVE_CUSTOMER_APPROVAL_DENIAL', 'customerApprovalHttp', 403),
    ('LIVE_ANONYMOUS_CASE_DENIAL', 'anonymousCasesHttp', 401),
    ('LIVE_CROSS_CLIENT_DENIAL', 'wrongTenantClientHttp', 403),
    ('LIVE_CROSS_TENANT_DENIAL', 'crossTenantHttp', 403),
    ('LIVE_ANONYMOUS_CREATE_DENIAL', 'anonymousCreateHttp', 401),
    ('LIVE_CUSTOMER_CSRF_DENIAL', 'customerMissingCsrfHttp', 403),
    ('LIVE_MALFORMED_CREATE_DENIAL', 'malformedCaseHttp', 400),
    ('LIVE_WRONG_METHOD_DENIAL', 'customerWrongMethodHttp', 405),
    ('LIVE_SELLER_CREATE_DENIAL', 'sellerCreateHttp', 403),
    ('LIVE_SELLER_CROSS_TENANT_DENIAL', 'sellerCrossTenantHttp', 403),
    ('LIVE_DUPLICATE_APPROVAL_DENIAL', 'duplicateApprovalHttp', 409),
)

def assess(denials: object, live_attested: bool):
    """Return id,status,reason tuples without echoing untrusted values."""
    values = denials if isinstance(denials, dict) else {}
    result = []
    for gate_id, field, expected in REQUIRED:
        actual = values.get(field)
        if not live_attested:
            status, reason = 'BLOCKED', 'NO_CURRENT_ATTESTED_BROWSER_RUN'
        elif field not in values:
            status, reason = 'BLOCKED', 'LIVE_DENIAL_EVIDENCE_MISSING'
        elif type(actual) is not int or actual != expected:
            status, reason = 'FAIL', 'LIVE_DENIAL_HTTP_MISMATCH'
        else:
            status, reason = 'PASS', 'FRESH_LIVE_HTTP_DENIAL_VERIFIED'
        result.append((gate_id, status, expected, reason))
    return result
