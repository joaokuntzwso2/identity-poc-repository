# P0.10 — WSO2 TOTP capability and assurance gate

This is a *read-only* gate, not an enrollment or policy provisioner. On 2026-10-28 the
Aurora Web/APP authentication sequences were both read back as DEFAULT with one
`BasicAuthenticator` step; Brisa Web/APP also used their default Basic-only flow.
The four OIDC client registrations, callback URIs, tenant-qualified Discovery,
and PKCE S256 configuration were independently verified. Chromium is installed.
None of these readbacks proves that a browser login or TOTP challenge succeeded.

The probe `scripts/ciam-p010-totp-capability.py` queries the WSO2 management
Authenticators API for both tenants using existing 0600 local owner journals,
without exposing a credential or writing configuration. Two documented list
paths are supported; the legacy endpoint is tried only if the newer path returns
404/501, never after an authentication failure. It requires an explicitly enabled
LOCAL TOTP authenticator and refuses ambiguous or unsupported response shapes.

Execute from the repository root:

```bash
python3 scripts/test_ciam_p010_totp_capability.py -v
python3 scripts/ciam-p010-totp-capability.py
python3 scripts/ciam-p010-totp-policy-plan.py
```

A successful capability probe **does not attest** enrolled seller OTP factors,
configured conditional authentication, ACR/AMR mapping, signed authentication
events, or an approved business request. The next configuration change, if the
probe allows it, requires an independently approved exact-write plan for only
Aurora WEB and APP. Preserve Brisa's flow and all four OIDC client registrations.
Before accepting approval, use the operator-assisted Playwright journey and
verify an actual WSO2 TOTP event (`amr`, selected `acr`, fresh `auth_time`) from a
signed ID token bound to the seller, same client, and one-time case transaction.
The BFF service must be activated via the existing scoped restart before testing
new production code; doing so expires its old sessions. Never commit runtime
journals, passwords, bearer tokens, session cookies, TOTP seeds, or raw reports.
