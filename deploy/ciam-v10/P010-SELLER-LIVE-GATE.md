# P0.10 — Seller live assurance and business approval gate

**Status:** The two Aurora application authentication-sequence PATCHes were
read back successfully on 2026-10-28, but seller enrollment and actual TOTP
approval are not attested without a real operator-assisted WSO2 browser run.

## Source and runtime boundaries

This delivery adds only a Python runner, tests and this document. The runner
reuses the existing *guarded* v10 BFF restart without editing its logic, its
private client manifest, or any WSO2 tenant/application/role/policy. It reads
both Aurora policy sequences (requires `after`), verifies Brisa is unchanged,
checks tenant TOTP capability, and requires all four clients to be ready.

## Usage (no manual edits, passwords or TOTP seed in scripts)

```bash
python3 scripts/ciam_p010_seller_live_gate.py plan

# Explicitly restarts only the independently verified v10 Node process on :4400,
# invalidating its browser sessions; DOES NOT write to WSO2:
python3 scripts/ciam_p010_seller_live_gate.py configure-bff \
  --confirm RESTART_ONLY_VERIFIED_V10_BFF_4400_FOR_P010

# Interactive: real browser logins, seller enters WSO2 TOTP, ONE persistent
# service-request write only after explicit operator opt-in:
python3 scripts/ciam_p010_seller_live_gate.py run-live \
  --confirm INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE
```

`configure-bff` supplies:

- `WSO2_TOTP_STEPUP_ACR=urn:ciampoc:assurance:totp:v1`
- `WSO2_TOTP_STEPUP_AMR=totp` (WSO2 default method name; **expected, not attested**)
- `WSO2_CASES_API_AUDIENCE=urn:ciampoc:service-requests:v1`
- `WSO2_CASES_SCOPES_ENABLED=1`

The real WSO2 signed ID token, nonce and PKCE are still verified by the BFF;
exact configured ACR, actual `totp` AMR, sufficiently recent `auth_time`,
token-to-session subject, tenant-pinned token introspection, UserInfo subject,
case target and authorization must all pass before a business approval is
persisted. No requested `acr_values` alone can make a positive result.

**WSO2 seller enrollment** is a required interactive, user-owned action: the
seller may enroll the authenticator app via WSO2 My Account > Security >
Additional Authentication (scan QR, then enter/verify an actual OTP), or follow
a legitimate WSO2 progressive enrollment prompt if that feature is enabled.
Do not copy QR images, OTP seeds, backup codes or passwords into reports.
Enabling a TOTP authenticator for the tenant does not prove that this user has
enrolled. The interactive acceptance runner must remain fail-closed until the
seller actually completes the second factor and a real approval is persisted.

The browser flow creates a durable test case in the **existing** business
JSONL file. Use only in the authorized lab, never against production. The
existing browser acceptance runner records sanitized evidence under
`~/wso2-ciam-v10/inspection`; no credentials/cookies/tokens/TOTP seeds are
written by this orchestration. Browser acceptance failures retain the failure
state. The BFF restart invalidates browser sessions; it is explicitly scoped,
no arbitrary PID kill or Docker operations.

The WSO2 GA 7.3 deployment did not return application ETags. The approved
policy writes have already completed; this tool does not attempt to repeat
them. This stage does not claim SSO, enrollment, or MFA success based on a
GET-only plan. The negative runtime matrix remains pending even if the
positive interactive flow passes.
