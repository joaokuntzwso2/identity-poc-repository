# P0.11 Live Security Negative Runner (v32)

This increment is scoped to the existing `live-wso2` BFF, Playwright, and
private `~/wso2-ciam-v10/inspection/` evidence convention. It makes **no WSO2
writes during installation**. Never substitute fixture claims for a real
provider-authenticated session.

## What the new `live-negative` command can actually test

The command runs exactly one real browser security scenario per invocation.
Set `CIAM_P011_NEGATIVE_SCENARIO` to one of:

| Value | Gate | Side effects / prerequisites |
| --- | --- | --- |
| `canceled-mfa` | `LIVE_CANCELED_MFA` | Creates **one** persistent OPEN case; real distinct customer/seller login; seller initiates WSO2 TOTP step-up and operator cancels in WSO2; must receive matching `access_denied` callback; case must remain OPEN |
| `self-approval` | `LIVE_SELF_APPROVAL` | Existing real dual-role identity with create/read/approve scopes **required**; creates one OPEN case only after privileges are verified; same identity must get HTTP 403 and case stays OPEN; will block rather than provision a role |
| `expired-session` | `LIVE_EXPIRED_SESSION` | No case write; real authentication, then more than 3600 seconds of idle time without a BFF request, then authenticated flag must be false |
| `expired-stepup-transaction` | `LIVE_EXPIRED_STEPUP_TRANSACTION` | Creates one OPEN case; real distinct seller initiates WSO2 step-up, waits strictly beyond BFF transaction TTL, then operator signs in; a genuine returned code must be rejected with HTTP 400 and case stays OPEN |

These are **operator-assisted**, not unattended simulations. A WSO2 browser
interaction is needed. A canceled step-up without a WSO2 error callback, a
non-existent dual-role fixture, a timeout, a different runtime, or an inability
to complete the test results in `BLOCKED`. The status never becomes `PASS`
merely because no approval occurred.

For each run explicitly authorize the action with environment variables:

```bash
# Source should be clean; runtime must be the existing local v10 Docker/BFF.
CIAM_P011_NEGATIVE_SCENARIO=canceled-mfa \
CIAM_P011_SECURITY_CONFIRM=RUN_THIS_LIVE_SECURITY_SCENARIO \
CIAM_P011_CASE_WRITE_CONFIRM=CREATE_ONE_PERSISTENT_SECURITY_TEST_CASE \
CIAM_P010_LOCAL_WSO2_TLS_CONFIRM=TRUST_CURRENT_LOCAL_WSO2_CERTIFICATE_FOR_BROWSER_TEST \
./scripts/ciam-v10.sh live-negative

./scripts/ciam-v10.sh readiness
```

Use the other allowed values for other tests. `expired-session` does not
require `CIAM_P011_CASE_WRITE_CONFIRM`. The expiry scenario can take over an
hour by design; it does not accelerate, mock, or rewrite server time.

**Risk/fixture limits:** The cases created by these scenarios are persistent
OPEN records retained for inspection. They are uniquely titled. The runner
does not delete, approve, or silently clean them up. Do not run repeatedly to
force PASS. An existing dual-role WSO2 identity must be used for the
self-approval test; the runner will not grant/create such a role. Browser
cookies, authorization codes, secrets, and full callback URLs are never
included in evidence. WSO2 uses the existing local pinned TLS configuration.

## Evidence

Successful real browser results are written mode `0600` to the private
inspection directory. The CLI validates fields, current source SHA, runtime,
timestamps, and private permissions, then emits a checksummed `p011-security-attested`
record referencing the exact browser report checksum. Readiness revalidates
both artifacts before accepting a gate. Test data alone or an expired report
cannot satisfy the live gate. The SHA-256 manifest detects mutation but is not
an independently authenticated signature.

`expired-stepup-transaction` **does not** prove that a cryptographically
verified but *stale signed* `auth_time` was rejected. That remains the distinct
mandatory `LIVE_STALE_MFA` gate. No one should rename or promote this lesser
test to claim signed-claim freshness.

## Still blocked (do not fabricate)

- `LIVE_STALE_MFA`: requires real signed stale MFA evidence; ordinary
  expiration of OAuth state is insufficient.
- `LIVE_ACCESS_TOKEN_REVOCATION`: requires an approved, dedicated token
  revocation with live BFF-bound access denial; generic introspection fixtures
  are insufficient.
- `LIVE_SSO_LOGOUT`: the BFF does not yet implement/prove cross-client RP-initiated
  WSO2 logout; BFF `/api/logout` is only local session destruction.
- `LIVE_WSO2_OUTAGE`: requires separately approved controlled infrastructure
  interruption, observation and recovery; no Docker pause/stop is performed.
- `CASE_RESOURCE_ROLE_READBACK`: original private provisioning journal is
  absent; independent live configuration check passes but does not attest
  historical ownership. Do not synthesize an original journal.

`FULL_LIVE_NEGATIVE_MATRIX` remains `BLOCKED` while any mandatory scenario is
unattested. Do not use a browser-only PASS to declare the project READY.
