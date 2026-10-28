# CIAM runtime acceptance evidence — 2026-10-28

**Evidence source:** observed command outputs and authenticated browser tests in the development session. This is a human-readable acceptance ledger, not a signed audit report, and it contains **no passwords, cookies, access tokens, or client secrets**.

## WSO2 provisioning and BFF startup

| Test | Observed result | Claim supported |
|---|---|---|
| Phase 4 `business-bootstrap.py plan` | Aurora/Brisa resources initially absent; `remoteWrites: 0` | Safe initial plan |
| Phase 4 `business-bootstrap.py apply` after guarded HTTP 200 recovery | `readback: VERIFIED`, `remoteWrites: JOURNALED` | Provisioning performed and verified by bootstrap |
| Phase 4 `business-bootstrap.py verify` | `readback: VERIFIED`, `businessRuntime: NOT_TESTED` | Business API, scopes, app authorization, roles read back |
| v4 Node unit tests | 3 passed, 0 failed | Local scoped handler tests only |
| Static zero-mock gate | `PASS_STATIC_ONLY`, no issues | Absence of *known* mock patterns; not proof of end-to-end identity |
| `bff-diagnose` | `BFF_READY`, port 4400, 4 OIDC clients configured | BFF ready |
| Anonymous HTTP gates | profile/cases 401, synthetic routes 503 or 404, both brand portals 200 | Fail-closed anonymous behavior |
| WSO2 audience recovery v4.4 | `businessAudienceConfigured: true`, profile preserved, readback `VERIFIED`, BFF `RESTARTED` | Aurora Web configured for business audience, remote OIDC configuration read back |

### Why the audience recovery was necessary

Ana's token initially carried the Aurora Web client ID and `https://api.ciam-v10.test/profile` as audiences, **not** `urn:ciampoc:service-requests:v1`, despite being granted business scopes. The profile endpoint returned 200; cases returned `401 access_token_inactive` because the BFF deliberately rejects a token without the business API audience. A business-only-scope login repeated that result, ruling out mixed scopes as the cause.

Read-only WSO2 app/API audits confirmed the business API identifier, exact scopes, and authorized-resource ID matched. A scoped, journaled Aurora Web OIDC PUT using the management API preserved the pre-existing profile audience while adding the business identifier. Version 4.4 reported `readback: VERIFIED` after the actual remote write. This was a **one-off compatibility recovery**, not a reason to bypass audience validation or repeat the bootstrap.

## Authenticated positive/negative tests

| Real user / context | Operation | Observed response | Acceptance |
|---|---|---|---|
| Ana Costa, Aurora Web | New session with scopes | `ciam:cases:create`, `ciam:cases:read`, `ciam:profile:read` | Pass |
| Ana Costa, Aurora Web | `GET /api/protected/profile` | HTTP 200 | Pass |
| Ana Costa, Aurora Web | `GET /api/brands/aurora/cases` | HTTP 200, `OWNER_ONLY` | Pass; business audience and scope gate accepted |
| Ana Costa, Aurora Web | Create request | HTTP 201, status `OPEN` | Pass |
| Ana Costa, Aurora Web | Readback of created case | HTTP 200, `OWNER_ONLY`, `persistedAndVisible: true` | Pass |
| Marcos Oliveira, Aurora Web | Session scopes | `ciam:cases:approve`, `ciam:cases:read`, `ciam:cases:review` | Pass |
| Marcos Oliveira, Aurora Web | Read Ana's case | HTTP 200, `BRAND_REVIEW`, case visible | Pass |
| Marcos Oliveira, Aurora Web | Attempt customer-only case creation | HTTP 403, `wso2_scope_denied` | Pass; no unauthorized creation |
| Marcos Oliveira, Aurora Web | Attempt approve nonexistent UUID without fresh TOTP | HTTP 403, `fresh_wso2_totp_required` | Pass; approval gate denied |

**Persisted request UUID:** `a23bd357-d6b1-4006-afb6-f919dd35aad2`. It is a service-request identifier, not personal data or an access credential.

The final anonymous gates also returned 401 for `/api/brands/aurora/cases` and the Aurora profile route when unauthenticated. No test here proved a real Brisa business-case token, valid TOTP approval, or actual delegated B2B permissions.

## Known gaps and release interpretation

- **Verified:** real WSO2 Aurora Web login, live profile authorization, business API audience and scope enforcement, customer ownership, persistent create/read, seller review, denied seller creation, denied approval without recent WSO2 TOTP.
- **Not verified:** enrolled real TOTP factor and successful case approval; approval step-up challenge; role names in verified ID token; released name/email; business-case audiences for Aurora App/Brisa Web/Brisa App; B2B delegated org management; privacy consent v2.
- **Not claimed:** a durable multi-process transactional database, complete security testing, production readiness, or a substitute for WSO2-managed identities.

The test used **a randomly generated nonexistent case ID** for the negative approval attempt. Ana's real request was not the approval target.

## Repeatable non-destructive checks

```bash
cd "$HOME/wso2mi/Projects/Demo/poc-implementation"
python3 deploy/ciam-v10/phase4/business-bootstrap.py verify
./scripts/ciam-v10.sh bff-diagnose
./scripts/ciam-v10.sh runtime-acceptance
bash scripts/live-denial-gate.sh
node --test tests/live-userinfo.test.mjs tests/live-cases-v4.test.mjs
python3 scripts/zero-mock-gate.py .
```

These checks do not substitute for fresh authenticated browser acceptance. Never paste token or password values into evidence logs.
