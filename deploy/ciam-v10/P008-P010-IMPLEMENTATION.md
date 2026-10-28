# P0.08–P0.10 — Real OIDC and approval-specific WSO2 TOTP step-up

Status: **source implemented, live WSO2 TOTP acceptance NOT YET ATTESTED**.

## Four clients

`aurora-web`, `aurora-app`, `brisa-web`, `brisa-app` remain independent OIDC registrations
bound to tenant-qualified issuers and exact callback URIs. Mobile is a **browser preview**.
The existing BFF implements Authorization Code + PKCE S256, state, nonce, signed ID-token
verification, live introspection, protected UserInfo and server-side sessions. Browser SSO
within a tenant must be measured, and never implies cross-root-tenant federation.

## P0.09 / P0.10 transaction

An authenticated seller with a live `ciam:cases:approve` scope invokes
`POST /api/brands/aurora/cases/{uuid}/approve?client=aurora-web` (or `aurora-app`)
with the same-origin CSRF header. This **does not approve**: the BFF checks the
persisted target and creates a separate one-use authorization transaction.
The 202 JSON contains `authorizationUrl` for a real WSO2 authentication request.
The browser navigates to WSO2. WSO2 MUST enforce a TOTP-only or TOTP-required
assurance profile that matches this request's ACR; other authenticators alone must
not satisfy the configured claim mappings.

The registered OIDC callback consumes the state, exchanges the code with PKCE,
cryptographically validates the new ID token and nonce, verifies the same issuer,
subject and client, checks a configured **actual TOTP AMR**, matching ACR, and a
fresh `auth_time` after the transaction began. It revalidates the fresh access
token's **tenant-pinned introspection**, exact `ciam:cases:approve` permission,
and UserInfo `sub`. Only then does it durably append an audited `approved`
event to the existing tenant JSONL case ledger and redirect to the portal for
an independent persistent-state readback. No OTP seeds, tokens or passwords
are stored in repository artifacts or returned to browser script.

## Mandatory runtime assurance configuration

`WSO2_TOTP_STEPUP_ACR`: exact *actually configured WSO2* assurance class, NOT an
assumed/guessed standard ACR.

`WSO2_TOTP_STEPUP_AMR`: comma-separated values positively mapped to WSO2 TOTP
in a **signed ID token** (e.g. `totp` only after confirmed from live mapping).

These are fail-closed. Setting the values is NOT proof that the WSO2 app login
sequence performs TOTP. Read back the live authentication sequence, set TOTP
as a mandatory step when the requested high-assurance ACR is used, enroll
an authorized Aurora seller through WSO2 My Account or progressive enrollment,
and complete the real challenge interactively. Do not write OTP seeds to Git.

Existing `WSO2_CASES_API_AUDIENCE=urn:ciampoc:service-requests:v1` and
`WSO2_CASES_SCOPES_ENABLED=1` remain required for business permissions. Use the
existing guarded BFF runtime restart workflow; never restart unrelated services.

## Preflight and acceptance boundaries

Run `node scripts/ciam-p008-p010-preflight.mjs` and `python3 scripts/ciam-p010-wso2-auth-policy-readback.py` (management GETs only) or, when live WSO2 is configured and an authorized operator is present, the opt-in browser driver `CIAM_P010_LIVE_CONFIRM=INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE node scripts/ciam-p010-interactive-acceptance.mjs` (from an environment with `@playwright/test` installed and Chromium available). for static structural checks,
then `npm --prefix services/identity-bff test` and `./scripts/ciam-v10.sh test`.
The source-only installer has no WSO2 write mode and does not change registration,
authentication sequences, role scopes or persistent business data.

**Not accepted without live browser evidence:** four successful current-runtime
logins/UserInfo and scopes; fresh seller TOTP enrollment/challenge; persistence
transition after callback; negative cross-tenant, wrong client, replay,
self-approval, expired MFA, outage and logout tests. Record sanitized evidence
per test with timestamps. An operator may have to enter the one-time TOTP code
inside WSO2's UI. No local OTP verification, hardcoded credentials or mocked
positive runtime claims are allowed.

References: WSO2 IS application management REST API, conditional authentication,
TOTP enrollment and ACR/AMR guidance. Implementing a separate conditional login
sequence in WSO2 still needs a verified readback and explicit operator-approved
configuration plan; the BFF must deny approval until configured.

<!-- P010_RUNTIME_GATES_V2_START -->
## Current-runtime gate correction (v2, read-only)

The first P0.08 preflight accidentally imported private BFF config in a plain shell,
which made all four genuinely registered clients appear unconfigured. The replacement
runs without client secrets by cross-checking the anonymous live BFF status at
`http://127.0.0.1:4400` against the four WSO2 management GET readbacks from the
existing tenant-owner and OIDC journals. It does not mark a browser login successful.

```bash
node scripts/ciam-p008-p010-preflight.mjs
python3 scripts/ciam-p010-totp-policy-plan.py
node scripts/ciam-p010-browser-ready.mjs --install
```

The Chromium installer uses the **already installed project's** `playwright` CLI;
it downloads a browser binary into the usual user cache but neither changes
WSO2 nor starts the interactive acceptance journey. Use `--check` to verify
without downloads. It refuses if the installed CLI is absent.

The TOTP policy plan is GET-only and requires the existing WSO2 configuration
still to have a single BasicAuthenticator step on all four clients. It proposes
**Aurora Web and Aurora Mobile Browser only** for conditional Basic + TOTP
when an explicitly configured approval ACR is requested. Brisa is preserved.
This is a candidate design, not an approved write payload. Nothing in the plan
claims that the TOTP authenticator is enabled, that the seller is enrolled, or
that the ID token contains a signed TOTP AMR. Those facts require independent
WSO2 capability checks, separate approval for WSO2 configuration writes and
live interactive authentication before approval can pass.

A WSO2 runtime restart is NOT made by the source installer. The guarded
`./scripts/ciam-v10.sh bff-runtime-plan` / explicitly confirmed `bff-restart`
workflow remains necessary to activate newly installed BFF source. Existing
sessions expire after that BFF restart; the installer does not touch other ports.
<!-- P010_RUNTIME_GATES_V2_END -->
