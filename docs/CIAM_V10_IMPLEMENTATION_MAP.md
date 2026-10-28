# CIAM implementation map — WSO2 Identity Server 7.3 (Aurora / Brisa)

**As of 2026-10-28.** This document describes the actual local CIAM demo and how its components relate. Read it alongside [`CIAM_V10_ACCEPTANCE_2026-10-28.md`](CIAM_V10_ACCEPTANCE_2026-10-28.md) for evidence and limitations. This is **not** a claim that every planned feature is complete or production-ready.

## 1. Architecture: what owns which data

```text
Browser (real WSO2 login; Aurora / Brisa portals)
    |  same-origin HTTP + BFF session cookie + CSRF on writes
    v
Node BFF  http://127.0.0.1:4400
    |  OIDC Authorization Code + PKCE; signed ID-token validation
    |  WSO2 access-token introspection on protected decisions
    |               +-----------------------------------+
    +-------------->| WSO2 IS 7.3 / PostgreSQL           |
    |               | https://localhost:9444             |
    |               | Aurora + Brisa tenants             |
    |               | users, groups, app roles, scopes,  |
    |               | OIDC applications, API resources   |
    |               +-----------------------------------+
    |
    +--> /api/identity/me  : real session, scopes, optional verified ID-token roles
    +--> /api/brands/{brand}/profile : OIDC UserInfo (release-controlled attributes)
    +--> /api/brands/{brand}/cases   : business API (authorization at every request)
              |
              +--> private append-only JSONL service-request ledger
                   CIAM_BUSINESS_DATA_DIR (NOT identity or role storage)
```

**WSO2 is the source of truth for identity, login, OAuth clients, granted scopes, and app-role membership.** The BFF does not manufacture users, roles, permissions, consent, or MFA outcomes. The business ledger stores genuine application transactions; it does not serve as an identity provider. PostgreSQL is the IS database, not the demo's cases database.

### Runtime boundaries

| Component | Purpose | Source / runtime | Not responsible for |
|---|---|---|---|
| WSO2 tenant + OIDC clients | Account authentication and token issuance | `deploy/ciam-v10/`, Docker `wso2-ciam-v10-is-1` | Business case storage |
| Tenant-local SCIM users/roles | Real seeded human accounts and application-specific grants | `deploy/ciam-v10/identities/{seed.json,bootstrap.py}` | Cross-tenant linked identities |
| API resource registry and app authorizations | Define `ciam:profile:read` / `ciam:cases:*` scope ownership and RBAC | `deploy/ciam-v10/phase4/{desired.json,business-bootstrap.py}` | Deploying an HTTP business API |
| BFF OIDC and live authority | Login/session, issuer/client/audience/scope enforcement, UserInfo | `services/identity-bff/src/{server.js,wso2-authority.js,live-userinfo.js}` | Locally assigning roles |
| Branded portals | Present only live session and API responses | `/portal/aurora`, `/portal/brisa`; `live-brand-v3.*`, `live-cases-v4-ui.js` | Independent authorization decisions |
| Service-request API and ledger | Create/read/review/approve with backend enforcement | `live-cases-v4.js`; private JSONL | Banking, checkout, retail orders or synthetic data |
| Bootstrap recovery journal | Fail-closed operation recovery and readback | `~/wso2-ciam-v10/private/` | Source-controlled configuration |

## 2. Tenant → application → API → role → token relationship

**Tenants.** Aurora is `aurora.identity.test`, Brisa is `brisa.identity.test`; tokens and subjects are tenant-scoped. The same username in different tenants represents two separate WSO2 accounts, not automatic single sign-on. Tenant issuer, selected BFF client and route brand must agree.

**OIDC applications.** Each tenant has **Web** and **App** clients (four registered in total). A browser chooses an explicit client key such as `aurora-web`. An OIDC application is the OAuth client; it is not an API resource. A registered OIDC application must be authorized to request API-resource scopes, and its users must possess the relevant application-scoped role.

**API resources and scopes.** The pre-existing profile resource is identified by `https://api.ciam-v10.test/profile` and provides `ciam:profile:read`. Phase 4 adds the tenant-local business resource `urn:ciampoc:service-requests:v1` with four actions:

| Scope | Meaning | Customer | Seller | Administrator |
|---|---|---:|---:|---:|
| `ciam:cases:create` | Create own service request | Yes | No | No |
| `ciam:cases:read` | Read eligible requests | Yes | Yes | Yes |
| `ciam:cases:review` | Review requests across the brand | No | Yes | Yes |
| `ciam:cases:approve` | Eligibility for approval **only with fresh TOTP** | No | Yes | Yes |

This is the **Phase 4 desired-role matrix**, not a claim that all user/session combinations have been independently browser-tested. These are *new* business roles; the v10 original app roles were not rewritten. The running v10 authority journal is pinned to the deprecated **SCIM role API v2**; do not reset it or silently switch versions.

**Roles versus scopes.** WSO2 app roles determine which permission scopes a user is eligible to receive. OAuth tokens and live introspection provide the granted `ciam:*` scopes. The BFF enforces scopes, not a role label shown by JavaScript. The portal only shows the `roles` claim if WSO2 actually includes it in a *verified* ID token; the absence of that claim does not mean the user has no WSO2 roles.

**JWT audience.** Scope membership and audience are independent gates. A token with `ciam:cases:read` is **still denied** unless its `aud` includes `urn:ciampoc:service-requests:v1`. The BFF reads the live WSO2 introspection result and checks active token, client, issuer/expiry, required audience and required action scope. The pre-existing profile endpoint has its own audience. Do **not** bypass or substitute the audience checks.

**Observed IS 7.3.0 behavior.** Aurora Web initially issued a JWT with the profile audience, even when only a business scope was requested. A guarded, journaled Aurora Web OIDC configuration change appended the business identifier to its pre-existing *configured* ID-token audience list. After a fresh login, both profile and cases endpoints returned 200 with their unchanged strict BFF validators. This is a documented compatibility behavior of **this lab**, not license to change all other clients' audiences without testing. The successful one-off bootstrap is retained in `scripts/recovery/ciam-v4-audience-bootstrap-v4_4.py` for audit/history; it is **not** a fresh-lab installer and must not be blindly reapplied.

## 3. Request processing and trust boundaries

1. The branded page starts an actual WSO2 Authorization Code + PKCE login through the BFF, preserving tenant/client association and validating the signed ID token.
2. The BFF holds tokens server-side and maintains an HTTP-only session; the browser calls same-origin APIs and supplies the session CSRF value on writes. It must not send access/refresh tokens to the browser console.
3. `/api/identity/me` introspects live access tokens and returns only the permissions WSO2 issued. It is a *display/diagnostic endpoint*, not proof that every protected resource audience has been satisfied.
4. `/api/brands/{brand}/profile?client=...` verifies brand/client, profile API authority, then calls WSO2's UserInfo endpoint. It checks the returned `sub` against the verified ID-token subject. **Profile scope is not an automatic release of name or email**; UserInfo previously returned only `sub`.
5. `/api/brands/{brand}/cases?client=...` enforces brand/client mismatch **before** authorization, then live introspection of the *business audience and action scope*. The BFF stores only business events: UUID, title, description, status, timestamp, and an irreversible owner fingerprint derived from `(issuer, sub)`.
6. The customer only sees their own events (`OWNER_ONLY`). A seller with `ciam:cases:review` can read the brand's cases (`BRAND_REVIEW`). `POST` operations also require same-origin and CSRF protection.
7. Approval additionally demands WSO2's **signature-verified ID-token** `amr` contains `totp` and `auth_time` is within 300 seconds, and denies self-approval. Merely having `ciam:cases:approve` is insufficient. **Successful TOTP approval has not been proved**; only denial without recent TOTP passed.

The private append-only JSONL ledger is suited to a single-instance demonstration. It is not a production multi-writer, transactional, high-availability, audit-retention database.

## 4. Bootstraps and deployment lifecycle

| Stage | Purpose | Execution guard / evidence |
|---|---|---|
| v10 authority | Bootstrap persistent IS lab, tenants, four OIDC clients, original API resources/app roles | Existing v10 private authority journal; **do not rerun `fresh-bootstrap`** |
| v10 identities | Create/read back 9 tenant-local real SCIM users and business personas | `deploy/ciam-v10/identities/bootstrap.py`; private identity journal |
| v3 portal | Remove fixture-driven UI, enforce live BFF and UserInfo | `scripts/install-live-brand-v3.py`; `tests/live-userinfo.test.mjs` |
| v4 business | Register service-request API and scopes, authorize apps, assign new business roles | `deploy/ciam-v10/phase4/business-bootstrap.py plan/apply/verify`; private journal readback |
| v4 BFF | Wire live cases API, portal, local durable ledger | `scripts/install-business-v4.py`; `tests/live-cases-v4.test.mjs` |
| v4 Aurora Web audience reconciliation | Retain existing profile audience, add business audience with guarded PUT, verify full settings/readback | `scripts/recovery/ciam-v4-audience-bootstrap-v4_4.py` (one-off, previous journal required) |
| B2B organizations | Child organization + app sharing + delegated administrator | `phase4/b2b-bootstrap.py`; **not executed/verified** |
| Privacy consent v2 | Only when server update and endpoint support are verified | `phase4/consent-preflight.py`; **not enabled** |

The local environment uses Docker Compose project `wso2-ciam-v10`, WSO2 IS at `https://localhost:9444`, and BFF at `http://127.0.0.1:4400`. Runtime startup parameters:

```bash
export WSO2_CIAM_V10_ROLE_API=v2
export WSO2_CIAM_V10_ROLE_V2_CONFIRM=USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES
export CIAM_BUSINESS_DATA_DIR="$HOME/wso2-ciam-v10/private/business-cases-v4"
export WSO2_CASES_API_AUDIENCE='urn:ciampoc:service-requests:v1'
export WSO2_CASES_SCOPES_ENABLED=1
```

Keep these runtime values in the *BFF-launching shell*, not in a committed secret `.env` file. The server's active configuration is also influenced by the **remote WSO2 OIDC settings**, which cannot be reconstructed merely by checking out the Git commit. To check remote state, use the existing read-only `verify` bootstrap (no new writes):

```bash
python3 deploy/ciam-v10/phase4/business-bootstrap.py verify
./scripts/ciam-v10.sh bff-diagnose
./scripts/ciam-v10.sh runtime-acceptance
bash scripts/live-denial-gate.sh
node --test tests/live-userinfo.test.mjs tests/live-cases-v4.test.mjs
python3 scripts/zero-mock-gate.py .
```

**Never** commit `~/wso2-ciam-v10/private`, the PostgreSQL volume, generated passwords, SCIM journals, API credentials, browser tokens, diagnostic JSONL, BFF PID files, `*.bak`, or other local backups. Checking out this code does not provision a clean server automatically.

## 5. Outstanding work — no synthetic stand-ins

- **Real TOTP/step-up:** configure authentication flow and factor enrollment with WSO2; verify an actual challenge, verified `amr` and fresh `auth_time`, then positive approval. No action-level step-up claim yet.
- **B2B delegation:** organizational creation/sharing/admin flows exist as candidate scripts, but need a verified authorized org-admin token and end-to-end readback. Neither partner administration nor cross-tenant identity is currently certified.
- **Privacy preferences:** separately verify the installed WSO2 update level (v2 consent capability may require 7.3.0.12+); OAuth scope consent alone is not privacy preference management.
- **Profile attributes/ID-token roles:** user-approved deferral; implement actual WSO2 attribute release or verified roles claim later. Never invent missing attributes.
- **Other clients:** Aurora App and both Brisa OIDC apps have their business API configuration provisioned/read back; positive business-token audience and end-to-end business usage have **not** been verified for them.
- **Production hardening:** transactional business storage, concurrency/idempotency, audit controls, multi-client testing, and scalable session management are not claimed.

For exact browser acceptance results and test UUID, see [the dated evidence](CIAM_V10_ACCEPTANCE_2026-10-28.md).
