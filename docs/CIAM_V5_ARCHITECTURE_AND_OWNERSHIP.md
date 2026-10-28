# CIAM v5 — architecture, tenancy, ownership, and live capability map

**Baseline:** WSO2 Identity Server 7.3.0, persistent v10 local lab, with v3–v5 additive identity, business and Experience Center stages. **Evidence date: 2026-10-28.** The source paths below are repository paths; private runtime data lives outside Git.

> **Authority rule:** WSO2 is authoritative for users, authentication, application registrations, roles, API resources, token scopes and authentication factors. The Node BFF validates real WSO2 tokens; it is not an identity provider. Its JSONL case ledger contains application business data, not identity/permissions. Client-side pages may display permissions but cannot grant them.

## 1. Complete topology: Carbon Super → Aurora and Brisa

```text
Mac / Docker project: wso2-ciam-v10
  WSO2 IS 7.3.0  https://localhost:9444
    carbon.super  ← server super tenant / super admin 'admin'
      ├─ server-level tenant API, IS/SCIM/system administration context
      ├─ creates root tenant + tenant owner: aurora.identity.test
      └─ creates root tenant + tenant owner: brisa.identity.test
    aurora.identity.test  ← independent identity realm
      ├─ owner / tenant-local M2M application / bootstrap SCIM user
      ├─ Aurora Web OIDC app (aurora-web)    ──┐
      ├─ Aurora Mobile Browser OIDC (aurora-app) ├─ profile + cases API resources
      ├─ application-scoped SCIM v2 roles      ┘
      └─ 6 persona SCIM users, including Ana and Marcos
    brisa.identity.test  ← independent identity realm
      ├─ owner / tenant-local M2M application / bootstrap SCIM user
      ├─ Brisa Web OIDC app (brisa-web)       ──┐
      ├─ Brisa Mobile Browser OIDC (brisa-app)  ├─ profile + cases API resources
      ├─ application-scoped SCIM v2 roles      ┘
      └─ 3 persona SCIM users, including its own separate Ana
  PostgreSQL container: ciam_identity, ciam_shared, ciam_agent

Browser
  ├─ /, /lab, /experience (Experience Center / six guided journeys)
  ├─ /portal/aurora/web        /portal/aurora/mobile
  └─ /portal/brisa/web         /portal/brisa/mobile
          │ same-origin BFF session cookie (no bearer tokens in browser JS)
          ▼
  Node BFF http://127.0.0.1:4400
          ├─ /auth/{client}/login → WSO2 Authorization Code + PKCE
          ├─ /api/identity/me → live introspection / validated session evidence
          ├─ /api/brands/{brand}/profile → validated UserInfo from WSO2
          └─ /api/brands/{brand}/cases → audience + action scope + tenant checks
                 └─ private append-only cases JSONL in CIAM_BUSINESS_DATA_DIR
```

The PostgreSQL databases are the **Identity Server persistence layer**, shared by the same server instance. They do *not* imply a shared user realm or interchangeability of Aurora and Brisa tokens. The `ciam_agent` database is an AgentIdentity datasource configured by the server bootstrap, **not** proof that a live agent/token-exchange journey is implemented.

## 2. Carbon Super — what really belongs there

| Object / responsibility | Carbon Super relationship | Source of evidence |
|---|---|---|
| Default server super tenant | `carbon.super` is the built-in root/super administration context, not a customer brand | WSO2 multi-tenancy docs + server topology |
| Super administrator | `admin`, created by `[super_admin] create_admin_account = true`; password saved privately | `deploy/ciam-v10/server/render.py` and `~/wso2-ciam-v10/private/admin.private.json` |
| Root tenant creation | Super admin calls `POST /api/server/v1/tenants` and reads the owners for `aurora.identity.test` and `brisa.identity.test` | `deploy/ciam-v10/tenants/provision.py` |
| Runtime policies and datasources | Hostname/port offset, PostgreSQL identity/shared/agent config and introspection policy in private `deployment.toml` | `deploy/ciam-v10/server/render.py`, `server/introspection_policy.py` |
| WSO2 system apps, built-in API resources, SCIM users/roles | Can exist in the super tenant. **Do not infer the complete live inventory from the brand bootstraps.** | `python3 scripts/ciam-carbon-super-readback.py` (read-only, bounded, prints status as UNVERIFIED if unsupported) |
| Brand OIDC clients and brand SCIM roles | **Not Carbon Super-owned:** they are provisioned under `/t/aurora.identity.test/...` or `/t/brisa.identity.test/...` | `oidc/bootstrap.py`, `authority/bootstrap.py`, Phase 4 bootstrap |
| Demonstration customer login | **Not in Carbon Super.** Use the appropriate tenant and one of the four tenant OIDC clients | BFF OIDC / tenant-qualified issuer |

The super-admin is a high-privilege **administrative identity**, not a representative seller/administrator persona and not an `admin` user in each brand. A tenant owner is an entirely different account (`labtenantadmin@<tenant-domain>`). WSO2's built-in super-tenant roles should not be confused with the application-scoped `CIAM Demo …` and `CIAM Business …` roles in the two customer tenants.

WSO2 documents that `carbon.super` is present by default and additional root organizations/tenants isolate user bases. This system-level statement does not establish the exact application/user inventory of your running super tenant; the read-only audit supplements it. See [Manage Root Organizations](https://is.docs.wso2.com/en/7.2.0/guides/multitenancy/manage-tenants/).

<!-- CIAM_V5_CARBON_SUPER_READBACK_2026_10_28 -->
### Carbon Super live readback — October 28, 2026

The read-only Carbon Super audit confirmed:

| Resource | Verified evidence |
|---|---|
| Root customer tenants | `aurora.identity.test`, `brisa.identity.test` (2) |
| Super-tenant applications | `Console`, `My Account` (2) |
| Super-tenant SCIM users | 1: administrator `admin` |
| Super-tenant SCIM v2 roles | `Administrator`, `Impersonator`, `system`, `everyone`, `admin` |
| API resources | 184 reported; first 100 inspected |

**Important:** The super-tenant API-resource enumeration is
partial (100 of 184). These system/management resources must not
be confused with the separately registered Aurora and Brisa
customer applications, API resources, users, or roles.

The audit is reproducible with:
`python3 scripts/ciam-carbon-super-readback.py`.

## 3. Aurora and Brisa ownership by object type

| Object | Aurora tenant | Brisa tenant | Created/read by |
|---|---|---|---|
| Tenant domain | `aurora.identity.test` | `brisa.identity.test` | Carbon Super root-tenant API |
| Tenant owner | `labtenantadmin@aurora.identity.test` | `labtenantadmin@brisa.identity.test` | Tenant owner journal/API |
| Bootstrap non-admin SCIM user | `ciam_aurora` | `ciam_brisa` | `resources/bootstrap.py` |
| Scoped management M2M OAuth app | `Identity Lab AURORA Management Bootstrap` | `Identity Lab BRISA Management Bootstrap` | `resources/bootstrap.py` |
| Customer Web OIDC application | `Identity Lab v10 Aurora Web` (`aurora-web`) | `Identity Lab v10 Brisa Web` (`brisa-web`) | `oidc/bootstrap.py` |
| Customer Mobile Browser OIDC application | `Identity Lab v10 Aurora Mobile Browser Preview` (`aurora-app`) | `Identity Lab v10 Brisa Mobile Browser Preview` (`brisa-app`) | `oidc/bootstrap.py` |
| Profile API resource | `https://api.ciam-v10.test/profile` (its own tenant registration) | Same identifier, **separate registration** | `authority/bootstrap.py` |
| Business API resource | `urn:ciampoc:service-requests:v1` (tenant registration) | Same identifier, **separate registration** | `phase4/business-bootstrap.py` |
| Profile scope | `ciam:profile:read` | `ciam:profile:read` | WSO2 authorized API and app roles |
| Business scopes | `ciam:cases:create`, `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | Same names, tenant-specific grants | `phase4/desired.json` |
| Root-tenant SCIM personas | 6 accounts | 3 accounts | `identities/seed.json`, `identities/bootstrap.py` |
| App-specific roles | Separate Web and Mobile role audiences and memberships | Separate Web and Mobile role audiences and memberships | SCIM v2 roles, app ID audience |
| Issuer | `https://localhost:9444/t/aurora.identity.test/oauth2/token` | `https://localhost:9444/t/brisa.identity.test/oauth2/token` | Tenant OIDC discovery / BFF |

All four OIDC clients are confidential server-side BFF clients configured with authorization code, mandatory PKCE, and per-app redirect URIs. The Mobile views are **responsive browser demos**, not native mobile-app production clients. Pairwise subject configuration was requested at registration; stronger sector-host/pairwise guarantees and cross-tenant linked identity remain separate, unverified work.

### User and role inventory: generated from your actual journals

Run `python3 scripts/ciam-identity-ops.py inventory --output docs/CIAM_V5_TENANT_INVENTORY.md`. This generates the exact per-tenant seeded user list and both Web/Mobile role tables from **your local** `identities/seed.json`, protected user/role journals, OIDC-app journal, and business-resource journal. It shows no passwords, token values, emails, or client secrets. Review the generated Markdown before any Git commit.

The six seed personas represent **nine distinct WSO2 accounts**:

| Persona | Aurora | Brisa | Purpose |
|---|---|---|---|
| Ana Costa (`ana.costa`) | Yes | Yes | Customer; create/read own requests |
| Rafael Nunes (`rafael.nunes`) | Yes | No | Tenant-scoped seeded persona; consult actual seed `type` and granted permissions |
| Marcos Oliveira (`marcos.oliveira`) | Yes | No | Seller; read/review/approve scope, approval gated by verified TOTP |
| Luiza Ferreira (`luiza.ferreira`) | Yes | Yes | Tenant-scoped seeded persona; consult actual seed `type` and grants |
| Pedro Reis (`pedro.reis`) | Yes | No | Tenant-scoped seeded persona; consult actual seed `type` and grants |
| Camila Lima (`camila.lima`) | Yes | Yes | Tenant-scoped seeded persona; consult actual seed `type` and grants |

**Do not confuse “same visible person” with shared credentials or tenant identity:** `ana.costa` in Aurora and `ana.costa` in Brisa have separate WSO2 user records and separately generated bootstrap passwords. Never move an access token from one tenant into another.

### Role families, their scope and their relationships

The original `CIAM Demo <Role Label> WEB/APP` roles are application-scoped **per tenant and per client**. The seed intentionally grants `ciam:profile:read` to customer roles and no operational API permissions to unsupported persona categories; check the generated inventory for exact labels, membership, and journal states.

Phase 4 creates separate `CIAM Business Customer WEB/APP`, `CIAM Business Seller WEB/APP`, `CIAM Business Administrator WEB/APP` roles **only in tenants with matching seeded members**, each audience-bound to the corresponding OIDC application's WSO2 app ID. It does not silently modify the older roles.

| Business role family | Actual WSO2 permission scopes | Effective BFF capabilities |
|---|---|---|
| Customer | `ciam:cases:create`, `ciam:cases:read` | Create/read own request(s) |
| Seller | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | Brand-wide review; approval requires fresh genuine TOTP |
| Administrator (business app role) | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | Brand-wide review; approval requires fresh TOTP; **not** Carbon or tenant administration |
| Other original demo roles | Depends on the real bootstrap seed, often none | No implied extra business privileges |

The BFF checks **granted access-token scopes**, not visual role names; a missing `roles` ID-token claim is not evidence that the WSO2 role assignment is missing. All four OIDC clients passed client-specific positive login/scope/profile/read and opposite-brand denial tests. A scope does not imply audience: the BFF separately demands the exact profile or business API resource audience.

## 4. End-to-end trust, data and API ownership

1. **Browser → BFF:** `/auth/{brand}-web/login` or `/auth/{brand}-mobile/login` invokes real authorization code + PKCE, tenant-correct issuer, state/nonce and callback validation; the browser gets an HttpOnly same-origin session cookie.
2. **BFF → WSO2:** `/api/identity/me` introspects the actual access token. It shows WSO2-granted scopes and only verified ID-token roles if released; it never invents an actor.
3. **Profile:** `/api/brands/{brand}/profile?client={client}` validates identity/client/tenant/profile audience and `ciam:profile:read`, calls the WSO2 OIDC UserInfo endpoint and enforces exact subject equality. `sub`-only UserInfo is a legitimate WSO2 release decision; name/email claims remain deferred.
4. **Requests:** `/api/brands/{brand}/cases?client={client}` requires an active token, correct client ID, tenant issuer, `urn:ciampoc:service-requests:v1` in `aud`, and action-specific scope. Customer reads are `OWNER_ONLY`; reviewers may receive `BRAND_REVIEW` within the same tenant.
5. **Mutations:** writes require CSRF and Origin/session protection. Business case creation persists append-only JSONL under `CIAM_BUSINESS_DATA_DIR` (outside Git); the case owner is bound to actual WSO2 issuer and subject. Approval additionally denies self-approval and requires the verified ID-token TOTP AMR and authentication time no older than 300 seconds. **Positive TOTP approval has not been proven.**
6. **Illustrative UI vs live operations:** static product cards and guided conceptual scenarios are demonstration design content, not WSO2 records. Identity/permission/consent/MFA success must never be simulated. Legacy `/api/experience/*` synthetic APIs remain blocked.

### Primary routes

| Route | Role | Source |
|---|---|---|
| `/`, `/lab`, `/experience` | Main guided Experience Center; six journeys and four WSO2 login choices | `live-experience-v5.*` and original design assets |
| `/portal/aurora/web`, `/portal/aurora/mobile` | Aurora Web/Mobile browser experiences | `aurora-web`, `aurora-app` |
| `/portal/brisa/web`, `/portal/brisa/mobile` | Brisa Web/Mobile browser experiences | `brisa-web`, `brisa-app` |
| `/portal/aurora`, `/portal/brisa` | Backward-compatible v3 brand portal | Client selector + protected BFF |
| `/api/identity/me` | Sanitized BFF session/token readback | WSO2 introspection |
| `/api/brands/{brand}/profile` | Protected live OIDC UserInfo | WSO2 |
| `/api/brands/{brand}/cases` | Protected persistent service requests | WSO2 authorization + private JSONL ledger |

## 5. Bootstrap lifecycle and private state

| Stage | Code | Evidence / private journal |
|---|---|---|
| Local server + persistent PostgreSQL | `server/setup.sh`, `server/render.py` | `private/deployment.toml`, admin password, database files |
| Carbon Super tenant creation | `tenants/provision.py` | `bootstrap-tenants-v10.private.json` |
| Tenant management clients + `ciam_*` users | `resources/bootstrap.py` | `bootstrap-resources-v10.private.json` |
| Four OIDC applications | `oidc/bootstrap.py` | `bootstrap-oidc-v10.private.json` |
| Profile API + app roles | `authority/bootstrap.py` | `bootstrap-authority-v10.private.json` (pinned `roleApiVersion=v2`) |
| Six personas / nine tenant accounts | `identities/bootstrap.py` | `bootstrap-identities-v10.private.json` |
| Business API + roles | `phase4/business-bootstrap.py` | `bootstrap-business-v4.private.json` |
| Audience compatibility readbacks | v4.4 and v5.1 guarded recovery scripts | Separate private OIDC backups/recovery journals; **not** fresh-lab installers |
| Lab UI + four websites | v5 installer + v5.2 visible-login patch | Local source files; no WSO2 writes |

Private file default root: `~/wso2-ciam-v10/private/`, permissions 0600 for secret journals. **Never commit or upload them.** Source control carries only code/manifests/docs. `carbon.super` bootstrap identity is not a substitute for tenant user management.

**Existing lab guardrails:** never run `fresh`, `docker compose down -v`, an old v8 script, or repeat a journaled `apply` just to check status. The real running IS 7.3.0 is bound to `https://localhost:9444`; the BFF listens on `http://127.0.0.1:4400`. Original port 9443 and other services remain separate.

## 6. Verified behavior versus planned capability

**Observed successful browser results (2026-10-28):** all four OIDC clients authenticated Ana with `ciam:profile:read`, `ciam:cases:create`, `ciam:cases:read`; each returned profile 200, cases 200 `OWNER_ONLY`, and a wrong-brand 403. Aurora Web: Ana created a real case (201) and read it back; Marcos read it as `BRAND_REVIEW` and received 403 on a customer-only creation; approval without fresh WSO2 TOTP received 403 `fresh_wso2_totp_required`. Case ID recorded in the acceptance report.

**Not claimed:** all six guided journeys are not complete WSO2 workflows; positive TOTP approval, TOTP enrollment, real B2B delegated organizations, consent preference persistence/revocation, real agent/token exchange, full profile attribute release, ID-token `roles` release, native mobile SDK behavior, and production Postgres/case-ledger durability are unverified or pending. Architecture diagrams and source manifests alone do not prove them.

Continue with [E2E testing guide](CIAM_V5_E2E_TESTING.md) and [generated inventory](CIAM_V5_TENANT_INVENTORY.md). For earlier evidence, see [2026-10-28 acceptance](CIAM_V10_ACCEPTANCE_2026-10-28.md).
