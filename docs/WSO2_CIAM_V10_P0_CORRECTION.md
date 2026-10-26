# Isolated v10 WSO2 CIAM P0 corrective runbook

Updated: 2026-10-26. This document applies **only** to the isolated v10 instance at `https://localhost:9444` and BFF `http://127.0.0.1:4400`. Never use bootstrap/fresh on the existing v10 runtime, never touch `wso2-identity-server-1` (9443), do not reset the PostgreSQL volumes, and do not recreate tenants, users, OIDC applications, or management credentials.

## Evidence classification and limits

- The source patch here is a **corrective candidate**, not an already accepted live implementation. The corrective patch was constructed from public remote `main` files; the remote HEAD SHA could not be fetched through a direct Git connection in the authoring environment. Check the exact SHA locally before applying.
- In the previously recorded GET-only preflight, both API-resource catalogs responded `200`, while tenant-qualified Basic on Roles v3 and Consent v2 returned `401`. **401 does not prove that the endpoint is unsupported**; distinguish credential format, tenant context, REST API privilege, OAuth scope, access policy, route, and update-level activation.
- The repo-backed provisioner intentionally never mutates existing management M2M clients. Any expansion of management privileges must be a separate, verified, least-privilege change; this P0 stage uses the existing tenant-qualified administrator credentials, never the Console's unqualified login name for tenant APIs.
- `consent-apply` is intentionally **BLOCKED** and has no write implementation: do not create a fake consent receipt, database, or approval just to satisfy a unit test.

## Architecture and trust boundaries

Browser -> BFF session/OIDC authorization code + PKCE -> WSO2 `9444` tenant OIDC -> JWT ID-token signature/issuer/audience/nonce validation -> secure server-side session. The ID token establishes authentication **only**. `GET /api/protected/profile?client=aurora-web` is an identity-safe demonstration: BFF introspects the tenant client's **access token at each request** with OAuth client credentials, requires active, expiry, issuer if returned, client ID, API audience, and `ciam:profile:read`. It returns metadata, **not a fabricated identity profile**. All synthetic persona, retail, delegated operator and consent endpoints return denial in live mode. The 9443 container never participates.

The new stage `deploy/ciam-v10/authority/bootstrap.py` registers each tenant's *own* business API (`https://api.ciam-v10.test/profile`), scope `ciam:profile:read`, authorizes only the tenant's two **preexisting** OIDC clients (Web and App), and provisions an application-audience profile reader role for each client bound to that tenant's existing SCIM user. It refuses to adopt unjournaled resources. It records a random ownership marker before API creation, records POST-in-flight state before each write, verifies authoritative readback, and blocks retries if a network result is ambiguous. Missing grants after prior verification are treated as revocations and are **not automatically restored**.

WSO2 Roles v3 permission/readback support and the exact `POST /scim2/v3/Roles` grant shape must be confirmed on this installation before authorizing writes. If it returns HTTP 401/403/404, **stop**. Do not switch silently to deprecated Roles v1/v2 or invent role assignments. Existing tenant-management M2M privileges are deliberately unchanged.

## Deployment from the existing checkout

```
cd "$(git rev-parse --show-toplevel)"
pwd
git status --short
git branch --show-current
git rev-parse HEAD
git fetch origin main
git pull --ff-only origin main
# Download artifact from this answer to a temporary location, then extract
# archive into THIS checkout. It contains only tracked candidate source files.
unzip -n /path/to/ciam-p0-correction.zip -d .
python3 tools/install-p0-correction.py           # source-only dry-run
python3 tools/install-p0-correction.py --apply   # guarded exact-match source edits
python3 -m compileall -q deploy/ciam-v10
node --check services/identity-bff/src/server.js
node --check services/identity-bff/src/wso2-private.js
node --check services/identity-bff/src/live-wso2-ui.js
git diff --check
./scripts/ciam-v10.sh help
./scripts/ciam-v10.sh test
node --test services/identity-bff/test/wso2-authority.test.js services/identity-bff/test/wso2-authority-negative-p0.test.js
```

After extraction and source patching, do **not** run `fresh`, `bootstrap`, `server/setup.sh`, `tenants/provision.py apply`, `resources/bootstrap.py apply`, or OIDC app creation against the existing runtime. They are not upgrade commands.

## Consolidated privacy-safe diagnostic (do this once)

The following is a **single command** that produces a sanitized report from the repository-owned CLI. It does not include passwords, cookies, access tokens or SCIM/tenant IDs:

```
./scripts/ciam-v10.sh authority-evidence
```

It probes tenant-qualified vs unqualified Basic for API resources, Roles v3, Roles v2, and Consent v2. It also attempts tenant-bound OAuth client-credentials acquisition of read-only Roles/Consent scopes (POST to `/oauth2/token` is not a management write), probes their GET APIs only if authorized, and returns sanitized activation/online status for **only** `wso2-ciam-v10-is-1`. Token values are never printed. This helps classify 401; it cannot alone prove exact installed update level or cause a privilege grant. For strictly GET-only preflight use `./scripts/ciam-v10.sh authority-preflight`. To confirm container update provenance and consent activation without exposing `deployment.toml`, run the read-only commands in the next section. Keep private credentials and raw Docker logs out of pasted evidence.

## Read-only version/update/feature verification

```
# Only inspect NEW v10 container, never wso2-identity-server-1.
docker inspect -f 'name={{.Name}} running={{.State.Running}} image={{.Config.Image}}' wso2-ciam-v10-is-1
# The authority-evidence command in the preceding section checks the exact
# consent configuration setting without printing deployment.toml or secrets.
# Image tag is NOT proof of update level. Ask product updater for verifiable
# update-level metadata for the running installation and record only the number.
./scripts/ciam-v10.sh consent-verify
./scripts/ciam-v10.sh consent-plan
```

WSO2 official requirements: **Identity Server 7.3.0 update level >= 12**, `[consent_mgt] enable_v2_api = true` and the documented Console flow scopes. Documentation: <https://is.docs.wso2.com/en/latest/guides/consent-management/>. The current v10 project pins image `wso2/wso2is:7.3.0`; this is **not** evidence of update level. For an unsupported image, do not try applying a consent API patch or a custom PostgreSQL schema to compensate.

Supported non-destructive update approach: 1) Record immutable container image digest, installed update-level manifest and effective `deployment.toml` settings; 2) obtain an officially supported IS 7.3 build updated to at least `7.3.0.12` through the WSO2 update mechanism (<https://updates.docs.wso2.com>); 3) follow **that build's official database migration/upgrade notes** and test a restore to a **separate cloned v10 environment** with backups of identity, shared and agent PostgreSQL databases plus the private v10 journals and config volume; 4) rehearse login, issuer and JDBC checks against the clone; 5) authorize a controlled cutover **only of the isolated v10 IS container/config**, retaining databases, IDs and passwords; 6) activate consent v2 with documented configuration, check authorized management and end-user APIs, and enable the real WSO2 consent adapter in a separate reviewed patch. No commands here delete or recreate Docker containers or databases. Do not blindly apply schema scripts or replace the `isconf` volume.

## Authorization plan and optional explicit apply

```
./scripts/ciam-v10.sh authorization-plan
./scripts/ciam-v10.sh authorization-reconcile
./scripts/ciam-v10.sh authority-status
```

All readbacks must be `200`; plan must say `safeToApply: true`, and every existing/absent resource must match the private journal. If Roles v3 or application GET is `401`, stop and correct that authentication/privilege issue first. Be aware WSO2 may require bearer tokens with `internal_role_mgt_view`, `internal_role_mgt_meta_update`, `internal_role_mgt_users_update`, and `internal_role_mgt_permissions_update`. Do not grant these to the two management M2M clients reflexively: their original least-privilege mandate is unchanged. The administrative action should use only an appropriately authorized, tenant-bound principal.

Once the GET-only plan and endpoint contract are verified, a responsible operator can **explicitly** issue:

```
WSO2_CIAM_V10_AUTHORITY_CONFIRM=AUTHORIZE_EXISTING_V10_OIDC_AND_ASSIGN_SCIM_USERS \
  ./scripts/ciam-v10.sh authorization-apply
./scripts/ciam-v10.sh authorization-reconcile
./scripts/ciam-v10.sh authority-status
```

The authoring environment has **not** invoked these commands. Do not attempt an automatic second apply if the first was interrupted: inspect the private 0600 journal through `authority-status` and the GET-only `authorization-reconcile` output first. If uncertain or different, stop for incident review.

New logged-in users must obtain **fresh** WSO2 access tokens *after* a verified authorization apply. The repository OIDC BFF bootstrap bridge sets `WSO2_BUSINESS_API_AUDIENCE` and adds the requested `ciam:profile:read` scope **only when the private authority journal is fully verified**. It never alters OIDC client registrations or secrets. An already running BFF will not pick up new env on its own. Schedule an authorized restart of **only** the v10 BFF after capturing current session impact, never restart the old WSO2 or recreate databases.

## Runtime acceptance

```
./scripts/ciam-v10.sh runtime-acceptance
./scripts/ciam-v10.sh bff-diagnose
```

The automated command uses **no login cookies** and checks a negative boundary: `/api/identity/me` unauthenticated; each of the four `/api/protected/profile` channels returns **401**; `/api/consent`, `/api/scenarios`, and synthetic retail routes return **503**, with no fallback. It cannot prove four browser logins, actual user grants, revocation or consent persistence.

Positive browser acceptance must be performed with each real tenant test user and the corresponding registered login link at `http://127.0.0.1:4400/`:

1. Sign in to Aurora Web; inspect sanitized `/api/identity/me` for `authenticated: true` and the real WSO2 issuer. Call `/api/protected/profile?client=aurora-web` **from the same BFF session** (the live frontend provides a per-channel probe). Require `200` only when WSO2 granted `ciam:profile:read` for the expected audience; `openid` alone must give `403`.
2. Repeat individually for Aurora App browser preview, Brisa Web and Brisa App browser preview. The old Aurora Web signed-ID-token observation is historical user evidence, **not** this patch's live acceptance.
3. Test cross-tenant keys: an Aurora-only authenticated BFF session cannot authorize `client=brisa-web`. Test expired, revoked, wrong-tenant and wrong-audience tokens. Never paste raw tokens or cookies.
4. In WSO2, remove/revoke the role or application API authorization using an approved **source-controlled** change procedure. Request a *new token* and confirm the required scope is absent and the API returns `403`. On an **old session**, check WSO2 introspection `active` and previously issued scopes: the old access token may continue to authorize until its expiry or explicit revocation; record this as a token lifetime limitation, not as passed immediate revocation. Explicitly revoke the old token where supported and verify a `401`. Bootstrap reconciliation should report removed grants and never self-heal them.
5. With consent v2 **actually installed and configured**, create purpose/policy/preference data via documented WSO2 APIs and Flow Builder, accept as test user, verify using the authorized WSO2 user-consent/My Account APIs, revoke, and repeat a consent-dependent operation from the **same** BFF session. Until an implementation has verified this check, the action remains disabled (`503`) and is **BLOCKED**; there is no local consent ledger fallback.
6. During an authorized outage test of **only** the v10 identity service, protected requests from existing BFF sessions must return `503` (outage), `401` (token inactive) or `403` (authorization denied), **never `200`**. Do **not** stop 9443 or destroy volumes. Avoid an outage if the valuable v10 runtime is in active use.

## Security publication gate and additive commit

```
git status --short
git diff --check
python3 scripts/security/check_public.py --staged  # after git add below
# Stage ONLY the reviewed source files. Never `git add -A`.
git add README.md docs/WSO2_CIAM_V10_P0_CORRECTION.md \
  deploy/ciam-v10/authority/ deploy/ciam-v10/cli.py \
  deploy/ciam-v10/oidc/bootstrap.py deploy/ciam-v10/resources/bootstrap.py \
  services/identity-bff/src/server.js services/identity-bff/src/wso2-private.js \
  services/identity-bff/src/live-wso2.html services/identity-bff/src/live-wso2-ui.js \
  services/identity-bff/test/wso2-authority-negative-p0.test.js \
  tools/install-p0-correction.py
git diff --cached --check
python3 scripts/security/check_public.py --staged
git diff --cached --stat
git commit -m "fix(ciam-v10): guard WSO2 business API authorization and fail closed on unverified consent"
git push origin main
```

Do not commit `~/wso2-ciam-v10/`, `var/`, credentials, access tokens, private journals, raw evidence, database exports, certs or temporary containers. Confirm the security check exists in your checkout. A new commit is preferred; no force push.

## P0 acceptance matrix (authoring-environment evidence)

| Requirement | Status | Evidence / gap |
| --- | --- | --- |
| P0 #1 synthetic identity/consent/retail forbidden in live mode | TESTED_OFFLINE (pending repository test run) | Existing live route guard, new negative tests; no live outage evidence |
| P0 #1 four OIDC browser channels | BLOCKED | Four registered, only historical Aurora Web browser result supplied; three channels not exercised here |
| P0 #2 business API + roles + user assignment | TESTED_OFFLINE (pending integrated tests) | Guarded writer and readback contract tests; Roles v3 GET 401 unresolved, zero authorized writes by this patch |
| P0 #2 protected endpoint issuer/aud/expiry/client/tenant/scope | TESTED_OFFLINE (pending integrated tests) | WSO2 introspection per request; cannot assert real scope issuance or role-revocation behavior without live tokens |
| P0 #3 purposes, policy, preferences, attribute consent, storage/revoke | BLOCKED | Installed update level and v2 activation not proven; real adapter and persistent grant flow intentionally not implemented |
| Existing PostgreSQL / tenants / OIDC apps / 9443 | NOT MODIFIED by patch | Source-only artifact; new authority journal written only after explicit apply |

No `VERIFIED_LIVE` entry is warranted from this authoring environment. Update this matrix only after collecting scoped, sanitized real acceptance evidence.
