# CIAM P0 — WSO2-authoritative enforcement

## Scope and operational warning

This patch **does not** claim completion of RBAC provisioning or Consent Management v2. It establishes a fail-closed live runtime, adds live WSO2 access-token introspection, denies all fixture-backed/locally consented actions, and prepares a protected API scope gate. It is deliberately a **security foundation**, not the full P0 acceptance sign-off.

The code changes only the Git checkout. The running port-4400 BFF will not change until restarted through the existing v10 command. Keep the legacy port-4000 H2 lab untouched. Private credentials, tokens, and journals must never be committed.

## Enforcement model

- `IDENTITY_MODE=live-wso2` disables fixture-backed `/api/experience`, `/api/retail`, `/api/scenarios`, the local `/api/consent` ledger and `/api/identity/consent` PostgreSQL repository, synthetic `/api/session` and operator-only token demonstrations. They respond with 503, `allowed:false`, and no fallback.
- The live landing page replaces the synthetic Experience Center. All four OIDC login links remain accessible.
- The BFF retains access tokens in its **server-side in-memory session** following authorization-code + PKCE exchange; it never sends them to the browser.
- `/api/identity/me` queries the **tenant-pinned WSO2 introspection endpoint on every authenticated read**. An unavailable introspection API returns 503 and `authenticated:false`; revoked tokens are not reported as authenticated.
- Reported `permissions` are scoped values returned by WSO2 introspection with the `ciam:` prefix. There are no locally manufactured permissions or operator roles.
- `/api/protected/profile?client=aurora-web` requires a WSO2-active access token, client binding, a configured `WSO2_BUSINESS_API_AUDIENCE`, and the exact `ciam:profile:read` scope. Without all of them it returns 401, 403 or 503. This is a protected **metadata-only** endpoint, not a simulated customer profile.
- Revocations invalidate subsequent checks **only if WSO2 introspection reports the token inactive**. Role removal does **not necessarily invalidate an already issued token**; require short token lifetimes and a real revocation/session policy before claiming immediate role-revocation enforcement.

## Required WSO2 configuration

WSO2 client-credentials introspection must be explicitly enabled for the RP and tested against the running server (or replaced by a dedicated least-privileged introspection client). See https://is.docs.wso2.com/en/7.1.0/guides/authentication/oidc/token-validation-resource-server/ . No super-admin secrets should be injected into the BFF.

Existing v10 OIDC apps request `openid` only. Therefore `/api/protected/profile` **correctly denies** until the business API resource `ciam-api` and `ciam:profile:read` permission are created in WSO2, authorized to the correct OIDC clients, user roles assigned, and the login requests updated to include the scope. This is next-stage bootstrap work, not performed by this source-only patch.

The `WSO2_BUSINESS_API_AUDIENCE` runtime environment variable must exactly match WSO2's introspection audience for that API. Do **not** disable the audience check to make a test pass.

## Consent blocking prerequisite

WSO2 Consent Management v2 requires 7.3.0 update level >= 12 and `[consent_mgt] enable_v2_api = true`; the Docker image tag `wso2/wso2is:7.3.0` alone does not prove that capability is installed. See https://is.docs.wso2.com/en/latest/guides/consent-management/ . Grant/inspect/update/revoke/re-consent cannot be represented as working until the actual v2 API schema, issuer scopes and audit enforcement are verified live. In live mode the previous ConsentLedger and DurableConsentRepository endpoints are disabled; they cannot grant or check consent.

A future consent adapter must resolve only the **current tenant subject and client** from server-side validated credentials; must never use a same-name cross-tenant identity join; and must re-read WSO2 on each protected operation, failing closed when absent/revoked/unavailable. Re-consent requires a fresh WSO2-mediated decision, not a local Boolean.

## Security acceptance checklist

1. `node --test services/identity-bff/test/wso2-authority.test.js` (offline tests).
2. `node --check services/identity-bff/src/server.js` (syntax).
3. Restart the **v10** BFF only, using repository entrypoint after verifying no duplicate BFF process. No Docker restart.
4. Anonymous `/api/identity/me` returns `authenticated:false`. Live synthetic `/api/consent`, `/api/identity/consent/check`, `/api/scenarios`, `/api/retail/*` return 503.
5. Complete Aurora OIDC login and observe `/api/identity/me`; if the introspection endpoint is unavailable, **503 is the correct secure result**, not a bug to bypass.
6. Once WSO2 introspection, API scopes and roles are configured, demonstrate protected endpoint 200 for permitted user and 403 for unpermitted user **without local overrides**.
7. Turn off WSO2 temporarily only in a disposable test deployment; protected access and identity must fail closed. Never restart, remove or recreate the original H2-backed container.
8. Cross-brand consent, partner admin, delegation and synthetic Experience Center pages remain **unavailable** until separately implemented and live-verified.

## Deploy sequence

- Dry-run installation; apply source patch; run offline tests and publication scan; commit source files only.
- Add the WSO2 API-resource, role and OIDC-scope provisioning stage with write-ahead journals and API readback. It must run via the project bootstrap, not manual Console operation.
- Configure an introspection-capable least-privileged RP credential, `WSO2_BUSINESS_API_AUDIENCE`, then restart only the v10 BFF.
- Upgrade WSO2 to a supported Consent v2 update level via a tested persistent-server upgrade path, probe the exact self-service consent API and implement the adapter. Do not assume base image support.
