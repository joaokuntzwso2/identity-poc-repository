# CIAM v10 — scenario / evidence matrix

Statuses describe the **26 Oct 2026 operator evidence**, not claims independently reproduced by CI. `RESOURCE_VERIFIED` means an object was read back, not a validated user journey.

| Scenario | Existing evidence | Acceptance still required |
| --- | --- | --- |
| Aurora Web OIDC | **LIVE_LOGIN_OBSERVED**: BFF reported `WSO2_SIGNED_ID_TOKEN` and signed-token evidence | Repeat in automation; prove issuer, nonce, audience, expiration, signature, PKCE callback replay denial |
| Aurora mobile browser preview | RESOURCE_VERIFIED | Real `aurora-app` browser callback with `ciam_aurora`; check BFF proof; distinguish from native mobile SDK flows |
| Brisa Web | RESOURCE_VERIFIED | Real Brisa user login and signed BFF session |
| Brisa mobile browser preview | RESOURCE_VERIFIED | Real `brisa-app` browser callback |
| Tenant isolation | Two root tenants and distinct issuers verified | Negative cross-tenant issuer, audience, client binding and management API denial tests |
| Pairwise subjects | Pairwise setting requested; no HTTPS sector documents in v10 | Same-user Web/App comparison within each brand; across-brand privacy cannot be inferred only from different issuers or subject fingerprints; require a supported cross-RP matching experiment with explicit lawful mapping |
| Cross-tenant SSO | NOT_VERIFIED | Test expected session continuity/non-continuity under explicitly defined policy; independent tenant login is not proof of SSO |
| Session/CSRF | BFF sessions and CSRF controls in code | Expired state, replayed callback, mismatched nonce, logout and CSRF failure cases; never expose raw tokens |
| Account recovery, MFA, step-up | NOT_VERIFIED | Real enrolled factor, credential update, lockout and recovery acceptance through WSO2 |
| Consent lifecycle | Synthetic/extension contracts | Durable WSO2-integrated consent records, purpose-bound enforcement, revoke and audit |
| B2B delegation and partner admin | Synthetic | Independent organization RBAC, delegation limits, tenant-scoped admin API and denial evidence |
| Federation | NOT_VERIFIED | External IdP trust, account linking and issuer validation |
| M2M least privilege | Two management tokens with authorized scopes verified | Negative calls outside each scope, rotation, revocation, expiry and audit |
| Agent / RFC 8693 delegation | Synthetic demo | Real signed actor/sub delegation and resource-server enforcement |
| Persistent operations | Three PostgreSQL DB schemas, container active | Backup **and tested restore**, restart recovery, upgrade migration, durable sessions, failure injection, performance/load |
| Fresh deployment from Git alone | Offline scripts tested, staged runtime deployed incrementally | Execute `fresh` + `bootstrap` + four browser logins on a second empty machine with no manual Console edits; inspect all guard paths |

## Suggested automated acceptance progression

1. **Offline:** `./scripts/ciam-v10.sh test`; BFF tests; publication/secret guard; file safety and idempotence regressions.
2. **Read-only integration:** stage `status`, `bff-diagnose`, WSO2 tenant/app/SCIM readback, token actual-scope assertions; test running old server untouched.
3. **Browser:** isolate fresh cookie jars, complete each authorization-code/PKCE flow with separate tenant-user credentials, demand exact tenant issuer and BFF evidence, check session retention across four clients.
4. **Negative security:** callback without state, expired/replayed state, wrong client audience, mismatched issuer/JWKS, CSRF and Origin denials, unauthorized M2M scope, unknown app name collision, credential material in logs.
5. **Privacy:** fix desired sectors, verify within-brand continuity and across-brand non-linkability with controlled identities. Distinct root-tenant issuers **alone do not demonstrate a single user with pairwise subjects**.
6. **Recovery and operations:** simulate halfway API 200/201, timeout, interrupted journal, PID stale, Postgres restart, and a tested volume restore **in a throwaway isolated deployment**.

Keep each gate's evidence separate. Do not mark B2B, federation, consent, MFA, SSO or pairwise-subject privacy as accepted because the Aurora Web login succeeded.
