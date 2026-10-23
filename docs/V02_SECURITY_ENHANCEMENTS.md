# POC Login — v0.2 security and acceptance hardening

**Purpose:** make the existing v0.1 demonstration safer and its evidence less misleading. This is not a completed RFP PoC or WSO2 integration validation. The existing project and all customer artifacts must remain private.

## Code changes with paths

1. `services/identity-bff/src/session-store.js`: opaque sessions; rotate session ID/CSRF after verified login; delete session on local logout; `__Host-` cookie on HTTPS; deny new sessions when at capacity rather than evict active operators; expire stale sessions.
2. `services/identity-bff/src/oidc.js`: require approved TLS endpoint origins from discovery, including JWKS; restrict arbitrary metadata endpoint redirects; support `OIDC_DISCOVERY_URLS_JSON` per issuer; reject critical/unsupported JOSE JWT headers; bound OIDC metadata body size.
3. `services/identity-bff/src/server.js`: do not allocate sessions on public health/discovery/sector endpoints; cap concurrent pending login states at eight per browser session; rotate on callback; correct local logout cookie deletion; consent decisions belong only to the authentication of the selected origin client; default-disable ephemeral consent unless explicitly opted in outside production; reject invalid actions, invalid purposes and malformed JSON safely.
4. `services/identity-bff/src/pairwise.js`: require issuer continuity within each brand and do not claim canonical-person proof from pairwise subjects alone. Separate issuers across brands are not automatically disallowed.
5. `apps/experience-center/src/main.tsx`: disable prototype consent controls unless enabled and the corresponding brand's web client is authenticated. Explain why this is not LGPD or WSO2 v2 evidence.
6. `services/identity-bff/test/`: regression tests, including a real BFF Authorization Code+PKCE cycle verified with a signed **test-only** issuer fixture. The test fixture is not used by the demo runtime.

## Run after applying patch

```bash
cp .env.example .env            # only if you have not already created .env
npm test
npm run check
node scripts/secure-config-check.mjs
```

To run the optional local-only consent demonstration, set `ENABLE_EPHEMERAL_CONSENT=true` in `.env` and restart the BFF. **Never set this option in production or AWS.** Actual POC D-01/D-07 requires a durable, tenant-isolated consent model and appropriate WSO2 7.3 update level; consent management v2 is documented at update level >=7.3.0.12.

If the organization topology uses different issuer URLs, configure `OIDC_DISCOVERY_URLS_JSON` with an object keyed by the exact issuer URL. Keep OAuth authorization, token and JWKS endpoints on the issuer origin, or explicitly allow known HTTPS origins with `OIDC_TRUSTED_ENDPOINT_ORIGINS` after review.

## Live pairwise acceptance helper

After provisioning the **real** WSO2 four-client environment, building React, and installing Playwright Chromium:

```bash
npm install
npx playwright install chromium
# Start BFF and Vite separately; use the same HTTPS issuer and real client IDs.
CONFIRM_REAL_WSO2=yes E2E_BASE_URL=http://localhost:5173 npm run test:pairwise-live
```

This opens Chromium, prompts the presenter to authenticate the **same** synthetic customer four times, checks each login against the backend's cryptographically verified OIDC session, and writes **redacted** identifier-predicate evidence. It intentionally marks `canonicalPerson` and RFP B-01/B-02 as `NOT_VERIFIED` until independent cross-brand account-linkage proof and actual registered sector identifiers are shown.

## Remaining qualification blockers

- **B-01/B-02/B-03:** four real signed WSO2 tokens; proof of same canonical identity, correct sector/organization isolation, and production-equivalent sector URI configuration. Unit fixtures are *not* proof.
- **D-01/D-07:** durable, purpose-scoped, tenant-aware, auditable consent with real WSO2 Consent Management v2 integration and cross-brand linking policy. Current prototype is disabled by default.
- **A-05/G:** trusted delegated RFC 8693 Token Exchange with actual actor token, reduced scopes, `issued_token_type`, and protected resource enforcement.
- **C/F/E:** MFA step-up; security events; session and long-lived refresh token requirements are not built.
- **H:** WSO2 automation, third brand onboarding, migration and LDAP test evidence remain pending.
- **I/J/K:** contractual evidence; AWS HA/performance, multi-region design and operational compliance remain pending.
- **AWS:** BFF sessions remain local memory; multiple EKS replicas REQUIRE a shared server-side session backend (Redis-compatible or Postgres), coordinated secret management, external consent persistence, and operational controls. Deploying this v0.2 process unchanged as a multi-replica service is not correct.

## Product references

- https://is.docs.wso2.com/en/latest/guides/authentication/user-attributes/enable-attributes-for-oidc-app/
- https://is.docs.wso2.com/en/latest/guides/consent-management/

**Validation recorded:** v0.2 automated Node tests passed locally. React dependency build, Docker stack, production TLS, WSO2 7.3 topology and AWS deployment were not executed in this environment.
