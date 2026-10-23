# POC Login — technical presentation runbook (v0.1)

The suite below is **not yet customer-ready**. It is the exact presentation target and test checklist for the next implementation milestones. No scripted action may be represented as passed until an actual WSO2-issued verified result exists.

## Prerequisites (presentation day)

- WSO2 IS 7.3 server version and update level confirmed; products and management endpoints available; trusted certificates.
- Pairwise four-client configuration confirmed with admin screens. Two brands and two *different client IDs* per brand; user sharing/canonical link verified privately.
- At least two authorized synthetic people; per-brand login/consent/MFA policies; LDAP and corporate IdP seeded; Keycloak or corporate OIDC running per original project.
- Presenter account added to `OPERATOR_ALLOWLIST` via exact `iss|sub`; restricted APIs never available anonymously.
- Third tenant baseline absent; provisioning script validated separately and repeatable; negative tests prepared.
- Consent Management v2 support version verified and durable extension deployed (not current in-memory prototype); sensitive purpose policy approved.
- Actor-token delegation capabilities verified at pinned update >=7.3.0.18 and programmatic API evidence collection installed.
- No fake JWTs, static fixture claims, or scripts that force a passing result. All positive/negative outcomes must be observable via real network traffic and hashed evidence.

## 0. Executive story (4 minutes)

Open Experience Center. Explain: one private identity authority; sector-specific pseudonyms; least disclosure; delegated business and machine access; AWS Cloud as the potential deployment substrate. Show status screen and clarify measured vs planned outcomes.

## 1. Four-client pairwise sub (RFP §7.2.1, B-01/B-02) — 8 minutes

1. Open Aurora Web client using `/auth/aurora-web/login`. Authenticate Persona Ana using real WSO2. Show signed JWT metadata in Identity Inspector.
2. Repeat Aurora App (`/auth/aurora-app/login`), same synthetic person. Compare `sub` and `iss`.
3. Repeat Brisa Web/App with same underlying person via supported shared-identity architecture.
4. Assert intra-brand equality, cross-brand difference, canonical-person linkage, sector JSON body, actual backend JWKS validation, and Discovery `pairwise` advertisement.
5. Negative: try to reuse Aurora credentials/token to inspect Brisa’s PII; API denies cross-brand access.

If result differs, stop. Label `FAIL`, diagnose sector registration, issuer/organization sharing. Do not make client-side substitutions.

## 2. Minimization (RFP §7.2.2, B-09) — 4 minutes

Compare logged-in token claims with two client configurations and `userinfo`. Request extra PII from an unauthorized client; show absence in ID token, access token, and userinfo; capture signed proof. Distinguish protocol-required fields from personal attributes.

## 3. Step-up (RFP §7.2.3, C-03) — 6 minutes

Perform low-assurance login. Request sensitive action; enforce actual WSO2 policy requiring stronger ACR via MFA (TOTP or passkey). Show access denied before step-up, elevated `acr`/`amr` after re-authentication. Cancel/decline path must deny.

## 4. Consent isolation (RFP §7.2.4, D-01/D-07) — 6 minutes

Deny by default. Grant purpose-limited data-sharing consent from Aurora to Brisa. Check read authorization; revoke and retry -> denied; show tamper-evident persisted event history, policy version and actor trace. **Current in-memory prototype is not sufficient**, replace with durable audited implementation before buyer demo.

## 5. Token Exchange (RFP §7.2.5, A-05) — 6 minutes

Obtain `subject_token` and independent `actor_token` through legitimate grants. Exchange with WSO2 RFC8693. Inspect wire response `issued_token_type`, scope subset, signed JWT `sub`, `act.sub`, and token audience; invoke resource. Attempt unauthorized `admin.write`, untrusted client, wrong org; all denied.

## 6. Repositories (RFP §7.2.6, H-09) — 4 minutes

Authenticate WSO2 local user, then OpenLDAP `CORP` user, without replicated credentials. Deny unauthorized role. Disable LDAP briefly in staging and confirm local users remain serviceable; restore with runbook.

## 7. Onboard tenant (RFP §7.2.7, B-03/H-11) — 8 minutes

Start heartbeat from Aurora and Brisa; create third brand via idempotent WSO2 Management APIs, add distinct sector and 2 OAuth clients, policies/roles/consent purposes, then verify login. Display elapsed time, API-call count, restart count, and old-tenant health and subject unchanged. Roll back and rerun to prove reproducibility.

## 8. Broader B2C/B2B/M2M (RFP §7.3) — 8 minutes

B2C user login and profile update; B2B seller nested organizations and delegated admin; M2M Client Credentials with real token. Negative: seller token cannot affect another seller, M2M scope cannot escalate.

## 9. Performance (separate controlled PoC)

Run pre-approved `k6 run perf/m2m-token.js` in dedicated runner, with real HTTPS issuer and scoped M2M client. `RATE=1000 LOAD_STAGE=peak DURATION=10m` only after written test acceptance and capacity confirmation. Collect actual p95/p99, throughput, token DB strategy, DB metrics, CPU, 4xx/5xx, scaling and warm-up; distinguish token-issuance load from 2-hour cached-token reuse.

## 10. Optional differentiation

B2B sellers; customer service CIBA; kiosk Device Authorization; agent identity + MCP approval; assurance/provenance; Doorkeeper synthetic credential migration and 8,227-client migration manifest; refresh session policy. Any action not implemented must remain clearly marked pending, not claimed passed.
