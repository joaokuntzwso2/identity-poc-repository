# POC Login — WSO2 Identity Server 7.3 | Identity Experience Center

**Implementation milestone 1: working application source + security-tested backend, not the completed POC RFP.**

![Status](https://img.shields.io/badge/Live_WSO2_Proof-NOT_VERIFIED-orange) ![TenantArchitecture](https://img.shields.io/badge/Architecture_Gate-OPEN-orange)

This confidential companion project contains implemented React brand websites for Aurora and Brisa (web and mobile-style views) and is an **implementation increment** intended to be integrated with [demo-identity-advanced](https://github.com/joaokuntzwso2/demo-identity-advanced), not an unauthorized reproduction of its repository. The runtime in which the code was authored could retrieve individual GitHub source pages but could not clone GitHub, install React dependencies or run Docker. The original upstream WSO2 bootstrap, Keycloak, LDAP, business APIs and agents are **not included here**; keep them in place when integrating.

The customer RFP is the source of truth. The complete proposal blueprint is bundled at `docs/ORIGINAL_BLUEPRINT.md` and proposes patterns that need runtime validation. The RFP baseline includes **132 requirements** and seven scored demonstrations. See `docs/PAIRWISE_ARCHITECTURE_GATE.md`, `docs/DEMO_RUNBOOK.md`, `docs/IMPLEMENTATION_STATUS.md`.

## Architecture at a glance

```
Browser (http://localhost:5173 for LOCAL DEVELOPMENT)
     ├── React/TS dashboard, Aurora/Brisa web + mobile-style browser journeys
     ├── /auth, /api, /oidc sector documents (Vite proxy)
     ▼
Node.js Identity BFF (localhost:4100; no public browser tokens)
     ├── OIDC Discovery -> WSO2 Identity Server 7.3.0 (+ vendor-confirmed update level)
     ├── Authorization Code+PKCE S256 / OIDC state and nonce
     ├── Verification of RSA ID Token signature against issuer JWKS
     ├── Four-client subject predicate on REAL verified ID tokens
     ├── Consent event prototype (EPHEMERAL, NOT D-01 compliance)
     └── Operator-gated M2M token endpoint request (token remains server-side)

Existing upstream demo stack remains independently deployed:
WSO2 IS 7.3 + Keycloak / OpenLDAP + original Bootstrap + protected API + agents
```

### Port coordination with the original repo

- Original demo usually serves UI on **3000**, protected API on **4000**, WSO2 on **9443**.
- This companion uses Vite experience center on **5173** and BFF on **4100**, avoiding direct port conflicts.
- The BFF requires CA-TRUSTED HTTPS to reach WSO2, even for the local demo; import your test CA with `NODE_EXTRA_CA_CERTS` if needed. **Never disable hostname/TLS verification.**

## Get started (Node.js 22+)

1. Clone the original repo to a sibling folder on your development machine, start its supported Docker environment, and verify WSO2: `./demo.sh up`, then `./demo.sh smoke`.
2. Unzip this project into its own sibling directory, not on top of the original Compose file.
3. `cp .env.example .env` and set `OIDC_ISSUER` to the actual WSO2 Discovery `issuer`, `PUBLIC_ORIGIN=http://localhost:5173`, and the **four real registered WSO2 client IDs**. If the four applications have independent issuers, populate each `OIDC_<BRAND>_<CHANNEL>_ISSUER` instead. Register all callbacks exactly as below.
4. Verify WSO2's actual pairwise sector/tenant behavior using `docs/PAIRWISE_ARCHITECTURE_GATE.md`. Only configure HTTPS sector documents in the evaluation environment; local HTTP is a development-only preview, not buyer proof.
5. Set trusted Node CA: `export NODE_EXTRA_CA_CERTS=/absolute/path/to/your-local-wso2-ca.pem` if your issuer uses a test CA. Use a publicly trusted certificate on AWS.
6. `npm install --no-audit --no-fund` (requires network-enabled npm registry).
7. Terminal A: `set -a && source .env && set +a && npm run start:bff`.
8. Terminal B: `npm run dev`.
9. Open **http://localhost:5173**. Click Aurora Web/App and Brisa Web/App — these open actual WSO2 Authorization Code+PKCE login flows; no synthetic JWTs are generated.
10. Execute `npm test`, `npm run check`, `node scripts/verify-oidc.mjs`, and view Identity Inspector. Supply operator allowlist only after actual validated login; M2M runs only for authorized operators.

**If dependencies cannot be installed:** BFF has a self-contained readable status/dashboard preview at **http://localhost:4100/app/**. To use this route, set `PUBLIC_ORIGIN=http://localhost:4100` and adjust the four callback URIs. This fallback is not the React experience.

### Required WSO2 registrations

| Client | Callback for Vite local development | Sector URI (HTTPS in final) |
|---|---|---|
| `aurora-web` | `http://localhost:5173/auth/aurora-web/callback` | `https://<approved-host>/oidc/sector/aurora.json` |
| `aurora-app` | `http://localhost:5173/auth/aurora-app/callback` | identical to Aurora Web |
| `brisa-web` | `http://localhost:5173/auth/brisa-web/callback` | `https://<approved-host>/oidc/sector/brisa.json` |
| `brisa-app` | `http://localhost:5173/auth/brisa-app/callback` | identical to Brisa Web |

All four are independent client registrations and must be set to **Pairwise** under User Attributes. RFP requires identical `sub` within a brand and distinct across brands **for the same canonical person**, validated against real signed tokens. The `app` channel is **browser-based mobile-style emulation**, *not* a shipping iOS/Android native SDK.

### Container companion

`cp .env.example .env && docker compose up -d --build` starts the companion BFF/Vite only. It does **not** start WSO2, Keycloak, LDAP, run the original bootstrap, or provision any brand automatically. A Dockerized BFF needs a network-reachable WSO2 hostname matching the actual TLS certificate and advertised `issuer`; `https://localhost:9443` inside a container resolves to the container itself. For local upstream WSO2 self-signed certs, prefer Node host execution with an imported CA; for integrated Compose choose a trusted internal DNS name and consistent issuer routing.

### Automated checks

```sh
npm test                              # 12 unit/security/HTTP tests
node scripts/preflight.mjs            # 13 mapped scenarios, 7 RFP demos required
node scripts/evidence-report.mjs      # writes NOT_VERIFIED baseline for 132 rows
node scripts/secure-config-check.mjs  # rejects TLS-off config in source
node scripts/verify-oidc.mjs          # requires configured reachable REAL issuer
node scripts/inspect-wso2-registrations.mjs # optional read-only application Management API inventory
```

`node scripts/load-requirements.mjs /path/to/rfp_requirements_extracted.json` regenerates the private 132-row traceability from the customer's original workbook-derived export. The current archive already includes `config/rfp-132-traceability.json`.

## How the implementation enforces security

- Node backend is the OAuth client; tokens remain server-side in an ephemeral memory session; browser receives only HttpOnly SameSite cookie.
- Authorization uses state, PKCE S256, nonce, and strict issuer/audience/expiry/issued-at claims; verifies **RS256/RS384/RS512** using discovered JWKS. Discovery issuer must match exactly.
- M2M token response contains only non-reusable metadata and access-token hash fingerprint; requires a logged-in operator explicitly allowlisted by `iss|sub` and matching CSRF + origin.
- Consent prototype requires a logged-in subject, deny-by-default directional decisions, event hash chain, validated purpose/client/brand. It is **not durable** and not suitable for production LGPD consent retention.
- No default WSO2 credentials; no `-k` or TLS bypass; no mock OIDC login responses, demo-specific fake subjects or static pass indicators.
- **Not production-ready** until shared session store, external service authentication, full CSP and security review, backups, durable consent, cross-brand identity resolution, and role authorization are completed.

## Limitations and current status

Current source includes a polished React portal (`apps/experience-center/src`) but the npm dependency build was not executable in this restricted environment; TypeScript/TSX transpilation syntax checks completed. The local BFF and fallback HTML were served and exercised with curl. Browser screenshot was attempted but blocked by the execution environment. The WSO2 runtime is **not present** here and the live four-token predicate has **not** been validated. Token Exchange actor flow, multi-org provisioning, actual LDAP identity test, CIBA/agent, assurance, migration and AWS installation are additional implementation milestones; the code deliberately labels them as pending.

Do not submit this repository as complete RFP proof. The main branch should only contain documented real evidence. See `docs/IMPLEMENTATION_STATUS.md` for an exact delivered/pending register.

## AWS handoff

See `docs/AWS_HANDOFF.md`. The AWS target is isolated `sa-east-1` EKS, RDS PostgreSQL Multi-AZ, ACM, Route53, ALB, WAF, Secrets Manager, observability and performance runner, with WSO2 7.3 support/update provenance checked. **The actual IaC is not part of this increment.**

## Confidentiality

The POC questionnaire, sizing data, accepted documents and all test evidence are customer-confidential. Keep repository **private**, seed only synthetic identifiers, and never distribute to public showcase/marketing.

## Official technical sources

- Pairwise Sector Identifier: <https://is.docs.wso2.com/en/latest/guides/authentication/user-attributes/enable-attributes-for-oidc-app/>
- OIDC Authorization Code/PKCE: <https://is.docs.wso2.com/en/latest/guides/authentication/oidc/>
- Application Management APIs: <https://is.docs.wso2.com/en/latest/apis/application-rest-api/>
- WSO2 Configuration Catalog (OIDC Discovery paths): <https://is.docs.wso2.com/en/latest/references/configuration-catalog/>

## v0.2 security hardening addendum

See [`docs/V02_SECURITY_ENHANCEMENTS.md`](docs/V02_SECURITY_ENHANCEMENTS.md). Login sessions now rotate, issuer endpoints are checked against trusted origins, and the ephemeral consent prototype is **disabled by default** (`ENABLE_EPHEMERAL_CONSENT=false`). Consent operations require login to the selected originating brand client. The acceptance result still requires the same person's signed tokens from actual WSO2, and canonical-person linkage remains **NOT_VERIFIED**. The BFF remains single-process and is **not** a multi-replica AWS-ready session implementation.
