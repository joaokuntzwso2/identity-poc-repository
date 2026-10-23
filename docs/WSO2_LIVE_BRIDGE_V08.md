# WSO2 Identity Server Live Bridge v0.8 — truthful integration contract

## Scope, version and topology

Use WSO2 Identity Server **7.3.0 update level 18 or later**; this is NOT version `7.3.18`. WSO2's public Docker Hub image contains GA bits without Updates. Supply an entitled updated image, a digest and verified build provenance in an out-of-repo file. The attestation gate catches accidental downgrade but does not independently prove the running binary: verify container digest and effective update level before any live acceptance.

Keep four independent OIDC applications: Aurora Web/Mobile and Brisa Web/Mobile. Pairwise sector identifiers are scoped **per brand**, shared across web/mobile of that brand, disjoint across brands. A sector identifier URI MUST be HTTPS and must host JSON listing all authorized redirect URIs of its applications. Invoke `./wso2-lab.sh sectors` with final callback URLs, build and publish the sector JSON, then prove that WSO2 can retrieve it before `apply`.

**Hierarchy:** WSO2 `organizations` for delegated partner/seller B2B; these are not interchangeable with separate Carbon tenants. The public lab's two brand contexts do NOT automatically establish two actual isolated WSO2 tenants. Designing tenant-vs-organization topology is a separate architecture and acceptance gate.

## Bootstrap/run/reset (local)

1. Supply a licensed updated WSO2 image and `var/wso2/lab.env` (mode 0600). Provide `WSO2_ADMIN_USER`, `WSO2_ADMIN_PASSWORD`, an organization-management OAuth bearer `WSO2_ORG_API_TOKEN`, and a verified update attestation at `WSO2_BUILD_ATTESTATION_FILE` with `{ "release": "7.3.0", "update": 18, "imageDigest": "sha256:<64hex>" }`. Never commit these. Do not disable TLS verification; use `NODE_EXTRA_CA_CERTS` where needed.
2. `./wso2-lab.sh docker-up`. Confirm readiness via HTTPS and discovery, validate management API privileges.
3. Set `DEMO_PUBLIC_BASE_URL` to a public/reachable base matching real callbacks. The published BFF already implements `/auth/aurora-web/callback`, `/auth/aurora-app/callback` and corresponding Brisa routes. Set `DEMO_BFF_BASE_URL` to the BFF `PUBLIC_ORIGIN`. The React URLs (`DEMO_PUBLIC_BASE_URL`) are separate and are never registered as callbacks. Use `./wso2-lab.sh bff-env` to generate private OIDC config after applying resources. Publish sector JSON on reachable HTTPS and set `DEMO_SECTOR_BASE_URL` if needed.
4. `./wso2-lab.sh sectors`, `./experience.sh build`, `./wso2-lab.sh plan`. Inspect everything, including separate OIDC clients, callback URLs and scopes. `WSO2_LAB_CONFIRM=CREATE_SYNTHETIC_RESOURCES ./wso2-lab.sh apply` executes documented app/SCIM/org APIs and records owned resource IDs under `var/wso2/`.
5. Configure your genuine session-backed identity BFF with the generated private environment file `var/wso2/identity-bff.generated.env`, after verifying `WSO2_OIDC_ISSUER` matches live discovery. **Web browser/mobile simulator never receives client secrets.** App sign-in still requires wiring existing OIDC routes to these registered clients. Browser preview interactions do not magically become authenticated or trustworthy.
6. Start `./wso2-lab.sh operator` with `DEMO_RESET_OPERATOR_ENABLE=YES_LOCAL_ONLY`, long random `DEMO_RESET_OPERATOR_KEY`, WSO2 admin credentials and org bearer. Open `/wso2-lab.html`, enter the key and `RESET DEMO` to remove only resources recorded by this lab. The append-only evidence ledger is retained by archiving the old SQLite database before a fresh synthetic preview database is opened. This works only while the local preview API is running with the same operator key as the local operator process. If no WSO2 inventory exists, it rotates preview state only.
7. For command-line reset: `WSO2_LAB_CONFIRM=DELETE_LAB_OWNED_RESOURCES ./wso2-lab.sh reset`. If any DELETE fails, inventory remains with only unresolved resources and a nonzero exit code. Reset never destroys a WSO2 instance, root tenant, unrelated users, or unmanaged customers.

## Explicit gates still pending live proof

- WSO2 update level and deployment topology (tenant boundaries vs child orgs); actual pairwise token equality and cross-brand inequality, SSO, claims minimization.
- Verified OIDC authorization code + PKCE callback, nonce/state, TLS, key rollover, cookie/session controls, logout; no browser trust in synthetic persona selection.
- MFA, risk-based step-up, consent-revocation-to-authorization integration, external user stores, privileged admin assignment and org-level federation.
- Actor-aware RFC 8693 token exchange with delegated `act`, reduced scopes, RFC 7523 assertion anti-replay, workload grant; AI-agent identity and MCP API resources with actual WSO2 authorization APIs and issuer-generated tokens.
- Native-app flows (RFC 8252), CIBA, device authorization, FAPI, mTLS, PAR, DCR, SAML, VC/wallet flows as applicable. Performance, multiregion, uptime, service assurance, legal/security certificates, and supplier commitments need independent evidence.

## Official WSO2 references

- https://is.docs.wso2.com/en/latest/apis/application-rest-api/
- https://is.docs.wso2.com/en/latest/apis/scim2/
- https://is.docs.wso2.com/en/latest/apis/organization-apis/org-organization-mgt/
- https://is.docs.wso2.com/en/latest/guides/organization-management/organization-applications/
- https://is.docs.wso2.com/en/latest/guides/authorization/delegation/
- https://is.docs.wso2.com/en/latest/guides/agentic-ai/mcp/mcp-server-authorization/
- https://hub.docker.com/r/wso2/wso2is

## Reset environment setup

Start the preview server with the shared local operator key in its environment: `set -a; source var/wso2/lab.env; set +a; ./experience.sh dev`. In a second terminal run `./wso2-lab.sh operator`. The operator key is never displayed by the site and must be entered manually only by the operator. Reset archives append-only evidence rather than silently wiping it.
