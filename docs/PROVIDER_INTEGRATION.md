# Identity provider boundary — operational contract (v0.7)

## Trust boundaries

**UI:** React applications are presentation and untrusted browser contexts. Browser personas are merely test fixtures, not authenticated users.

**Identity BFF:** owns provider adapters, OIDC authorization-code+PKCE, session cookies, issuer/audience/nonce verification, JWKS trust and future login/token endpoints. Existing BFF code is not replaced by this package. The new module currently provides a strict interface, status and read-only metadata verification only. Login/exchange/provision functions raise `503` rather than minting fake tokens.

**Local extensions:** fictional customer and commerce data, consent ledger, attribute assurance and B2B fixtures. Local persistence is not WSO2 consent storage, and its canonical-correlation boundary must be validated before use with a real user.

**WSO2 IS 7.3:** future identity authority; NOT running in this repository by default.

## Runtime mode contract

- `IDENTITY_MODE=story-preview` (default): local synthetic service can run, provider status says not verified.
- `IDENTITY_MODE=offline-contract`: used by `./provider.sh test`; all adapter auth/issuance methods reject. No server is started by the contract runner.
- `IDENTITY_MODE=live-wso2`: opt-in config and read-only discovery verification. **Do not run the synthetic `./experience.sh dev` server in live mode.** It refuses to start in non-preview modes. Live BFF login wiring requires subsequent controlled implementation.

The React readiness page's mode picker is **read-only explanatory UI** and cannot switch backend modes.

## Configuration and ownership

Configure privately (e.g. environment loaded in the shell). Required keys:

```text
IDENTITY_MODE=live-wso2
WSO2_INTEGRATION_ACK=yes
WSO2_OIDC_ISSUER=https://idp.example
WSO2_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration
WSO2_CLIENT_AURORA_WEB_ID=<registered client id>
WSO2_CLIENT_AURORA_MOBILE_ID=<registered client id>
WSO2_CLIENT_BRISA_WEB_ID=<registered client id>
WSO2_CLIENT_BRISA_MOBILE_ID=<registered client id>
WSO2_BUILD_ATTESTATION_FILE=/absolute/private/path/to/build-attestation.json
```

Keep all client secrets, private keys, credentials and live URLs in an approved private secret store. Do not add them to React environment variables (`VITE_*`), the public README, staged Git changes or frontend bundles. The attestation JSON is a private operator assertion with shape:

```json
{"release":"7.3.0","update":18}
```

Attestation alone does **not** prove product behavior or update installation. Version/update must be independently verified against the installed runtime and support entitlement.

Use `WSO2_DEV_ALLOW_LOCAL_HTTP=true` only with **loopback** `localhost` or `127.0.0.1` when explicitly needed for local testing. Production issuer and endpoints require HTTPS. The adapter checks endpoint origin, rejects untrusted redirects, requires the metadata's `issuer` to match the pinned value, and does not accept caller-supplied URLs.

## Commands

```bash
./provider.sh status                    # no outbound traffic
./provider.sh test                      # 11+ offline boundary/security tests
./provider.sh check                     # offline tests + privacy stage gate
./provider.sh build                     # production UI build
./provider.sh dev                       # story preview only
./provider.sh verify                    # REAL read-only discovery (must opt in)
```

`verify` writes a private local report at `var/provider-readiness.json` with an issuer **fingerprint**, metadata verification and an explicit `liveAcceptance: NOT_VERIFIED`. The `var/` directory must remain ignored. Discovery is not a signature verification of a token and does not prove multi-brand SSO, pairwise `sub`, consent isolation, MFA, or SLA.

## WSO2 7.3 specific integration gates

| Gate | Required evidence | State |
| --- | --- | --- |
| Product build and support entitlement | Real build number/update level | Pending |
| Four independent clients | Aurora Web/Mobile + Brisa Web/Mobile | Pending |
| Same-brand pairwise `sub` | Live signed tokens with proper sector identifiers | Pending |
| Different-brand pairwise `sub` | Live signed tokens for same canonical identity | Pending |
| Cross-domain SSO | Cookie/session analysis on real brand domains | Pending |
| Consent v2 | Requires WSO2 IS 7.3.0 update **12+** per documentation | Pending |
| Actor-aware delegation | Verify WSO2 update/support and true downstream `act` + scope attenuation | Pending |
| Token Exchange | Actual RFC 8693 request, issued token verification, denied escalation | Pending |
| B2B | Federation with distinct sub-organizations, delegated administration | Pending |
| Assurance | Attribute-level provenance and partial update behavior | Pending |
| Performance and resilience | Reproducible measured evidence | Pending |

**Topology remains an architecture decision**, not an assumption: do not treat WSO2 root tenants and organizations as interchangeable. Validate first-class tenant isolation, canonical identity, sectors, cookies, and consent together before importing real users or declaring a requirement met.

### Further integration contract

Implement real login only by extending the existing `services/identity-bff/src/server.js` (or its current replacement) after inspecting live redirect URI registration, issuer/audience values, browser domain policy, nonce/state, PKCE, session storage and cookie security. Do **not** route real OAuth callbacks through `services/experience-api/server.mjs`.

Separate the eventual provider calls into explicit methods: `discover`, `beginAuthorization`, `handleCallback`, `getSession`, `logout`, `exchangeToken`, `manageOrganization` and `revokeSession`. Each implementation must collect source-correlated, timestamped evidence before acceptance. The v0.7 adapter intentionally implements only `discover` and throws for all real stateful identity actions.

## Official references

- WSO2 OIDC flows: https://is.docs.wso2.com/en/latest/guides/authentication/oidc/
- WSO2 consent management (update dependency): https://is.docs.wso2.com/en/latest/guides/consent-management/
- Token Exchange: https://is.docs.wso2.com/en/next/guides/authentication/configure-token-exchange/
- WSO2 release overview: https://is.docs.wso2.com/en/latest/references/about-this-release/

Verify these references and update-level requirements against the exact vendor-supported 7.3.0 release you install. No external claims are counted as local test evidence.
