<!-- CIAM_V5_CURRENT_ARCHITECTURE_START -->
# Identity Experience Center — WSO2 IS 7.3 live CIAM lab

**Current implementation:** guided Experience Center and four brand/channel browser experiences backed by real WSO2 Identity Server 7.3 authentication and authorization. **Last positive customer tests: 2026-10-28.** This is a controlled local demonstration, not a production multi-tenant/mobile deployment.

Start at **[the guided lab](http://127.0.0.1:4400/lab)** after starting the existing WSO2 Docker project and BFF. The four experiences are [Aurora Web](http://127.0.0.1:4400/portal/aurora/web), [Aurora Mobile](http://127.0.0.1:4400/portal/aurora/mobile), [Brisa Web](http://127.0.0.1:4400/portal/brisa/web) and [Brisa Mobile](http://127.0.0.1:4400/portal/brisa/mobile). Mobile is a responsive browser OIDC client, not a production native app.

## Architectural ownership at a glance

| Realm / service | What it owns | What it does not own |
|---|---|---|
| **Carbon Super (`carbon.super`)** | WSO2 server-level super administrator `admin`, root-tenant creation and shared IS runtime configuration | Aurora/Brisa customer Web/Mobile OIDC applications or their application-scoped roles |
| **Aurora (`aurora.identity.test`)** | Aurora tenant owner, users including Ana/Marcos, management M2M client, Aurora Web and App OIDC clients, tenant-local API resources and app roles | Brisa subjects, tokens or permissions |
| **Brisa (`brisa.identity.test`)** | Brisa tenant owner, separate user accounts including its own Ana, management M2M client, Brisa Web and App clients, tenant-local API resources and roles | Aurora subjects, tokens or permissions |
| **Node identity BFF (`127.0.0.1:4400`)** | Secure OAuth code+PKCE sessions, ID-token verification, introspection/audience/scope checks, UserInfo proxy, CSRF and real application service-request ledger | WSO2 identity, role grants, token issuance, fake assurance or consent |
| **PostgreSQL / IS (`localhost:9444`)** | Persistent WSO2 identity/shared/agent data and tenant-local WSO2 configuration | Application service-request ledger |

### Application → role → scope → endpoint

Each tenant registers **two independent OIDC applications**. A successful app login receives a WSO2 JWT access token; an application-scoped WSO2 role determines eligible grants, an authorized API resource determines permitted scopes and token audience, and the BFF revalidates those protections per operation. The profile API (`https://api.ciam-v10.test/profile`) owns `ciam:profile:read`; the business API (`urn:ciampoc:service-requests:v1`) owns `ciam:cases:create/read/review/approve`. Customer roles can create/read owned cases; Seller/Business Administrator roles can review/hold approval scope, but approval additionally requires **fresh WSO2 TOTP evidence**. A permission displayed in the UI is not itself authorization.

The six guided journeys are part of the Experience Center. Some advanced B2B, privacy preference, MFA-positive and agent flows are **not yet implemented/verified**; there are no fabricated identity/consent/step-up success results. The storefront merchandise is illustrative presentation content, whereas service-request records are real BFF business data authorized by WSO2.

## Authoritative documentation and scripts

- **[Full architecture, Carbon Super and tenant ownership](docs/CIAM_V5_ARCHITECTURE_AND_OWNERSHIP.md)** — detailed components, tenant/application/user/role/resource relationships, data lineage, API contracts and boundaries.
- **[Exact locally generated tenant/user/role inventory](docs/CIAM_V5_TENANT_INVENTORY.md)** — produced from the real seed and private journals by `python3 scripts/ciam-identity-ops.py inventory --output docs/CIAM_V5_TENANT_INVENTORY.md`. No passwords are exported.
- **[End-to-end acceptance and secure password-copy commands](docs/CIAM_V5_E2E_TESTING.md)** — four websites, customer, seller, negative tenant isolation, case persistence, MFA denial and Carbon Super readback.
- **[WSO2 read-only Carbon Super inventory](scripts/ciam-carbon-super-readback.py)** — bounded GET-only report; does not equate unsupported API endpoints with missing resources.
- **[October 28 baseline acceptance evidence](docs/CIAM_V10_ACCEPTANCE_2026-10-28.md)** — earlier recorded business and security tests.

> **Existing lab:** Never run `fresh`, `docker compose down -v`, reinitialize the database, replay a journaled write, or commit any `~/wso2-ciam-v10/private` contents merely to test or document the current environment.

---

**Legacy/add-on documentation follows below.** Earlier readiness labels, old route inventories and prior “NOT TESTED” statements describe historical stages; use the current architecture and dated acceptance files above for the latest verified scope.
<!-- CIAM_V5_CURRENT_ARCHITECTURE_END -->
