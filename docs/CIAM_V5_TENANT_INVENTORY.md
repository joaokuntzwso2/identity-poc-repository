# CIAM v5 — tenant/application/identity inventory

> Generated locally 2026-10-28 17:34 UTC using source manifests and private bootstrap journals. **No passwords, client secrets, or tokens are written.**
> Journal status is provisioning evidence, not a live remote SCIM read or authenticated browser test.

## Carbon Super (`carbon.super`)

- **Role:** WSO2 server super tenant; not Aurora or Brisa and not a customer website.
- **Super administrator:** `admin` configured by the private `[super_admin]` deployment setting; the password is in `~/wso2-ciam-v10/private/admin.private.json`.
- **Provisioning responsibility:** root tenant creation via `/api/server/v1/tenants` and owner setup. Tenant APIs and SCIM roles are then administered using tenant-qualified accounts.
- **Shared runtime:** one `wso2/wso2is:7.3.0` container, PostgreSQL identity/shared/agent databases, and the common TLS endpoint on `https://localhost:9444`.
- **Important:** this source/journal inventory does *not* enumerate arbitrary applications, service accounts, system roles or APIs that may exist in Carbon Super. A read-only live Carbon audit is required to claim a complete super-tenant catalog.
- **Consumer logins:** none of the four demo OIDC clients belongs to Carbon Super; their applications are tenant-local.

## Tenants and tenant-local resources

### Aurora — `aurora.identity.test`

- **Owner:** `labtenantadmin@aurora.identity.test` (tenant admin, distinct from Carbon Super admin).
- **Bootstrap SCIM user:** `ciam_aurora` (non-super support/test identity).
- **Management M2M application:** `Identity Lab AURORA Management Bootstrap` (tenant-local; used for authorized management/SCIM scope operations, not a customer login).
- **Profile API resource:** `https://api.ciam-v10.test/profile`; `ciam:profile:read`.
- **Business API resource:** `urn:ciampoc:service-requests:v1`; `ciam:cases:create`, `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve`.
- **Business case data:** BFF JSONL records tagged by brand; not a WSO2 user table.

| OIDC channel | WSO2 application name | BFF client key | Callback |
|---|---|---|---|
| Web | Identity Lab v10 Aurora Web | `aurora-web` | `http://127.0.0.1:4400/auth/aurora-web/callback` |
| Mobile browser | Identity Lab v10 Aurora Mobile Browser Preview | `aurora-app` | `http://127.0.0.1:4400/auth/aurora-app/callback` |

| Seeded person | Username | Persona category | SCIM journal state |
|---|---|---|---|
| Ana Costa | `ana.costa` | customer | verified |
| Rafael Nunes | `rafael.nunes` | customer | verified |
| Marcos Oliveira | `marcos.oliveira` | seller | verified |
| Luiza Ferreira | `luiza.ferreira` | administrator | verified |
| Pedro Reis | `pedro.reis` | attendant | verified |
| Camila Lima | `camila.lima` | analyst | verified |

**Application-scoped roles and permission membership**

| Application | Role | Members (usernames) | Scopes / permissions | State |
|---|---|---|---|---|
| `aurora-web` | `CIAM Demo Customer WEB` | `ana.costa`, `rafael.nunes` | `ciam:profile:read` | verified |
| `aurora-web` | `CIAM Demo Seller WEB` | `marcos.oliveira` | None (not an authorization grant) | verified |
| `aurora-web` | `CIAM Demo Business Administrator WEB` | `luiza.ferreira` | None (not an authorization grant) | verified |
| `aurora-web` | `CIAM Demo Attendant WEB` | `pedro.reis` | None (not an authorization grant) | verified |
| `aurora-web` | `CIAM Demo Security Analyst WEB` | `camila.lima` | None (not an authorization grant) | verified |
| `aurora-web` | `CIAM Business Customer WEB` | `ana.costa`, `rafael.nunes` | `ciam:cases:create`, `ciam:cases:read` | verified |
| `aurora-web` | `CIAM Business Seller WEB` | `marcos.oliveira` | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | verified |
| `aurora-web` | `CIAM Business Administrator WEB` | `luiza.ferreira` | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | verified |
| `aurora-app` | `CIAM Demo Customer APP` | `ana.costa`, `rafael.nunes` | `ciam:profile:read` | verified |
| `aurora-app` | `CIAM Demo Seller APP` | `marcos.oliveira` | None (not an authorization grant) | verified |
| `aurora-app` | `CIAM Demo Business Administrator APP` | `luiza.ferreira` | None (not an authorization grant) | verified |
| `aurora-app` | `CIAM Demo Attendant APP` | `pedro.reis` | None (not an authorization grant) | verified |
| `aurora-app` | `CIAM Demo Security Analyst APP` | `camila.lima` | None (not an authorization grant) | verified |
| `aurora-app` | `CIAM Business Customer APP` | `ana.costa`, `rafael.nunes` | `ciam:cases:create`, `ciam:cases:read` | verified |
| `aurora-app` | `CIAM Business Seller APP` | `marcos.oliveira` | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | verified |
| `aurora-app` | `CIAM Business Administrator APP` | `luiza.ferreira` | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | verified |

**API and application relationship:** both `aurora-web` and `aurora-app` are explicitly authorized to consume the profile and business resources in the **aurora.identity.test** tenant. WSO2 still decides token scopes from memberships and authorization; the BFF checks live audience and scope per call.

### Brisa — `brisa.identity.test`

- **Owner:** `labtenantadmin@brisa.identity.test` (tenant admin, distinct from Carbon Super admin).
- **Bootstrap SCIM user:** `ciam_brisa` (non-super support/test identity).
- **Management M2M application:** `Identity Lab BRISA Management Bootstrap` (tenant-local; used for authorized management/SCIM scope operations, not a customer login).
- **Profile API resource:** `https://api.ciam-v10.test/profile`; `ciam:profile:read`.
- **Business API resource:** `urn:ciampoc:service-requests:v1`; `ciam:cases:create`, `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve`.
- **Business case data:** BFF JSONL records tagged by brand; not a WSO2 user table.

| OIDC channel | WSO2 application name | BFF client key | Callback |
|---|---|---|---|
| Web | Identity Lab v10 Brisa Web | `brisa-web` | `http://127.0.0.1:4400/auth/brisa-web/callback` |
| Mobile browser | Identity Lab v10 Brisa Mobile Browser Preview | `brisa-app` | `http://127.0.0.1:4400/auth/brisa-app/callback` |

| Seeded person | Username | Persona category | SCIM journal state |
|---|---|---|---|
| Ana Costa | `ana.costa` | customer | verified |
| Luiza Ferreira | `luiza.ferreira` | administrator | verified |
| Camila Lima | `camila.lima` | analyst | verified |

**Application-scoped roles and permission membership**

| Application | Role | Members (usernames) | Scopes / permissions | State |
|---|---|---|---|---|
| `brisa-web` | `CIAM Demo Customer WEB` | `ana.costa` | `ciam:profile:read` | verified |
| `brisa-web` | `CIAM Demo Business Administrator WEB` | `luiza.ferreira` | None (not an authorization grant) | verified |
| `brisa-web` | `CIAM Demo Security Analyst WEB` | `camila.lima` | None (not an authorization grant) | verified |
| `brisa-web` | `CIAM Business Customer WEB` | `ana.costa` | `ciam:cases:create`, `ciam:cases:read` | verified |
| `brisa-web` | `CIAM Business Administrator WEB` | `luiza.ferreira` | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | verified |
| `brisa-app` | `CIAM Demo Customer APP` | `ana.costa` | `ciam:profile:read` | verified |
| `brisa-app` | `CIAM Demo Business Administrator APP` | `luiza.ferreira` | None (not an authorization grant) | verified |
| `brisa-app` | `CIAM Demo Security Analyst APP` | `camila.lima` | None (not an authorization grant) | verified |
| `brisa-app` | `CIAM Business Customer APP` | `ana.costa` | `ciam:cases:create`, `ciam:cases:read` | verified |
| `brisa-app` | `CIAM Business Administrator APP` | `luiza.ferreira` | `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve` | verified |

**API and application relationship:** both `brisa-web` and `brisa-app` are explicitly authorized to consume the profile and business resources in the **brisa.identity.test** tenant. WSO2 still decides token scopes from memberships and authorization; the BFF checks live audience and scope per call.

## Distinctions not to collapse

- A tenant owner, a management M2M OAuth app, and an application-scoped business administrator role are **three different authorities**.
- Ana in Aurora and Ana in Brisa are **two separately provisioned WSO2 tenant accounts**, not a shared cross-tenant session or linked subject.
- The same human may be a member of both Web and Mobile app roles; these are still separate OIDC applications with distinct client IDs and token audience policies.
- Application roles are not equivalent to the `roles` claim in an ID token. Browser UI renders role names only when WSO2 releases the claim.
- OAuth access-token audience is checked independently of `ciam:*` scopes; the four OIDC clients were configured for both profile and business audiences and each passed a positive browser read/isolation test on 2026-10-28.
- Consent preference APIs, B2B child-organization delegation, successful TOTP approval, and production native-mobile SDK behavior remain unverified.
- Inventory above comes from source and private journals; run the explicit management API verify steps in the E2E guide for a fresh remote readback.
