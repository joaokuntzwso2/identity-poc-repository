# Identity Operations Laboratory v0.6

**Standalone, executable P1 implementation overlay** for the existing public Identity Experience Center **v0.5** (v0.3 base + v0.4 retail portals + v0.5 mobile laboratories). It does not modify the identity BFF, OIDC/JWT verification, PKCE implementation, retail storefronts or mobile apps.

## Install on macOS from the repository root

```bash
cd /path/to/poc-implementation
unzip -oq ~/Downloads/identity-operations-v06.zip -d ~/Downloads
bash ~/Downloads/identity-operations-v06/install.sh
npm ci
./experience.sh operations-test
./experience.sh dev
```

Open the four independent browser pages:

| Module | Local URL |
|---|---|
| Seller organization console | `http://127.0.0.1:5173/b2b.html` |
| Brand onboarding wizard | `http://127.0.0.1:5173/onboarding.html` |
| Authorization / delegation playground | `http://127.0.0.1:5173/authorization.html` |
| Evidence Center | `http://127.0.0.1:5173/evidence-lab.html` |

They are also linked from the existing Experience Center landing page. Each is responsive, with a navigation rail, distinct content layout, interactive forms, progress/decision states, Presenter vs Technical mode, error/empty states and clear local-preview labels. The UI uses bundled CSS and SVG; no remote assets are required.

### Build and run all applications

```bash
./experience.sh build
./experience.sh serve
# identical paths on http://127.0.0.1:4317
```

Optional Playwright integration test (with `./experience.sh dev` running in a separate terminal):

```bash
cd apps/experience-center
npx playwright install chromium
npx playwright test tests/operations-v06.spec.ts
```

## Feature scope and exact behavior

### B2B Partner Console

- Synthetic three-level organization structure with a delegated `org_admin` and independently assigned `editor` / `viewer` roles.
- Switch fictional actor (clearly **not** authentication), choose organization, view members, create child organizations, assign role, create synthetic `.example` invitations.
- Server enforces subtree authorization, rejects actions by non-admins and self-role modification, and limits organizational depth.
- Rejected authorization attempts are recorded as append-only evidence. Invites do not send email.
- **Live pending:** actual B2B organizations in WSO2, customer IdP federation, management APIs, SAML/OIDC, real delegated admin sessions and privilege proofs.

### New Brand Onboarding

- Four-step wizard: brand metadata; web/mobile sector URI and distinct redirects; validation; persisted, downloadable JSON provisioning plan.
- Mandatory independent consent and public HTTPS URI syntax validation (not live reachability); rejects duplicate brand codes and reused redirects.
- Plan includes technical and regression acceptance checks, rollback, isolation, policy and issuer/topology review.
- All plans are **`provisioned:false`** and **`identityProvider:'not_configured'`**. There is no endpoint to activate a tenant.
- **Live pending:** selecting WSO2 root-tenant vs organization topology, the actual admin/provisioning APIs, domain/cookie SSO, OIDC token and `sub` checks, and onboarding impact tests.

### Authorization and Delegation

- Controlled, server-owned fixtures covering **Client Credentials** (no human subject), **user Token Exchange** (actor + subject, attenuation), and **agent** (actor + user approval requirement).
- Actual fixture-protected HTTP endpoints for `GET /api/lab/resources/catalog`, `GET/POST /api/lab/resources/orders`, `GET /api/lab/resources/preferences`, and `POST /api/lab/resources/transfers`. Unauthorized requests return **HTTP 403**; accepted requests return synthetic response bodies and evidence IDs. These are not OAuth-protected production APIs.
- The `evaluateAccess()` function enforces scopes, actor scope, subject scope, audience/brand boundary, mandatory human subject, approval, and purpose consent.
- Every decision is recalculated in the backend (not from frontend flags), and every attempt writes a durable evidence record.
- **No fake JWT**, no OAuth tokens issued, no real Resource Server; future live tests must verify cryptographic token validation and protected API authorization.

### Evidence Center

- Append-only SQLite execution records: timestamp, scenario, domain, expected outcome, observed outcome, policy result, evidence origin, detail and acceptance state.
- Self-check execution runs five offline policy cases and records the observed outcome.
- Displays scenario readiness across **Requires WSO2** and **Documentary/Contractual**, plus exported JSON evidence.
- When an existing private release-gate report is available at `evidence/identity/release-gates.json`, the UI reads only aggregate reported state; it does not import private requirements, claim independent review or promote the status.
- All records have immutable `acceptance_status = 'NOT_VERIFIED'`, enforced by a DB trigger that blocks UPDATE/DELETE. A passing local fixture **never** becomes `Live Verified` and is never counted as contractual evidence.
- Public scenario catalog is generic; do not check in private customer requirement matrices, volumes or contracts.

## Architecture / security

```
React (Experience Center + 4 Operations pages)
        |  loopback HTTP + explicit X-Experience-Preview: yes
        v
Experience Preview API :4317 (127.0.0.1 only)
        |── PreviewStore (consent / assurance / brand data)
        |── RetailStore  (Aurora/Brisa shops)
        `── OperationsStore (B2B / plans / resource policy / evidence)
             `── SQLite in var/identity-preview.sqlite (gitignored)

Identity Server 7.3: NOT CONNECTED
Identity BFF (OIDC/PKCE/JWT): UNMODIFIED
```

The actor selector is **an untrusted preview input**, not a substitute for authentication. The API is loopback-only, restricts origins and requires an explicit preview header on writes. Do not expose port 4317 outside your machine or treat this code as production-ready IAM authorization. The issuer-adapter and real token validation must be introduced later and audited separately.

## Test and release procedure

```bash
npm test
./experience.sh operations-test
./experience.sh test
./experience.sh build
python3 scripts/security/check_public.py --staged  # after reviewing/staging
```

Review the changes, do not commit private files, and keep live acceptance gated until actual WSO2 deployment and documentary approvals. **Offline feature completeness is not RFP compliance.**
