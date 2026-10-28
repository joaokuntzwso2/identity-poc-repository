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

# WSO2 Identity Server 7.3 – zero-mock identity provisioning add-on

**Status: provisioning implementation supplied, NOT a zero-mock certified customer portal.**

This is an additive patch for `joaokuntzwso2/identity-poc-repository` (reviewed against the `main` branch on 2026-10-28). It has been syntax-checked, but the WSO2 7.3 REST calls have **not** been executed against the customer's running server. It does not modify the GitHub repository itself. The original rich Experience Center remains synthetic and **must not be used as a live CIAM customer demonstration** until migrated. The existing strict `live-wso2` BFF is the safe customer-facing security boundary.

## Files

- `deploy/ciam-v10/identities/seed.json`: 6 fictional human personas, 9 distinct tenant-local accounts (6 Aurora, 3 Brisa), role definitions, and precisely ONE verified application permission: `ciam:profile:read`.
- `deploy/ciam-v10/identities/bootstrap.py`: local HTTPS WSO2 SCIM2 user/role plan, apply, and readback. Uses source repo's existing journal and HTTPS helpers. Collision/refusal, write-ahead journal, exact readback, generated strong passwords, local 0600 private state.
- `scripts/install-identity-stage.py`: one-time guarded change to `deploy/ciam-v10/cli.py` to execute new seed immediately after authority bootstrap, before BFF startup.
- `scripts/zero-mock-gate.py`: read-only failing release gate against known fake identity sources; it is **expected to FAIL** on the current rich Experience Center.
- `scripts/live-denial-gate.sh`: anonymous HTTP gate for blocked synthetic routes under strict `live-wso2` BFF. Does not prove positive login or role enforcement.

## Install overlay

From an existing **clean repository checkout** (not inside the add-on directory), copy the files preserving their relative paths. Assuming the downloaded ZIP is in `/tmp/wso2-is73-zero-mock.zip`:

```bash
cd /path/to/identity-poc-repository
unzip -o /tmp/wso2-is73-zero-mock.zip -d .
python3 scripts/install-identity-stage.py .
python3 -m py_compile deploy/ciam-v10/identities/bootstrap.py \
    scripts/install-identity-stage.py scripts/zero-mock-gate.py
bash -n scripts/live-denial-gate.sh
```

`install-identity-stage.py` checks anchor text of `cli.py`, compiles the rewritten Python, and refuses unexpected revisions. Review the `git diff` before execution. No remote writes occur during installation.

## Path A — existing persistent lab (recommended if tenants already exist)

**DO NOT run `fresh` or `fresh-bootstrap` on an existing lab.** These would create another environment and are not needed for new actors/roles.

The existing lab needs the four previously provisioned OIDC apps and an authority journal reporting `API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED`. The WSO2 runtime is expected at `https://localhost:9444`.

```bash
cd /path/to/identity-poc-repository
./scripts/ciam-v10.sh status
WSO2_CIAM_V10_ROLE_API=v3 ./scripts/ciam-v10.sh authority-status
python3 deploy/ciam-v10/identities/bootstrap.py plan
WSO2_CIAM_V10_IDENTITIES_CONFIRM=CREATE_DEMO_PEOPLE_AND_APP_ROLES \
    python3 deploy/ciam-v10/identities/bootstrap.py apply
python3 deploy/ciam-v10/identities/bootstrap.py verify
```

If and ONLY if your existing authority journal uses the deprecated v2 SCIM Role API, run the plan, apply, verify with the explicit environment variable below (do not silently switch an existing journal to v3):

```bash
export WSO2_CIAM_V10_ROLE_V2_CONFIRM=USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES
python3 deploy/ciam-v10/identities/bootstrap.py plan
WSO2_CIAM_V10_IDENTITIES_CONFIRM=CREATE_DEMO_PEOPLE_AND_APP_ROLES \
    python3 deploy/ciam-v10/identities/bootstrap.py apply
python3 deploy/ciam-v10/identities/bootstrap.py verify
unset WSO2_CIAM_V10_ROLE_V2_CONFIRM
```

**Do not blindly retry a rejected POST.** Examine the private journal and reconcile the existing remote object before any retry. All credentials are generated and saved only to `$CIAM_V10_HOME/private/bootstrap-identities-v10.private.json` (default `~/wso2-ciam-v10/private/`). This JSON is 0600 and contains passwords: never check it in or post its content to tickets.

You can inspect actor usernames and WSO2 IDs without printing passwords:

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
home = Path(os.getenv('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10')))
s = json.loads((home/'private/bootstrap-identities-v10.private.json').read_text())
for brand, record in s['tenants'].items():
    for actor, info in record['users'].items():
        print(brand, actor, info['username'], info.get('id'), info['state'])
PY
```

## Path B — **brand-new isolated lab only**

Read the original repository's `docs/CIAM_V10_END_TO_END.md` prerequisites. Ensure Docker, ports 9444/4400 and target `~/wso2-ciam-v10` are free. The existing `fresh-bootstrap` command creates a NEW persistent environment; it is not a reset operation. Our installer adds the actor/role stage to its full pipeline.

```bash
cd /path/to/identity-poc-repository
export WSO2_CIAM_V10_DEPLOY_CONFIRM=BOOTSTRAP_RECORDED_LAB_RESOURCES
export WSO2_CIAM_V10_ROLE_API=v3
export WSO2_CIAM_V10_FRESH_CONFIRM=CREATE_NEW_ISOLATED_PERSISTENT_LAB
./scripts/ciam-v10.sh fresh-bootstrap
python3 deploy/ciam-v10/identities/bootstrap.py verify
unset WSO2_CIAM_V10_DEPLOY_CONFIRM WSO2_CIAM_V10_ROLE_API WSO2_CIAM_V10_FRESH_CONFIRM
```

Select v3 only if the server API responds as required. For v2 instead, explicitly set `WSO2_CIAM_V10_ROLE_API=v2` and `WSO2_CIAM_V10_ROLE_V2_CONFIRM=USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES` before the first run, with verified support for that API. Never switch a role API contract after provisioning to make an error disappear.

## Read-only security and release acceptance

Run this ONLY when the strict `live-wso2` BFF is up on local port 4400:

```bash
bash scripts/live-denial-gate.sh
./scripts/ciam-v10.sh runtime-acceptance
python3 scripts/zero-mock-gate.py .
```

`zero-mock-gate.py` currently exits 1 as it should: `apps/experience-center/src/main.tsx` imports `src/data/personas.json`, allows persona selection, presents local authentication/checkout outcomes and fixture account data; non-live BFF still has local scenario and consent functionality. A PASS on the anonymous BFF test is **not** a PASS for the full UI.

To claim no mocks in the customer portal, the following changes MUST be made and independently tested:

1. Refactor the Experience Center to use `GET /api/identity/me` and protected APIs, never `personas.json` or `setPersonaId` as the current principal. Show only the identity authorized by the WSO2 OIDC session; fetch profile via SCIM/userinfo behind a server-side BFF, with least-privilege authorization and proper token checks.
2. Replace UI role/permission labels with application-audience role and API-scope derived authority, and add back-end endpoints for accounts, seller operations and security analytics. Enforce resource/action permissions in the back end, not by UI booleans. **New non-customer roles have NO operational API permissions on purpose** until such real APIs exist.
3. Build real WSO2 organizations, invitations, delegated administrators and organization-switch handling for B2B, or remove those journeys from the live UI. The new `Business Administrator` application role alone does not give delegated-organization administration.
4. Implement actual MFA/step-up on WSO2, and prove `acr` / `amr` (or other trustworthy assurance) rather than toggling a React indicator. No new factor registrations are created by this add-on.
5. Provide a verified WSO2 consent service contract plus persistence/revocation, or keep consent screens unavailable. Repo explicitly notes that consent API v2 is blocked on the public GA 7.3 image; this add-on **does not create substitute consent data**.
6. Provision and authorize M2M workload/agent identities as proper **OAuth applications/agents**, not SCIM human users. Agent token exchange, delegated authorization and approvals need their own verified bootstrap and API enforcement. Do not interpret a UI persona of type `agent` as an authenticated WSO2 agent.
7. The same fictional human in Aurora and Brisa is provisioned as two separate root-tenant accounts. This does **not** demonstrate cross-tenant SSO, linked identity, subject continuity, or pairwise correlation.
8. Replace synthetic consent, orders, audit logs, account relationships and security events with operational backends or disable those cards entirely. Identity Server is not an order-management or commerce catalog data store.
9. Add browser login, token expiry, invalid token, wrong-audience, scope change, role revocation, tenant isolation, operator abuse and denial-of-service tests; current GET readback is only resource-provisioning evidence.

**Release decision:** NO GO for the synthetic Experience Center as a WSO2-backed customer demo until these controls are real and `zero-mock-gate.py` plus live positive/negative acceptance tests pass. The strict live BFF is the safe limited demonstration today.

<!-- CIAM_V10_IMPLEMENTATION_2026_10_28_START -->
## Live CIAM implementation — WSO2 Identity Server 7.3

This repository includes a live, **zero-synthetic-identity** Aurora/Brisa customer
portal, WSO2-provisioned OIDC applications and tenant-local users, an
application-scoped business API, and a persistent service-request demonstration.
Authentication and authorization are provided by **WSO2**; the BFF owns only
session protection and application business records.

- **[Implementation map and component relationships](docs/CIAM_V10_IMPLEMENTATION_MAP.md)** — tenants → OIDC applications → API resources/scopes → app roles → tokens → BFF endpoints → business records; bootstrap lifecycle, security boundaries, configuration, and still-deferred capabilities.
- **[2026-10-28 acceptance evidence](docs/CIAM_V10_ACCEPTANCE_2026-10-28.md)** — what real WSO2 sessions verified and what remains untested.
- **[Phase 4 implementation runbook](README-IMPLEMENTATION.md)** — bootstrap plan/apply/verify instructions. Follow its guarded readback rules; never run fresh tenant provisioning against the existing lab.

**Verified so far:** Ana's Aurora Web login and owned case create/read (201/200),
Marcos's cross-user brand review (200), denied seller creation (403), and denied
approval without fresh WSO2 TOTP (403). **Not yet verified:** positive TOTP
approval, B2B delegation, privacy preferences, released profile names/email,
or business-token audiences for the other three OIDC clients. See the evidence
file for precise scope and API results.
<!-- CIAM_V10_IMPLEMENTATION_2026_10_28_END -->


<!-- CIAM_V5_LIVE_EXPERIENCE -->
## Experience Center – WSO2 live (v5)

Open `http://127.0.0.1:4400/lab` for the original-style guided lab and the four Aurora/Brisa Web/Mobile experiences. Identity and permissions are fetched through the live WSO2 BFF, not synthetic persona fixtures. See [v5 architecture](docs/CIAM_V5_EXPERIENCE_AND_WSO2_RELATIONSHIPS.md) and [v5 instructions](README-LIVE-EXPERIENCE-V5.md). Mobile is an OIDC browser preview, not a native app.
