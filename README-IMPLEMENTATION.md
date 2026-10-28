# CIAM v4 implementation — WSO2 IS 7.3

## Important constraints

This bundle targets the **already-installed v3 source** and v10 private WSO2 journals from the earlier conversation. No source ZIP from GitHub is assumed. The installers verify the v3 shape and back up modified files. This package does **not** automatically modify the existing v10 bootstrap, and does not run any remote writes unless you explicitly invoke the v4 `apply` stages.

The v10 identity bootstrap must continue passing. v4 creates **new** application-scoped roles (`CIAM Business ...`) rather than changing the existing seed roles, which have exact permission-readback contracts.

### What runs in WSO2

`business-bootstrap.py plan/apply/verify` creates **one scoped API resource per tenant** (`urn:ciampoc:service-requests:v1`), authorizes both registered OIDC applications in each tenant to request the four scopes, creates new application-scoped business roles for actual provisioned users, and does readback. The API resource is **not** an API deployment; the BFF handles the actual records. Journal: `~/wso2-ciam-v10/private/bootstrap-business-v4.private.json`.

`b2b-bootstrap.py plan/apply/verify` creates one child org under Aurora and shares the already registered Aurora Web application. `delegate` requests Luiza's existing root identity to be shared to the child organization with the organization's `Administrator` role; it **requires a scoped OAuth admin token** and its asynchronous `202` response must be verified separately. Journal: `~/wso2-ciam-v10/private/bootstrap-b2b-v4.private.json`. If the organization cannot issue a scoped token with permissions for the selected API, stop; no Basic auth fallback. The organizational administrator's actual privileges and interactive login require further proof.

`consent-preflight.py` blocks the privacy preference feature unless WSO2 update >= 7.3.0.12 is **independently confirmed** and `consent_mgt.enable_v2_api=true` is configured. Its output itself does not prove a deployed v2 endpoint.

### What runs in the portal

An additive `live-cases-v4.js` router implements true durable service requests: create, owner-only read, brand review, approval. Data is held in an append-only disk ledger under `CIAM_BUSINESS_DATA_DIR`, outside source control and in a private directory. The *identity authority* is WSO2; this ledger is only app business data. No fake orders or entitlements. New browser UI is appended to `/portal/aurora` and `/portal/brisa`.

Every BFF operation is authorized by `requireAuthorityForClient` using WSO2 live introspection and the **new** audience from `WSO2_CASES_API_AUDIENCE`. The existing `WSO2_BUSINESS_API_AUDIENCE` is unchanged to avoid breaking the working profile endpoint. On approval, server additionally requires `amr` containing `totp` and `auth_time` within five minutes in the **signature-verified ID token**; an `acr_values` request or UI flag is NOT proof.

## 0. Install in existing repository — no remote WSO2 writes

Copy the bundle into the repository while preserving directory structure, then:

```bash
cd "$HOME/wso2mi/Projects/Demo/poc-implementation"
python3 scripts/install-business-v4.py --check
python3 scripts/install-business-v4.py --apply
python3 -m py_compile deploy/ciam-v10/phase4/*.py
node --check services/identity-bff/src/server.js
node --check services/identity-bff/src/live-cases-v4.js
node --check services/identity-bff/src/live-cases-v4-ui.js
node --test tests/live-cases-v4.test.mjs
python3 scripts/zero-mock-gate.py .
```

If the installer refuses, do **not** force replace `server.js`; it indicates local version mismatch. Do not rerun v10 `fresh-bootstrap`.

## 1. Business API authorization (actual WSO2 writes)

```bash
export WSO2_CIAM_V10_ROLE_API=v2
export WSO2_CIAM_V10_ROLE_V2_CONFIRM=USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES
python3 deploy/ciam-v10/phase4/business-bootstrap.py plan
# Carefully inspect plan; only then run:
WSO2_CIAM_V4_BUSINESS_CONFIRM=CREATE_CIAM_BUSINESS_API_AND_ROLES_V4 \
  python3 deploy/ciam-v10/phase4/business-bootstrap.py apply
python3 deploy/ciam-v10/phase4/business-bootstrap.py verify
```

If an API/role POST is **uncertain**, the journal refuses automatic retries. Reconcile from actual WSO2 Console/API readback first. If v4 readback fails, do not enable new BFF request scopes.

After successful verification, configure runtime environment **in the shell that launches the BFF**:

```bash
export CIAM_BUSINESS_DATA_DIR="$HOME/wso2-ciam-v10/private/business-cases-v4"
mkdir -p "$CIAM_BUSINESS_DATA_DIR"
chmod 700 "$CIAM_BUSINESS_DATA_DIR"
export WSO2_CASES_API_AUDIENCE='urn:ciampoc:service-requests:v1'
export WSO2_CASES_SCOPES_ENABLED=1
```

Stop the **known** BFF Node process as previously; after port is free:

```bash
WSO2_CIAM_V10_STALE_PID_CONFIRM=CLEAR_DEAD_PID_ONLY ./scripts/ciam-v10.sh bff-clear-stale
./scripts/ciam-v10.sh bff-start
./scripts/ciam-v10.sh bff-diagnose
./scripts/ciam-v10.sh runtime-acceptance
bash scripts/live-denial-gate.sh
```

### Browser acceptance

In a fresh Aurora private session, Ana must log in and consent to WSO2-requested service scopes. `/portal/aurora` **Criar solicitação** writes real ledger record (201). Only Ana should see this record under owner-only read. Marcos gets the review scopes if and only if WSO2 granted them through the new role; in a separate authenticated session Marcos can read brand records. For approval Marcos must have a WSO2 ID token with `amr` containing `totp` and fresh `auth_time`; otherwise HTTP 403 is **correct**. A user who lacks `ciam:cases:approve` must be denied regardless of MFA.

The route deliberately does not implement retail order processing. Integrate a transactional retail backend before showing real retail orders.

## 2. Real profile attrs and displayed roles (deferred until you choose to enable)

Existing v3 BFF already shows **only** signed-ID-token roles and **only** actual UserInfo attributes. Do not synthesize missing values. For each existing registered application in both tenants, configure `User Attributes` in WSO2 Console to share exactly `given_name`, `family_name`, `email`, and optionally `preferred_username`; map them to OIDC `profile` / `email` scopes and obtain user consent. Ensure `config.js` requests `openid profile email ciam:profile:read` without touching registered callback or audience. A fresh login must show released attributes in `/api/brands/{brand}/profile`, with `sub` match and live scope introspection.

For roles: enable the verified WSO2 role claim only if it is available as an OIDC application token claim; do **not** assume SCIM role membership automatically appears as `roles` in the ID token. Confirm the exact attribute mapping, then make a new authorization flow and inspect `/api/identity/me` `rolesFromVerifiedIdToken`. The portal never turns role strings into backend permissions.

## 3. MFA and enforced approval assurance

For each intended WSO2 app, Console → Applications → the app → Login Flow → Predefined Flows → Add Multi-factor Login → `Username + Password -> TOTP` → Update. Enroll the test users via the actual WSO2 enrollment flow or My Account. A fresh browser login must show an actual TOTP challenge. Confirm the *verified ID token* includes `amr` with `totp`, and `auth_time` represents the login just performed. `live-cases-v4.js` denies approval if evidence is absent, even when WSO2 grants approval scope. This package implements MFA-gated approval for **fresh** MFA login; it does not falsely claim an on-demand step-up challenge. For action-level step-up, configure an ACR-based conditional policy and extend the authorization login flow with an ACR request plus fresh AMR/ACR verification before labeling it action step-up.

## 4. B2B organization + app sharing + delegated administrator

Requires separately obtained OAuth admin token containing required organization/application sharing/user sharing scopes (`internal_org_organization_create`, `internal_org_organization_view`, `internal_shared_application_create`, `internal_shared_application_view`, `internal_user_share`, `internal_user_shared_access_view`). Never paste the token into chat/logs.

```bash
read -s 'WSO2_CIAM_V4_ORG_ADMIN_BEARER?Paste scoped org admin token: '
export WSO2_CIAM_V4_ORG_ADMIN_BEARER
printf '\n'
python3 deploy/ciam-v10/phase4/b2b-bootstrap.py plan
WSO2_CIAM_V4_B2B_CONFIRM=CREATE_AURORA_PARTNER_ORGANIZATIONS_V4 \
  python3 deploy/ciam-v10/phase4/b2b-bootstrap.py apply
python3 deploy/ciam-v10/phase4/b2b-bootstrap.py verify
```

Then, after verifying that the target child org has an `Administrator` organization role with the intended admin privileges:

```bash
WSO2_CIAM_V4_B2B_DELEGATE_CONFIRM=SHARE_LUIZA_AS_AURORA_PARTNER_ADMIN_V4 \
  python3 deploy/ciam-v10/phase4/b2b-bootstrap.py delegate
python3 deploy/ciam-v10/phase4/b2b-bootstrap.py verify
unset WSO2_CIAM_V4_ORG_ADMIN_BEARER
```

`delegate` returns `ASYNC_ACCEPTED_NOT_VERIFIED` for HTTP 202. Only `verify` plus **actual delegated admin login and permitted/denied admin operations** can mark delegation demonstrated. This does not establish cross-root tenant SSO. The B2B API remains separate from the Aurora/Brisa retail portals until that interactive org context is verified.

## 5. Preference/policy consent (conditional on installed update)

From WSO2 IS docs: consent v2 & preferences require **update level 7.3.0.12+**. Do not assume base `7.3.0` includes it. Independently establish actual installed update level, then merge `consent-deployment.toml.txt` into existing `deployment.toml`, restart WSO2 using the existing persistent deployment, and establish that the v2 API and My Account consent UI are available.

```bash
export WSO2_IS73_VERIFIED_UPDATE_LEVEL=12 # only after independent proof
export WSO2_IS73_CONSENT_V2_ENABLED=true # only after deployment.toml readback
python3 deploy/ciam-v10/phase4/consent-preflight.py
```

In Console, configure a versioned purpose (for example, `aurora-marketing-emails`) and consent element(s) in Consent Management, then add a **Preference Management Consent** widget to the customer registration flow using the Flow Builder, and enable My Account consent review/revoke. Verify an actual user's opt-in, opt-out, persistence and events via v2 API and My Account. OAuth attribute consent is a **different** artifact. Do not enable a marketing/preferences switch in the brand portal until this positive/negative evidence exists. This bundle deliberately does not POST unverified consent payloads to an update-level-dependent API.

## Acceptance / limits

- No synthetic users, roles, permission grants or fabricated security results.
- Scope enforcement and MFA authorization occur server-side; no browser-supplied role/scope is trusted.
- Business records persist in private application storage, **not** in Identity Server.
- v4 source/Node unit tests are local proof only. WSO2 API `apply` and interactive browser tests are **not executed from this package**.
- Existing v10 legacy role/readback stays intact.
- B2B and consent interfaces are not advertised as operational until real acceptance passes.

## Reference documentation

- https://is.docs.wso2.com/en/7.3.0/apis/api-resource-management-rest-api/
- https://is.docs.wso2.com/en/7.3.0/apis/application-rest-api/
- https://is.docs.wso2.com/en/7.3.0/apis/role-management/roles-v2-rest-api/
- https://is.docs.wso2.com/en/7.3.0/apis/organization-apis/org-organization-mgt/
- https://is.docs.wso2.com/en/7.3.0/guides/authentication/mfa/add-totp-login/
- https://is.docs.wso2.com/en/latest/guides/consent-management/

<!-- CIAM_V4_2026_10_28_STATUS_START -->
## Current verified runtime status (2026-10-28)

**Start with the [component relationship map](docs/CIAM_V10_IMPLEMENTATION_MAP.md)** and
[dated acceptance evidence](docs/CIAM_V10_ACCEPTANCE_2026-10-28.md). The
instructions below include **original deployment steps and future feature sketches**;
not every step was executed, and the earlier manual Console descriptions are
**not** the deployment procedure used for this lab. Changes to WSO2 settings are
made with guarded bootstrap/API scripts, private backup, journal, and remote
readback. Do not manually edit Console settings as a substitute for a bootstrap.

As of this date, the v4 business API and role assignments read back successfully,
Aurora Web's profile and business audiences were confirmed after a guarded OIDC
PUT, the BFF restarted, and **real users** proved these endpoints: Ana created
and read an owned request (201/200); Marcos reviewed it (200), was denied a
customer-only create (403) and was denied approval without fresh TOTP (403).
Positive MFA approval, delegated organizations, privacy preferences and other
OIDC clients' business-token audiences remain unverified. The audience recovery
source in `scripts/recovery/` is a **one-time historical recovery**, not a
bootstrap for new labs. Do not re-run fresh tenant bootstrapping on this lab.
<!-- CIAM_V4_2026_10_28_STATUS_END -->
