# P2.24–P2.31 — WSO2 IS 7.3.0 capability and prerequisite matrix

**Assessment date:** 2026-11-04. **Deployment contract:** public `wso2/wso2is:7.3.0` GA, persistent database; do not replace it. **Repository source reviewed:** public `main`; README reports four live OIDC browsers as of 2026-10-28. **This package:** source-only, isolated tests passed; **NO live WSO2 acceptance evidence** was collected in the authoring environment.

`DOCUMENTED` means WSO2 documentation describes a capability for 7.3.0, **not** that it works or is provisioned in this installation. `SOURCE_ONLY` means shipped code can be unit-tested and installed, not that it has operated against WSO2.

| Phase | 7.3.0 GA platform boundary | Source increment in this package | Actual status / acceptance blocker |
|---|---|---|---|
| **P2.24 B2B** | Organization Management v1 under `/t/{tenant}/o/api/server/v1/organizations`; org SCIM under `/t/{tenant}/o/scim2`. Application sharing and org-scoped roles documented. `internal_org_organization_view/create` for discovery/provisioning; org user `internal_org_user_mgt_list/view/update` as needed. | `scripts/p2/guarded-org.mjs`, `cli.mjs`: **Aurora-only** parent metadata check, exact-name lookup, single child creation with durable prewrite journal + GET readback. | `SOURCE_ONLY`: parent/child organization IDs, least-privilege tokens and live readbacks not supplied. Real partner administrator portal, group/membership operations, shared app, delegation, denial of parent/sibling mutations **not implemented**. |
| **P2.25 Privacy** | **Update 7.3.0.12+** for Consent Management v2; requires `[consent_mgt] enable_v2_api = true` plus documented console scopes and flow configuration. | Version/activation and isolated migration/acceptance plan only. | **BLOCKED_ON_UPDATE_AND_APPROVAL**. No local checkbox is consent evidence. Do not send guessed API payloads on GA. |
| **P2.26 Adaptive** | Conditional-login script/flow builder documented in IS 7.3.0; role, group, login-attempt and other templates, steps with TOTP. | Live-status view shows only signed ID-token `acr`, `amr`, and, where emitted, `auth_time`; request context is not conflated with achieved MFA. | `SOURCE_ONLY`: adaptive policy not installed; verified positive TOTP step-up and true policy negative testing not available. Existing approval logic is fail-closed; successful approval still unproved. |
| **P2.27 Passkeys** | WSO2 Passkey FIDO2 login, My Account enrollment, progressive enrollment, credential management documented. Require browser/platform/WebAuthn RP origin verification. | Acceptance design; no private-key storage or fake registration. | **UNVERIFIED_RUNTIME**. Existing registered apps, WSO2 HTTPS origin, RP ID, registration, cancellation, revocation and account recovery need testing. |
| **P2.28 Federation** | OIDC/SAML external identity connections, claim mapping and JIT provisioning supported by WSO2 documentation. | Controlled-IdP runbook; no secrets committed. | **UNVERIFIED_RUNTIME**. Select a controlled IdP; verify issuer/JWKS, claim mapping, account linking policy, cancellation, outage, and denial of Brisa business rights. |
| **P2.29 Lifecycle** | WSO2 SCIM2 user and group APIs; organization SCIM user PATCH support. | `child-users` (complete first-page read) and `disable-user` (exact child context, GET user, PATCH active=false, GET readback) with no retries on ambiguous outcomes. | `SOURCE_ONLY`: not run against WSO2. Does **not** prove old access tokens/sessions are invalid; do explicit live introspection and protected-operation tests. Customer/seller/partner create/update/role removal not completed. |
| **P2.30 Audit** | WSO2 identity events/logs, application business records can be correlated when configured. | Explicit observed-vs-derived evidence schema and collection plan. | **NOT_IMPLEMENTED** centrally. No assertions of WSO2 event streams or request trace propagation until collectors and tests exist. |
| **P2.31 Brand** | Branding, organization-specific customer login, API authorization and existing Aurora/Brisa OIDC architecture documented. | `/p2/advanced` status view linked from live Experience Center. It calls `/api/identity/me` and only displays introspected sessions and signed token evidence. | `SOURCE_ONLY`: new page not deployed on Mac; advanced real partner/federation/passkey stories remain unverified. |
| **P2.TE Actor delegation** | **Update 7.3.0.18+** for OAuth token exchange with `actor_token` and `act` delegation; separate from B2B admin. Scope-restricted federated exchange and per-request `audience` also 7.3.0.18+. | Gate and migration criteria only. | **BLOCKED_ON_UPDATE_AND_APPROVAL**. Ordinary 7.3.0 token exchange/org-app support is not actor-aware delegation. |

## Repository ownership and engineering boundaries

- **System root:** `carbon.super` — server admin and tenant creation only. Do not create a partner as a root tenant or grant it Carbon privileges.
- **Aurora root:** `aurora.identity.test` — owns Aurora OIDC app/resource/roles and proposed child **Aurora Returns & Fulfillment Partner** (`aurora-returns-fulfillment`); parent metadata must match an independently recorded Aurora root organization UUID.
- **Brisa root:** `brisa.identity.test` — remains separate. The P2 CLI does not accept Brisa URLs and rejects them locally.
- **BFF:** `services/identity-bff/src/server.js` — existing OIDC + signed ID token + per-request introspection + business case policy; new static status page is not an administration endpoint.
- **Operator:** `scripts/p2/` — manually supplied short-lived, narrow WSO2 tokens in a 0600 file outside the checkout, HTTPS CA trust, no vendor secrets or users in Git; no automation from browser sessions.
- **Business records:** service-request append-only ledger remains business evidence only, not identity/consent authority.

## Minimum documented management scopes

| Operation | Endpoint class | WSO2 scope | Separation |
|---|---|---|---|
| Read child orgs/metadata | `/t/aurora.identity.test/o/api/server/v1/organizations` | `internal_org_organization_view` | Aurora root management token only |
| Create a child | same, `POST /organizations` | `internal_org_organization_create` | One guarded operator approval; no update/delete scope |
| Read child users | `/t/aurora.identity.test/o/scim2/Users` | `internal_org_user_mgt_list` and appropriate view permission | Token switched to *the exact child* |
| Suspend child user | same, `PATCH /Users/{id}` | `internal_org_user_mgt_update` + view | Child-only token; never owner or parent token |
| Read/manage groups | `/t/aurora.identity.test/o/scim2/Groups` | `internal_org_group_mgt_view/update` as needed | Not implemented in this source increment |
| Shared app role assignments | Organization-scoped roles / root-shared app permissions | Exact scope from **runtime OpenAPI** and assigned role | No blanket admin grants; not implemented |

**Prerequisite evidence (must be independently verified):** running image digest + update provenance; 7.3.0 API OpenAPI exposure; real org UUID/tenant; OAuth token `aud`, issuer, effective scopes and org context; delegated principal restrictions; claimed SCIM `active` mutability; documented conditional-login runtime inputs and resulting ID-token claims. A 200 status on a read-only probe does not prove authorized write behavior.

## Direct vendor references

- Organization API: https://is.docs.wso2.com/en/latest/apis/organization-apis/org-organization-mgt/
- Organization users: https://is.docs.wso2.com/en/latest/apis/organization-apis/scim2/
- Organization model and sharing: https://is.docs.wso2.com/en/latest/guides/organization-management/
- Scoped organization API access: https://is.docs.wso2.com/en/latest/apis/organization-apis/authentication/
- Consent gate: https://is.docs.wso2.com/en/latest/guides/consent-management/
- Conditional authentication: https://is.docs.wso2.com/en/latest/guides/authentication/conditional-auth/configure-conditional-auth/
- WSO2 passkey login: https://is.docs.wso2.com/en/latest/guides/authentication/passwordless-login/add-passwordless-login-with-passkey/
- OAuth token-exchange gate: https://is.docs.wso2.com/en/latest/guides/authentication/configure-token-exchange/


### P2.24 approved organization-view M2M bootstrap (increment)

Source implementation: `scripts/p2/m2m_bootstrap.py`; non-interactive launcher: `scripts/p2/run-approved-orgview.sh`. Local mocked tests: `tests/p2/test_m2m_bootstrap.py` and `tests/p2/m2m-root-guard.test.mjs`. Status: **source-tested, WSO2 live application creation and token scope pending operator execution**. Only one new Aurora application and its `internal_org_organization_view` authorization are approved; all partner mutations remain unapproved.

<!-- P2.24_V13_LIVE_ACCEPTANCE_PENDING -->
- **P2.24 V13 partner provisioning**: source installed; runtime creation and negative acceptance pending. Once live-verified, startup performs authenticated GET-only rechecks and never blindly repeats POST.

<!-- P2_24_V14_APP_SHARING_NOT_YET_AUTHORIZED -->
- **P2.24 V14**: GET-only application-sharing inspection is integrated into startup; app sharing and partner business authorization remain **PENDING** until a specific partner business app and permissions are approved and live-verified.
