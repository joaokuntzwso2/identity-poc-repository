# CIAM P2.24–P2.31 — version/prerequisite/evidence matrix

**Assessment basis:** prior source snapshot and previously inspected public README; the exact current local checkout has NOT been inspected and is known to differ from the original overlay anchors. This overlay is a *source increment*, **not** a new live GA acceptance result. The repository documents four real OIDC browser logins on 2026-10-28, an Aurora business-case creation, brand isolation denials, and TOTP approval denial. Current WSO2 update level must be proven locally; the documented lab image is 7.3.0 GA. Readiness output `--asserted-version` is an operator assertion, not a signed build attestation.

## Topology, API ownership and security invariants

- `carbon.super`: system administration only. Never a partner root or an Aurora/Brisa user/role container.
- `aurora.identity.test`: Aurora identity root tenant; proposed partner `Verde Logistics` (`verde-logistics`) is a **child organization here only**. No changes to the Brisa root.
- `brisa.identity.test`: separate independent root; its user IDs, issuers, sessions and permissions do not transfer to Aurora.
- UI/BFF: `services/identity-bff/src/server.js`, `live-experience-v5.js`; no alternate synthetic principal, test session or client-side role authority.
- Business evidence: existing `services/identity-bff/src/live-cases-v4.js`, persistent append-only `CIAM_BUSINESS_DATA_DIR` ledger. Sensitive data must remain private. The staged `p2-evidence.js` is designed to read **only** already-enforced existing BFF GET endpoints **after the live routes are reviewed and integrated**.
- Organization management token: stored in a 0600 owner-only private **file**, never in the browser, README, URL or Git. WSO2 authorizes the management permission, not the CLI. The CLI restricts the tenant, requires explicit fingerprint approval and compares parent IDs after all writes; this is defense in depth, not a substitute for org-scoped OAuth RBAC.

## WSO2 IS 7.3.0 GA capability matrix

| Feature | Documentation and API | Version prerequisite | Security/config prerequisites | Source increment | Current live acceptance |
| --- | --- | --- | --- | --- | --- |
| P2.24 B2B | `GET/POST /t/{tenant}/o/api/server/v1/organizations`, `GET /.../self`, `GET /.../{id}`, `PUT /.../{id}`. Requires `internal_org_organization_view/create/update` as appropriate. Organization SCIM, roles and application sharing separately | Organization Management API documented in 7.3.0 | Verify tenant root self ID, OAuth token audience/scopes, delegated role assigned inside partner org, actual org-issued tokens, app sharing and cross-org 403 | `scripts/p2-org*.mjs`: plan, create, readback, deactivate only | **NOT TESTED LIVE**, no partner administrator interface |
| P2.25 Consent | WSO2 Consent Management v2 purposes/elements/consents; policy and preference login flow/My Account | **7.3.0.12+** | `[consent_mgt] enable_v2_api=true`, Console scopes, purpose versioning, proper OAuth scopes and evidence, conditional event webhooks | Version gate only | **BLOCKED on GA**; do not use app-local preferences as WSO2 evidence |
| P2.26 Adaptive auth | WSO2 Application Login Flow + conditional scripting, Step 1 authenticators, Step 2 TOTP/Passkey | Supported feature family in 7.3; verify deployed build/config | Require provisioned factor, selected real role/group/risk input, permitted script functions, fail closed, signed ID-token `acr`,`amr`,`auth_time`, fresh transaction | Existing approval-stepup code preserved; new evidence reader shows only released claims | **NOT VERIFIED POSITIVE**, previously recorded negative TOTP case |
| P2.27 Passkeys | WebAuthn/FIDO2 and passkey in WSO2 login flow, My Account registration | Documented for 7.3, precise build/API readback still required | Trusted HTTPS RP origin, browser compatibility, WSO2 My Account enrollment, device recovery, credential owner/tenant readback | No fake passkey implementation | **NOT TESTED LIVE** |
| P2.28 Federation | Standard OIDC IdP in WSO2 tenant + JIT account policy + login-flow routing | Documented for 7.3 | Controlled external IdP, issuer/metadata/JWKS, callback URI, claims mapping, mapping of external subject to WSO2 user, separate business role and scope assignment | No IdP credentials or synthetic provider | **NOT TESTED LIVE** |
| P2.29 Lifecycle | Tenant-qualified SCIM2 Users/Groups/Roles, account disabling config and token/session revocation | SCIM2 in 7.3; account-disabled claim semantics must be proven for target build | `internal_user_mgt_*` and authorized group/role scopes, managed user IDs, deny stale tokens, verify account disabled claim mapping | Plan for guarded SCIM implementation only | **NOT TESTED LIVE**. Official current documentation gives a contradictory `accountDisabled:false` disable example; do not automate until readback semantics verified |
| P2.30 Audit | WSO2 event/log exporters + BFF access decisions + private business ledger | Confirm events enabled/available in exact update | Correlation IDs, tamper protection, strict PII minimization, storage access control, limited retention, purge/subject rights design | `p2-evidence.js` prepared as a read-only BFF evidence viewer; **not routed by this recovery** and not a native event collector | **PARTIAL SOURCE VIEW ONLY**, not complete central audit |
| P2.31 Branding | WSO2 branding preferences/organization branding + same four tenant OIDC clients | Verify specific 7.3 endpoint and permissions | Per-tenant login origin, no synthetic user creation, browser logout and domain tests | Advanced industry stories in prepared evidence UI assets, **not yet connected to the Experience Center** | **PENDING LIVE BROWSER PROOF** |
| Separate token-exchange OBO | RFC 8693 subject token and actor token, resulting `act` claim | **7.3.0.18+** | Both users resolve correctly; scopes attenuate; signed real `act`, checked authorized party and audience; negative escalation tests | Version gate only | **BLOCKED on GA** (not equivalent to organization admin) |

## Acceptance gate (must remain false until recorded)

For **each feature** capture: pinned product version/build image digest and config, correct root/child tenant, scopes and application/API audience, source revision, real positive result, negative unauthenticated/no-scope result, foreign-organization or opposite-brand denial, mutation readback, redacted request/trace ID, rollback validation and exact observed timestamp. Keep private raw evidence outside Git, and commit only high-level sanitized assertions. Only an authorized operator executes mutations and writes a private journal.

P2.24 boundary negatives required: partner A admin must fail to manage partner B, its root parent or Brisa. The current CLI uses a root authorized operator token for bootstrap; **this is not delegated administration**. A partner user-facing admin UI must authenticate separately through the correct org, use an org-scoped token and enforce the org ID in both authorization and API path. Root token permissions must not be repurposed as delegated permissions.

P2.29 session caveat: disabling a WSO2 user alone does not guarantee pre-existing JWT access tokens or BFF sessions become unusable. The repository's live introspection is useful, but active token revocation and session termination must be verified independently; if active tokens remain valid, deny protected operations by fail-closed account-state checks or a supported revocation mechanism, tested with a token issued **before** the disable operation.

## Primary references

- B2B Organization API: https://is.docs.wso2.com/en/latest/apis/organization-apis/org-organization-mgt/
- Consent Management: https://is.docs.wso2.com/en/latest/guides/consent-management/
- OBO token-exchange delegation: https://is.docs.wso2.com/en/latest/guides/authorization/delegation/
- Adaptive Authentication: https://is.docs.wso2.com/en/latest/guides/authentication/conditional-auth/configure-conditional-auth/
- Passkeys: https://is.docs.wso2.com/en/latest/guides/authentication/mfa/add-passkey-login/
- Federated OIDC IdP: https://is.docs.wso2.com/en/latest/guides/authentication/federated-login/add-oidc-idp/
- WSO2 manage users: https://is.docs.wso2.com/en/latest/guides/users/manage-users/
