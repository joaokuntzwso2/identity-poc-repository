# Requirements 24–31: evidence status after P2.24/P2.29 lifecycle source increment

Do not conflate code installation with live runtime verification.

| ID | State | Evidence | Not yet proven |
|---|---|---|---|
| 24 — B2B & delegated admin | **Partial, extensive live API acceptance** | Verde creation, app sharing, group, role, delegated end-user token, SCIM read 200, delegated ordinary-user create+readback, root 403, Brisa 401, role denial 403 | Browser OIDC partner session, other-partner write denial, complete partner offboarding, real downstream business access |
| 25 — Consent | **Blocked by update-level prerequisite** | GA release/runtime update not attested to have Consent v2; a version-gated plan exists | v2 live customer grant/review/revoke and downstream effect |
| 26 — Adaptive auth | **Foundation only** | Existing challenge/assurance BFF logic and negative tests | WSO2 conditional script/policy and live positive high-assurance login |
| 27 — Passkeys | **Pending** | No independent live enrollment/authentication proof | Real WebAuthn enrollment, login, cancellation and recovery |
| 28 — Federation | **Pending** | No independent external IdP live login evidence | Real controlled federation with claim and tenant isolation |
| 29 — Lifecycle | **Partial** | Previously live-created ordinary Verde user; this source increment implements guarded lifecycle operations | Live group, update/deactivation, revoked-token denial, customer/seller offboarding |
| 30 — Central audit | **Partial** | BFF/business evidence viewer and local sanitized lifecycle readback records | Native WSO2 auth/admin events and cross-service trace correlation |
| 31 — Brand stories | **Partial** | Aurora/Brisa Experience Center and existing business case flows | New journeys with full end-to-end stakeholder proof |

The portal's `WSO2_SCIM_READBACK` records become factual **only after a live operation and subsequent readback**. Installing source files does not update the table above to complete. Deactivation requires an independently verified GA API response; account/session revocation is a separate gate.
