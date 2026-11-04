# Approval-gated WSO2 7.3.0 updates — no active changes

**Current active deployment:** public `wso2/wso2is:7.3.0` GA; do not upgrade or replace as part of this package. Version/update verification is a separate operator-controlled gate. A configured environment variable or JSON attestation is not proof that the running binaries include a feature.

## Required update levels

- **Consent Management v2:** WSO2 docs require **7.3.0.12+**, plus `[consent_mgt] enable_v2_api = true`, the documented Console flow-scopes and purpose/consent features. Webhook events additionally require documented event-profile configuration and subscription. No app-local marketing preference is WSO2 consent evidence.
- **Actor-aware token exchange delegation:** WSO2 docs require **7.3.0.18+**. This uses `actor_token` and a verified `act` claim and is distinct from B2B organization administration. Audience narrowing and restrict-federated-scope features are also 7.3.0.18+.
- **Routine token exchange and B2B organization APIs:** do not infer actor-aware delegation from their availability on 7.3.0 GA.

## Isolated, executable *procedure* (approval required before running)

1. **Freeze change surface:** record current Git SHA, live container image **digest** and exact installed update/build provenance; capture ports, tenant-qualified issuers, OIDC callbacks, PKCE, `deployment.toml` configuration **without displaying secrets**, SCIM and app/role resource counts, business ledger location, org inventory, runtime update entitlement.
2. **Perform verified restorable backups:** snapshot **all** WSO2 databases (`ciam_identity`, `ciam_shared`, `ciam_agent`) consistently, volume/config/cert stores, private bootstrap journals, credential metadata and the BFF business ledger. Prefer atomic volume snapshots with the database backup consistency point. Record encryption, integrity hashes, permissions, and perform an isolated restore test. Do not rely on `docker commit` as a database backup.
3. **Acquire a vendor-supported update image/build:** use WSO2's supported update mechanism/entitlement to get 7.3.0.12+ for consent or 7.3.0.18+ for actor delegation (same release family, not a version guessed from the image tag). Pin immutable digest, JDK compatibility and vendor DB migration guidance. No guessed schema changes.
4. **Clone** the complete persistent deployment to distinct containers, ports, hosts and **restored copies** of each database/volume, with isolated callback registrations and no callback to production. Do not use active DB connections from the clone. Preserve IDs and seed metadata. Rehearse read-only first; only then use controlled disposable test identities for acceptance.
5. **Apply update/configuration to the clone only** by the vendor's exact migration order; validate startup, root realms, issuer/JWKS, all existing four OIDC clients, app roles, SCIM group memberships, TOTP, logout, business authorization, org APIs and backend readbacks. Verify consent endpoint availability and purpose semantics with the runtime's real OpenAPI.
6. **Consent acceptance in clone:** register a real purpose and version; for consenting customers, show purpose, grant/decline, readback, update, revoke, check downstream enforcement, log the action's subject/purpose/version with a trace. Negative cases: another user, another tenant, old purpose version, revocation after session refresh. No JSON consent shape should be invented until the clone's v2 OpenAPI is tested.
7. **Actor delegation acceptance in clone (if approved separately):** exchange real tokens with subject and actor, verify signed claims `sub` and `act`, actor account state, no scope escalation, correct requested audience and deny wrong actor/tenant. Do not reuse delegated tokens as org administration authority.
8. **Formal decision gate:** prepare signed approval with immutable image digest, exact build/update provenance, observed clone proof, downtime window, backup hashes, rollback rehearsal, business owner and scope of change. **STOP here without explicit approval.**
9. **Only after approval:** freeze writes, take final consistent backups, execute vendor-approved update/cutover procedure; do not delete/recreate root tenants or replay provisioning. Validate all four baseline logins and cross-tenant negatives before enabling consent or delegation in the application.
10. **Rollback:** stop newly updated application writes, restore the *consistent full database+volume+configuration snapshot* to the old pinned GA binaries on isolated recovery ports, validate issuer/clients/users/keys, then route traffic. Any writes after cutover (including consents) need a predefined compensation/replay decision; simply reverting the image with a migrated DB is unsafe. Record RPO/RTO and obtain business approval for potential data loss.

This document does not execute an upgrade, disable the active instance, create credentials or claim that the target update is available in the operator's subscription.

Official references:
- https://is.docs.wso2.com/en/latest/guides/consent-management/
- https://is.docs.wso2.com/en/latest/guides/authentication/configure-token-exchange/
- https://is.docs.wso2.com/en/latest/guides/authorization/delegation/
- https://updates.docs.wso2.com/
