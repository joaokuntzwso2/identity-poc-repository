# P2.24 V18 — Aurora Returns ordinary directory bootstrap (source implementation)

The existing V17 sharing journal is `INTENT` and WSO2 PostgreSQL has no current sharing row for the partner portal. No automatic sharing replay is authorized. V18 is installed after V17.2 in both BFF startup paths. Its current live-safe outcome is **PENDING**; it does not create users or groups while the share is unverified.

Once V17 has a complete `VERIFIED` journal **and** independently verified `EXACT` sharing readbacks, V18 checks for a new independently provisioned, partner-bound M2M application. That application must be the exact named `P2 Aurora Returns Partner Directory M2M`, use `client_credentials` only, and hold only these six organization-scoped permissions:

- `internal_org_user_mgt_list`, `internal_org_user_mgt_view`, `internal_org_user_mgt_create`
- `internal_org_group_mgt_list`, `internal_org_group_mgt_view`, `internal_org_group_mgt_create`

The actor's private file is `p2-aurora-partner-directory-actor.private.json`. No actor is auto-created by this package and credentials must never be manually invented or copied. An authorized subsequent actor-provisioning increment will generate the file securely and verify its actual WSO2 metadata and scopes.

When all prerequisites pass, V18's write-enabled engine can create two ordinary, **disabled** demonstration accounts (`p2-aurora-returns-operator`, `p2-aurora-returns-reviewer`) and two unprivileged groups (`AuroraReturnsOperators`, `AuroraReturnsReviewers`), one user per group. These are not real human partner identities. No email, application sharing, roles, permissions, delegated administrator status, or login activation is granted. Random initial passwords and per-operation journals remain private with mode 0600.

Each SCIM2 POST is preceded by a unique durable `INTENT` journal; each completed user/group has an exact GET readback and a `VERIFIED` journal. If any POST returns ambiguously, no automatic replay is allowed. A duplicate unowned remote name is rejected rather than adopted. Child/Brisa/root/Carbon paths are excluded by a purpose-limited HTTPS transport.

**This package does not resolve V17 or provision the separate SCIM M2M actor.** It adds a secure onboarding engine and automatic gate, and leaves customer BFF startup available while those prerequisites are pending. A successful source test is not live WSO2 evidence.

Run `python3 scripts/p2/partner_directory_v18.py status` (GET only) or `bootstrap` (automatic gate). The latter can issue SCIM2 writes **only after** V17 verified sharing and an independently verified, exact-scope, partner-bound actor are present.

Do not commit `.private.json` journals, client credentials, temporary tokens, generated passwords or local CA material. Do not push until integration tests, live acceptance and secret scans pass.
