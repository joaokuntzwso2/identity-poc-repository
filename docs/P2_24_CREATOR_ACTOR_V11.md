# P2.24 — Partner creation actor plan (v11)

## Scope and verified baseline

This is a **read-only plan** for a future, independent Aurora tenant organization-creation actor. The existing dedicated organization-view M2M application remains authorized for only `internal_org_organization_view`. The partner organization has **not** been created. V10 live evidence on 2026-11-04 established the organization-create API resource and its `internal_org_organization_create` scope, but did not grant that scope.

The plan pins the verified v8 M2M app fingerprint, v9 Aurora parent fingerprint, known v10 create-resource fingerprint, existing 7.3.0 Docker image, journal version, and validated local TLS certificate. All records stay in the existing owner-only private directory. The script never outputs tokens, secrets, credentials, full UUIDs, or raw API responses.

### Run

```bash
python3 -m unittest discover -s tests/p2 -p 'test_creator_actor_plan_v11.py' -q
python3 scripts/p2/creator_actor_plan_v11.py
```

The runner refreshes the short-lived existing organization-view token via the already verified v8 readback path, makes authenticated **GET** calls for the API-resource catalog, Aurora partner plan, and the complete Aurora application inventory, then returns a sanitized intent fingerprint. This token refresh is a client-credentials OAuth token POST, **not a management mutation**. It does not use the create permission.

### Plan outcomes

- `CREATOR_APP_ABSENT_SEPARATE_APPROVAL_REQUIRED`: no application with the exact dedicated creator-app name exists in the complete inventory, and the earlier readbacks are intact.
- `CREATOR_APP_EXISTS_REQUIRES_INDEPENDENT_OWNERSHIP_RECONCILIATION`: a named application exists but **is not adopted** or modified without proof of origin.
- Any `BLOCKED` status: unchanged or uncertain prerequisites; investigate without deleting journals, retrying writes, weakening TLS, or touching other tenants.

### Subsequent, separately approved write phase (NOT implemented/executed in v11)

A later increment would create a separate Aurora-only private OIDC M2M actor, permit only `client_credentials`, authorize exactly `internal_org_organization_create` under the verified management API resource, verify the real issued scope, and keep its client secret private. The existing view-only M2M must not gain create permission.

After actor verification, another separately approved partner-creation increment would use **one** guarded POST to `/t/aurora.identity.test/o/api/server/v1/organizations` under the authenticated Aurora parent, and independent GET readback using the view-only actor. It must journal intent before the POST, never blindly retry an uncertain outcome, and verify parent, name, handle, status and cross-tenant denial. No organization user, privileged role, app sharing or delegated administration is implied by creating the partner alone.

References:

- WSO2 IS Organization Management REST API, `POST /organizations`: `internal_org_organization_create`.
- WSO2 Application Management REST API, authorized APIs (RBAC).

**No current deployment upgrade, journal mutation, root-tenant merge or permission grant is performed.**
