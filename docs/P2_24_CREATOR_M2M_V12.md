# P2.24 V12 — Approved, Aurora-only partner-creator M2M bootstrap

## Approval and prohibited activity

The operator approved **one new Aurora root-tenant M2M application** with only `internal_org_organization_create`, under the existing `wso2/wso2is:7.3.0` deployment. They **did not approve creation of a partner organization**. This increment never invokes the organization-create endpoint; it does not alter Brisa or Carbon Super, existing identities, the view-only M2M application, or the WSO2 installation. Do not edit the scripts to broaden permissions or bypass prerequisites.

The WSO2 Application Management API uses:

- `POST /t/aurora.identity.test/api/server/v1/applications` with `isManagementApp: true` and only `client_credentials` (one attempt).
- `POST /t/aurora.identity.test/api/server/v1/applications/{appId}/authorized-apis` with the *verified* Organization Management API resource ID, `policyIdentifier: RBAC`, `scopes: ["internal_org_organization_create"]` (one attempt).
- Required authority to perform these operations: authorized tenant-qualified management credentials, normally `internal_application_mgt_create` and `internal_application_mgt_update` (management Basic authentication is supported by the API). The scope granted to the **new** app is **not** these administration scopes.
- `POST /t/aurora.identity.test/oauth2/token` may be used to prove issuance of exactly one create scope. Its bearer token is never printed or persisted.

API reference: [WSO2 application management REST API](https://is.docs.wso2.com/en/7.0.0/apis/application-rest-api/); [organization management REST API](https://wso2.com/identity-platform/docs/apis/organization-apis/org-management). Validate runtime contracts on the installed 7.3 GA container, not documentation alone.

## Automatic operation

From the repo root:

```bash
python3 "$HOME/Downloads/p2_24_creator_m2m_v12/install.py" "$PWD"
bash scripts/p2/run-approved-creator-v12.sh
```

The runner executes offline tests, the GET-only V11 plan, then the narrowly approved `apply`. It has no interactive prompts. Pre-existing authorized Aurora management credentials are loaded by the same v10 credential bridge that previously passed live authority readback. The pinned default TLS certificate is verified normally; do not disable certificate checks.

**Important:** The scripts are *source-tested*, not live-tested in your local WSO2 runtime. Any uncertainty stops execution. Re-running `apply` is safe only when the journal already has `COMPLETE` and fresh GET readback and token verification pass; an incomplete journal **never triggers another management POST**.

## Persistent evidence and provenance

All files are created **only** in the existing owner-only private directory (default `~/wso2-ciam-v10/private`):

- `p2-aurora-partner-creator-bootstrap.private.json` — write-ahead intent, immutable Aurora pins, prior inventory IDs, app ID, resource ID, attempted-write counter, phases, final verification markers. Does not contain secrets.
- `p2-aurora-partner-creator-client.private.json` — retrieved new client ID and secret; owner-only 0600. **Never commit or paste this file.**
- `p2-aurora-partner-creator-v12.lock` — prevents concurrent local V12 runs.

Phases: `CREATE_INTENT` (before first POST), `AUTHORIZATION_INTENT` (before second POST), `AUTHORIZATION_GET_VERIFIED`, `COMPLETE` (only after exact token-scope verification). A failed token check can be completed with a GET-only management verification plus an OAuth token request; no management POST is repeated.

For WSO2 create `201` with no application ID, a fallback checks the entire application inventory, requires exactly one new ID and one exact-name candidate relative to the persisted prior seven IDs, then fetches the application detail and OIDC configuration. It does **not** infer ownership from the name alone. Original HTTP response identification is distinguished in the journal as `201_PLUS_EXACT_INVENTORY_DELTA_GET`. The fallback proves a strong match, not cryptographic authorship.

An authorization HTTP response other than `201` does not by itself imply failure or success. Fresh `GET /authorized-apis` must prove **exactly one** authorized API resource, `RBAC`, and the sole `internal_org_organization_create` scope before token validation. No other API authorization is acceptable.

## Stops and recovery

If `CREATE_APP_POST_*`, `POST_CREATE_*`, `AUTHORIZATION_*` or `CREATOR_TOKEN_*` appears, **do not run apply again or delete/modify the journal**. Inspect read-only with:

```bash
python3 scripts/p2/creator_m2m_v12.py reconcile
```

It makes *no application or organization management writes* and does not repeat the create-scope authorization. Depending on journal phase it may refresh the existing view-only M2M access token or request a create-scope token on fully complete verification; OAuth token issuance is not a management write. Partial-state reconciliation intentionally does not resume POST.

If `reconcile` reports `CREATE_SCOPE_OBSERVED_GET_ONLY_NO_REPLAY` for `AUTHORIZATION_INTENT` or `AUTHORIZATION_GET_VERIFIED`, the following optional operation can **only** verify the previously persisted scope, issue an OAuth token, and complete the private journal locally—no application or organization-management POST:

```bash
python3 scripts/p2/creator_m2m_v12.py finish --readback-only
```

It refuses changes in the original seven-app inventory, application, API resource, credentials, or authorization. Work through the recorded phase, authorized-APIs readback and rollback review before approving any further remote mutation. No deletion, reset, or secret rotation is automated.

If the new application was created but scope authorization failed, retain the journal and application pending explicit review. Do not auto-delete a newly created identity object (which would erase forensic evidence). Revocation/deletion requires a separately approved, readback-verified procedure.

## Acceptance and phase distinction

`CREATOR_APP_AND_EXACT_CREATE_SCOPE_VERIFIED` means source + WSO2 GET readback + OAuth scope issuance accepted for this creator app. It **does not** mean a partner exists or that cross-tenant denial has been demonstrated. Collect sanitized report, exit status and independent restricted-token denial tests separately. The P2.24 partner onboarding, delegated admin user management, and business-access journeys still need separate implementation and approval.

Verification to run after success (these do not create a partner):

```bash
python3 scripts/p2/creator_m2m_v12.py reconcile
node --test tests/p2/*.test.mjs
npm test
npm run build
git diff --check
git status --short
```

Commit only after review and local guards pass, pushing using the repository's explicit `refs/heads/main:refs/heads/main` policy. Never add private files or live tokens.
