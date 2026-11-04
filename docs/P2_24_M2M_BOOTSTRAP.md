# P2.24 — Dedicated Aurora organization-view M2M bootstrap

**Environment**: WSO2 Identity Server public `wso2/wso2is:7.3.0` image; exact update build not attested. All paths target `https://localhost:9444/t/aurora.identity.test`. No changes to Carbon Super, Brisa, existing Aurora apps, business ledgers, users, roles or journals.

## Authorization already approved

Approval in the current work session: **create one new Aurora tenant-root M2M application** with **only** `internal_org_organization_view`, if the complete application inventory has no application with the dedicated name. This does **not** authorize partner creation, account creation, role grants, consenting, WSO2 upgrade, or secret rotation.

## Contracts and prerequisites

- `GET /t/aurora.identity.test/api/server/v1/applications`: read-only application list; `internal_application_mgt_view` or tenant-authorized Basic.
- `GET /t/aurora.identity.test/api/server/v1/api-resources` and its detail: verify the actual organization-management resource UUID and scope name.
- `POST /t/aurora.identity.test/api/server/v1/applications`: one M2M client with `client_credentials` only; `internal_application_mgt_create` or management-authorized Basic.
- `POST /t/aurora.identity.test/api/server/v1/applications/{id}/authorized-apis`: **only** the organization-management API UUID and `internal_org_organization_view`. WSO2 requires `internal_application_mgt_update` plus `internal_application_internal_api_update`, or a tenant-authorized management principal.
- `GET` readbacks, tenant token `POST /oauth2/token`, and `GET /t/aurora.identity.test/o/api/server/v1/organizations/metadata` must all succeed. Requesting a scope is *not* proof of receiving it.
- The existing private directory must be owned by the operator, mode 0700. Existing v10 private journals are owner-only mode 0600 and must contain a uniquely identifiable Aurora tenant-admin account. The script does not request any credentials interactively and does not enumerate your home directory. It also attempts to use the repository's existing `private_context()` loader if the journals use an older structure.
- The script rechecks that `wso2-ciam-v10-is-1` is running the **exact, previously observed** public GA image SHA-256 and that `authority-preflight` passes with journal pin `v2`. A changed container, role pin, or diagnostic blocks without any remote write. The script never upgrades or restarts WSO2.
- Trust chain must be valid via system TLS roots or existing `NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE` configuration. No `-k`, `verify=False`, arbitrary certificate enrollment, or redirect following.
- The application detail must actually return the OIDC client secret to the authorized tenant administrator (requires WSO2 `internal_application_mgt_client_secret_view` permission when applicable). If unavailable, stop; do not generate or rotate secrets to work around this.

## Noninteractive operator execution

One-command, tested workflow (tests, read-only plan, the authorized app creation if missing, real readback, then GET-only partner plan):

```bash
bash scripts/p2/run-approved-orgview.sh
```

Equivalent stepwise commands:

```bash
python3 -m unittest discover -s tests/p2 -p 'test_m2m_bootstrap.py' -v
node --test tests/p2/m2m-root-guard.test.mjs
python3 scripts/p2/m2m_bootstrap.py plan
python3 scripts/p2/m2m_bootstrap.py apply --approve=CREATE_AURORA_ORG_VIEW_M2M
```

`plan` is GET-only. `apply` repeats a complete GET inventory before any mutation, writes a durable intent journal before the first POST and advances its journal before the second POST. Do **not** rerun when the journal is `CREATE_INTENT` or `AUTHORIZATION_INTENT`: a write outcome may be unknown. A `COMPLETE` journal is verified again by WSO2 GET readback and a renewed scoped access token, with no new management mutation.

Private outputs (never add to Git):

- `~/wso2-ciam-v10/private/p2-aurora-orgview-bootstrap.private.json` — durable state, app/root UUIDs, no credentials.
- `~/wso2-ciam-v10/private/p2-aurora-orgview-client.private.json` — generated client ID and secret, 0600.
- `~/wso2-ciam-v10/private/p2-aurora-root-token.private.txt` — short-lived bearer for the existing P2 operator CLI, 0600.

The test suite uses fake HTTP replies and cannot establish live GA feature acceptance. Only sanitized output from the local approved `apply` can establish operational progress. If a write is ambiguous, do **not** delete journals, rerun POST, or create a replacement application; reconcile its exact app ID and authorization directly from WSO2 first.

## Subsequent GET-only organization plan

After `apply` verifies a tenant root, read the root ID from the private journal (without printing it) and invoke the read-only P2 operator CLI:

```bash
export P2_PRIVATE_DIR="$HOME/wso2-ciam-v10/private"
export P2_TOKEN_FILE="$P2_PRIVATE_DIR/p2-aurora-root-token.private.txt"
export P2_ROOT_ORG_ID="$(python3 -c 'import json,os,pathlib;print(json.loads((pathlib.Path(os.environ["P2_PRIVATE_DIR"])/"p2-aurora-orgview-bootstrap.private.json").read_text())["rootId"])')"
node scripts/p2/cli.mjs plan-partner
```

`create-partner` is explicitly **not** approved in this increment.

## Runtime evidence to keep (sanitized)

Record `plan` and `apply` status/code, HTTP readback success, exact granted scope, root metadata type/handle checks, counts, owner-only journal file modes, and `node --test` results. Never publish credentials, raw bearer tokens, full organization UUIDs, cookie values, or tenant-admin passwords.

## WSO2 documentation

- https://is.docs.wso2.com/en/latest/apis/application-rest-api/
- https://is.docs.wso2.com/en/latest/apis/organization-apis/org-organization-mgt/
- https://wso2.com/identity-platform/docs/guides/applications/register-machine-to-machine-app/
