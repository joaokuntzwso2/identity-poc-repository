# P2 operator-run acceptance, with no destructive actions

**Do not run a mutation merely to see if an API accepts it.** This is an incremental source contribution, not evidence of deployment. The original WSO2 7.3.0 GA image/databases/tenants must stay untouched until separately approved. Never use `fresh`, `down -v`, delete tenant, replace volume, or upgrade in place.

## 0. Baseline and source tests

From the existing Mac repository (after applying the source package):

```sh
cd "$(git rev-parse --show-toplevel)"
node --version # must be >=22
node --test tests/p2/*.test.mjs
node --check services/identity-bff/src/server.js
npm test
npm run build
./scripts/ciam-v10.sh authority-preflight
# inspect only; never mutate the current WSO2 container:
docker inspect -f 'name={{.Name}} image={{.Config.Image}} imageID={{.Image}} running={{.State.Running}}' wso2-ciam-v10-is-1
```

The current CLI validates a **pinned Aurora HTTPS endpoint on localhost:9444**. No endpoint is probed until an operator has supplied a valid private token file. The current image tag alone does not attest the update level. Capture an independent updater/build record, preserving no credentials in proof.

## 1. Aurora root organization — read-only preflight

Create a **separate least-privilege OAuth principal**, not the existing blanket tenant owner, with `internal_org_organization_view` for a read-only plan and additionally `internal_org_organization_create` only for the approved creation. Refer to the exact runtime OpenAPI/grant model. Obtain the Aurora root organization ID from the *authenticated* WSO2 org metadata; verify independently that it is `aurora.identity.test` and **not** Carbon Super/Brisa. Store the bearer in a private file outside Git (0600, current operator owner; no token in terminal history). Store the ID only in the local operator environment, never in public evidence.

```sh
export P2_PRIVATE_DIR="$HOME/wso2-ciam-v10/private"
export P2_TOKEN_FILE="$P2_PRIVATE_DIR/p2-aurora-root-token.private.txt"
export P2_ROOT_ORG_ID='REPLACE_WITH_AURORA_ROOT_UUID'
export NODE_EXTRA_CA_CERTS='REPLACE_WITH_VERIFIED_WSO2_CA_PEM_ABSOLUTE_PATH'
node scripts/p2/cli.mjs plan-partner
```

The tool refuses a missing/mismatched root metadata ID; refuses more than one exact name, incomplete pagination, wrong parent, wrong orgHandle and a non-ACTIVE existing partner. It prints only SHA-256-derived truncated object fingerprints. **Do not treat `CREATE` as proof that an organization exists.**

## 2. Single guarded partner creation

Only after the plan reports `CREATE` and a reviewed approval is recorded:

```sh
node scripts/p2/cli.mjs create-partner --confirm=CREATE_AURORA_RETURNS_PARTNER
node scripts/p2/cli.mjs plan-partner
```

The script first writes `p2-aurora-partner-create.private.json` intent (mode 0600), POSTs **once** with `parentId` bound to metadata, and requires a GET by returned ID matching name, handle, ACTIVE status and exact parent. It never retries a network exception, timeout, or uncertain POST. If the private journal is `INTENT`, stop: reconcile manually via authenticated GET; **do not delete the journal and replay**. A second create execution is deliberately refused after a committed journal; use `plan-partner` for idempotent readback.

**Required evidence:** observed 201 and GET 200, exact parent verified, partner details match, wrong-tenant token access denied. These were **not executed** by this package author.

## 3. Delegated child SCIM read / suspension

Generate a *separate organization-switched* OAuth token authorized only for the resulting Aurora partner organization, with `internal_org_user_mgt_list/view/update` as needed. Ensure the token cannot read or mutate Aurora parent, Brisa, or an Aurora sibling. Never reuse a privileged Aurora root creation token for child lifecycle operations.

```sh
export P2_TOKEN_FILE="$P2_PRIVATE_DIR/p2-aurora-partner-token.private.txt"
export P2_CHILD_ORG_ID='REPLACE_WITH_CHILD_UUID_FROM_PRIVATE_READBACK'
node scripts/p2/cli.mjs child-users
# Once a sacrificial test user exists in this partner and the action is approved:
export P2_TARGET_USER_ID='REPLACE_WITH_EXISTING_CHILD_SCIM_USER_UUID'
node scripts/p2/cli.mjs disable-user --confirm=DISABLE_AURORA_PARTNER_USER
```

`disable-user` requires metadata to match the child, GET target user `active:true`, durable mutation intent, a single SCIM PATCH setting `active:false`, and GET readback `active:false`. It refuses unknown state, wrong ID, 401/403/404 and all ambiguous outcomes. WSO2 business access must additionally be tested with **old tokens, old sessions and fresh login**; a successful SCIM readback does not prove immediate session/token revocation. If introspection remains active, explicitly revoke sessions/tokens or change token/session policy through a separate reviewed action and retest.

## 4. Operational acceptance gates by phase

| Phase | Live positive | Mandatory negative | Proof missing until |
|---|---|---|---|
| P2.24 | Partner create/readback; child user/group/app role, real delegated UI and business request | Child administrator denied parent/sibling mutation, Brisa access, escalation | All tests occur with real separate root and child tokens |
| P2.25 | WSO2 purpose/version persisted grant, update, revoke, downstream denial | Decline and revoke block business processing, crossed subject rejected | Isolated **7.3.0.12+** environment and v2 API enabled |
| P2.26 | Base login succeeds; sensitive seller approval genuinely steps up with verified ID-token `amr`, `auth_time` | Expired/missing MFA and wrong role denied; policy backend outage fails closed | Conditional login config and real login evidence |
| P2.27 | WSO2 My Account passkey enrollment, passkey login and credential revoke | Cancel, unknown credential, wrong RP origin, lost device, org boundary | Supported browser and WSO2 FIDO2 config independently verified |
| P2.28 | Controlled external OIDC/SAML authentication, verified issuer/JWKS and mapping | Bad signature, missing unique immutable ID, IdP outage, cancel, no Brisa business scope | Controlled IdP and tenant-specific WSO2 connection configured |
| P2.29 | SCIM create/update/roles/suspension and readbacks for customer, seller, partner | Inactive user denied business API despite existing session/token | Token invalidation policy and real request tested |
| P2.30 | Cross-system request ID links WSO2 event to BFF business event | Evidence cannot leak token/PII, missing trace is marked `UNOBSERVED` | WSO2 event/log pipeline installed |
| P2.31 | Branded Aurora and Brisa flows; retail/approval/partner journeys each demonstrate identity outcome | Wrong brand/role/case denied; no synthetic ID evidence | Browser end-to-end acceptance |
| P2.TE | `act` actor identity, `sub` user identity, scope attenuation | Wrong actor/issuer, scope escalation, audience switching denied | Separate **7.3.0.18+** environment & approval |

## 5. Sanitized evidence contract (private first, publish after review)

A valid `VERIFIED_LIVE` record contains: `phase`, `timestamp_utc`, `image_digest`, `installed_update_verified`, `tenant_name`, `actor_type`, `operation`, `request_id`, `http_status`, `subject_fingerprint`, `object_fingerprint`, `readback_status`, `enforcement_source`, `negative_case`, `result`, and a hash or reference to retained private log fragments. Label `source` as `WSO2_LOG`, `WSO2_API`, `BFF_BUSINESS_LEDGER` or `DERIVED_SUMMARY`. A derived summary is never a replacement for a directly observed event.

Never publish access/ID/refresh tokens, full email/name or address, session cookies, raw SCIM claims, passwords, passkey private keys, TOTP seeds, customer data or secret configuration. **No live evidence is included with this package.**
