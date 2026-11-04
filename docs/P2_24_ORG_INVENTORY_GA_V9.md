# P2.24 organization inventory GA compatibility (v9)

Source-only, GET-only increment for the verified Aurora organization-view M2M client. It does **not** create a partner organization, a client, API authorization, role, or user. It does not repeat any uncertain management write.

## Prerequisites

- `wso2-ciam-v10-is-1` running the unchanged `wso2/wso2is:7.3.0` GA image with the pinned image ID.
- Existing 7.3.0 authority journal pinned to Roles API `v2`.
- Previously reconciled `p2-aurora-orgview-bootstrap.private.json` with `phase: COMPLETE` and `reconciledBy: P2_24_GET_ONLY_AUTHORIZATION_READBACK_V8`.
- Previously verified, owner-only local TLS public certificate and application credentials (these are read locally and NEVER copied to the repository).
- Node and Python 3 available in the repo environment.

## Install / run (no prompts)

From the repository root:

```bash
unzip -oq "$HOME/Downloads/p2_24_org_inventory_v9.zip" -d "$HOME/Downloads"
python3 "$HOME/Downloads/p2_24_org_inventory_v9/install.py" "$PWD"
bash scripts/p2/run-org-inventory-v9.sh
```

The installer changes only `scripts/p2/guarded-org.mjs`, `scripts/p2/cli.mjs` and adds read-only runner/tests/documentation. It refuses unknown source layouts. It is idempotent.

The runner reruns the established GA image/authority guard; makes verified application and authorized-APIs **GET** readbacks, issues a short-lived OAuth client-credentials token (OAuth token endpoint POST only), rotates only the owner-only local token file, and invokes `inspect-partner-inventory` then `plan-partner` (GET-only). It never runs `create-partner` or touches the existing application authorization.

## Interpretation

- `AURORA_ORGANIZATION_LIST_STRUCTURE`: sanitized first-page shape; informational only.
- `READ_ONLY_PARTNER_PLAN_VERIFIED` with action `CREATE`: no exact partner found in a *fully verified* inventory, **not** approval to create.
- `READ_ONLY_PARTNER_PLAN_VERIFIED` with `ALREADY_PRESENT`: partner full detail matched parent, name, handle and active state.
- `ORG_INVENTORY_INCOMPLETE` or `ORG_FALLBACK_COLLECTION_INCOMPLETE`: no plan can be trusted. Do not create a partner.
- `ORG_PAGINATION_*`, `ORG_NEXT_*`: incomplete or untrusted pagination. Stop without mutations.

The implementation follows the WSO2 Organization Management GET response contract, which uses `organizations` and `links` (including `rel: "next"`). Bounded pagination reconstructs tenant-qualified URLs instead of trusting server-provided URLs. Empty omitted collections are accepted only after independent root no-children attestation, or independently enumerated unfiltered immediate-child inventory. Cross-tenant requests remain blocked.

## Evidence limitations

Offline tests verify parser, normalization and guard logic; only user runtime output can prove live WSO2 list behavior. Do not equate a read-only `CREATE` plan with a completed partner or authorized provisioning.

Before committing, run `npm test`, `npm run build`, `git diff --check`, review `git diff`, and scan for private paths/secrets using the existing publication hooks. Never stage the private journal or token/certificate secrets.
