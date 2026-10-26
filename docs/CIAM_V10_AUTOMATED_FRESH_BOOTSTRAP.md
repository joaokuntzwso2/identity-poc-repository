# CIAM v10: single-command, guarded fresh bootstrap

This is an **additive** orchestration of the existing source-owned tenant, resource,
OIDC, and authority provisioners. No client secret, private journal or PostgreSQL
schema is copied into Git. This is not a disaster-recovery/reprovisioning command.

## One command, ONLY for a genuinely empty runtime

The `fresh-bootstrap` entry point requires **all approvals before Docker starts**.
It refuses any existing runtime home, either occupied port, surviving v10 Compose
containers or v10 Docker volumes; never delete volumes to make this test pass.


```bash
WSO2_CIAM_V10_FRESH_CONFIRM=CREATE_NEW_ISOLATED_PERSISTENT_LAB \
WSO2_CIAM_V10_DEPLOY_CONFIRM=BOOTSTRAP_RECORDED_LAB_RESOURCES \
WSO2_CIAM_V10_ROLE_API=v2 \
WSO2_CIAM_V10_ROLE_V2_CONFIRM=USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES \
  ./scripts/ciam-v10.sh fresh-bootstrap
```

The deprecated v2 API is explicitly selected because the user's deployed GA WSO2
7.3 server returned 200 for tenant-qualified Roles v2 GET and 401 for Roles v3 GET.
No version downgrade occurs implicitly. Select `v3` instead, without the v2
confirmation, only when it is actually authorized in the chosen WSO2 build.

Preconditions: an empty `CIAM_V10_HOME` (default: `~/wso2-ciam-v10`), neither port 4400 nor 9444 occupied, no remaining v10 Compose containers or
`wso2-ciam-v10_` Docker volumes, and Docker queries available. Do **not** point `CIAM_V10_HOME` at an existing lab or database.

`fresh-bootstrap` runs, in strict order:

1. original `fresh`: create only isolated v10 PostgreSQL and WSO2 9444, with
   existing schema and private `deployment.toml` generation intact;
2. bounded HTTPS-readiness probe (no credentials or WSO2 writes);
3. tenant provisioning and readback;
4. management M2M, SCIM users and readback;
5. four OIDC application registrations with explicit `APPLICATION` role audience,
   and authoritative readback;
6. authorization GET-only plan; stop unless `safeToApply: true`, exact tenant
   and channel sets, and explicitly chosen Role API version;
7. authority write-ahead journaled apply with per-operation readback; never
   retry an ambiguous remote operation;
8. read-only authority reconciliation **and** private journal verification;
9. BFF manifest bridge *after* verified authority, launch on 4400;
10. negative HTTP acceptance: four anonymous profile denials, synthetic route
    denial, live mode and `remoteWrites: 0`;
11. report Consent v2 as `BLOCKED` on the public GA 7.3 binary.

If you have already completed `fresh` independently, the one-command finishing
flow is `bootstrap` with the same environment values **except** `FRESH_CONFIRM`.
It requires port 4400 to be free so that an old/stale BFF cannot be adopted.

## What it never does

- Does not touch `wso2-identity-server-1`, 9443, legacy H2, or its BFF.
- Does not remove/reset databases, volumes, tenants, applications, private
  journals, or user credentials.
- Does not silently retry HTTP writes with uncertain outcomes.
- Does not grant scopes to existing management M2M applications beyond their
  original rights.
- Does not synthesize roles, permission grants, or consent.
- Does not call Consent v2 writes unless the supported contract, update level
  and activation have been separately established and implemented.
- Does **not** claim browser-authenticated 200, revocation, or four-channel
  success from provisioning results or anonymous tests.

A crashed/failed stage may have left **valuable partial remote state**.
Do not repeat `fresh-bootstrap`, delete its journals, or rerun apply blindly.
Use `status`, `authorization-reconcile`, `authority-status`, and a review of
private journal status before any explicitly approved continuation.

## Existing v10 environments

Use only non-mutating diagnostics or separately approved additions:

```bash
WSO2_CIAM_V10_ROLE_API=v2 ./scripts/ciam-v10.sh authorization-reconcile
WSO2_CIAM_V10_ROLE_API=v2 ./scripts/ciam-v10.sh authority-status
./scripts/ciam-v10.sh runtime-acceptance
```

**Do not run `fresh-bootstrap` or `bootstrap` against existing provisioned v10.**
Use `bff-runtime-plan`/explicit `bff-restart` if needed; never kill an unknown
port listener.

## Acceptance distinctions

| Verification | Claim after clean bootstrap |
|---|---|
| Tenant, management user/app, OIDC registration and business authorization readback | Provisioning readback verified only |
| Anonymous and synthetic-route fail-closed BFF paths | Verified live only if negative acceptance passes |
| Real 200 protected API using scoped WSO2 token | Pending browser login and access-token evidence |
| Remove WSO2 permission -> protected API becomes 403 | Pending controlled revocation test |
| Consent v2 storage, revoke and enforcement | BLOCKED on unupdated public GA image |
| Original container and persistent data | Never targeted by automated command |

## Validation and publication

```bash
./scripts/ciam-v10.sh test
git diff --check
python3 scripts/security/check_public.py --staged
```

Do not commit credentials, outputs containing access tokens, or private journals.
