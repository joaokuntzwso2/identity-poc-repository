# CIAM v10 — explicit Roles v2 compatibility (P0 authorization)

Status: **original Roles v2 GET-only plan succeeded live on 2026-10-26**;
provisioning and token-based authorization remain unverified. The plan was strengthened
to check each application's `associatedRoles.allowedAudience == APPLICATION`
before allowing writes. Run it again after this guard is installed.

## Why this is necessary

The live v10 image `wso2/wso2is:7.3.0` returned 401 on tenant-scoped
`/scim2/v3/Roles` and 200 on tenant-scoped `/scim2/v2/Roles` with the same
**tenant-qualified Basic administrator** for Aurora and Brisa. The existing
management M2M clients did not receive the requested role-view scope.
Do not change those clients' grants or presume Basic v3 was supported.

WSO2 Identity Server 7.3 documents Roles v2, including application audience,
role permissions and user assignments, but **v2 is deprecated**. The v3 path
remains the default in this repository. This compatibility path is an explicit,
version-pinned alternative; it does not trigger automatically after a v3 error.

Sources:
- https://is.docs.wso2.com/en/latest/apis/role-management/
- https://is.docs.wso2.com/en/latest/apis/role-management/roles-v2-rest-api/

## Read-only validation on the existing Mac checkout

Do not run `fresh`, `bootstrap`, `authorization-apply` or `consent-apply`.

```sh
cd /path/to/poc-implementation
./scripts/ciam-v10.sh authority-status
WSO2_CIAM_V10_ROLE_API=v2 ./scripts/ciam-v10.sh authorization-plan
WSO2_CIAM_V10_ROLE_API=v2 ./scripts/ciam-v10.sh authorization-reconcile
```

Both commands must be GET-only, identify `roleApiVersion: v2` and show
`safeToApply: true` before any authorization write is considered. A
`ROLE_API_VERSION_JOURNAL_PIN_MISMATCH` is an intentional STOP: the existing
private journal is tied to v3. Do **not** edit, delete, or replace that journal
to bypass this refusal. Investigate its prior writes and readbacks first.

Other errors (wrong app, unexpected response shape, missing role permissions,
remote identity drift, consent API status) must also be investigated, not bypassed.

## Extra gates before an apply

1. Read-only plan for both tenants is safe and all remote resources are identified.
2. Existing tenant, OIDC and SCIM-user journals validate as before.
3. The private authority journal is absent or already pinned to `v2`, not legacy v3.
4. Explicit approval is obtained for the two tenant business API resources,
   four OIDC app API grants, four application roles and two existing users.
5. The WSO2 Roles v2 API contract is inspected on the installed image;
   creating a role requires `internal_role_mgt_create`, and assignment of users
   and permissions requires the corresponding scopes/permissions.
6. The application detail GET for each of the four OIDC clients must report
   `associatedRoles.allowedAudience: APPLICATION`. If it reports `ORGANIZATION`
   or omits the field, STOP; do not change role audience implicitly or provision
   role resources. Role audience changes can be destructive. See
   https://is.docs.wso2.com/en/next/apis/application-rest-api/.
7. A failed/ambiguous response is never retried blindly. No v2 scope is
   granted to the existing management M2M applications by this code.

Only after these gates, an operator may choose the **two explicit confirmation**
variables, documented here rather than exposing a one-click provisioning script:

```sh
WSO2_CIAM_V10_ROLE_API=v2 \
WSO2_CIAM_V10_ROLE_V2_CONFIRM=USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES \
WSO2_CIAM_V10_AUTHORITY_CONFIRM=AUTHORIZE_EXISTING_V10_OIDC_AND_ASSIGN_SCIM_USERS \
  ./scripts/ciam-v10.sh authorization-apply
```

The command performs writes to WSO2 port 9444 and is **not** part of the
read-only validation procedure. It records each prepared write, reads it back,
and refuses uncertain results; it must never be run against port 9443.

## Live acceptance still required

After provisioning, verify all four fresh browser OIDC flows. Confirm the
WSO2-issued access token includes the correct audience/issuer/tenant/client
binding and `ciam:profile:read`. Test the protected API with and without this
scope and after permission revocation, considering existing token lifetime and
revocation. Anonymous negative HTTP tests alone do not establish this.

Consent v2 remains independent and **blocked** pending a verified 7.3.0.12+
WSO2 build and activation; this role API selection does not enable consent.
