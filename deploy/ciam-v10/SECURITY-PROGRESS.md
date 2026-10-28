# CIAM v10 — security implementation checkpoint

**Status date:** 2026-10-28. This document describes readbacks and tests from a
local WSO2 Identity Server 7.3.0 proof of concept, **not** production certification.
The private WSO2 journals, session evidence, credentials and inspection logs
must remain outside Git.

## Implemented in the source tree

- Four independent OIDC browser clients across `aurora.identity.test` and
  `brisa.identity.test`, with tenant-pinned issuer/client validation and
  a strict signed ID-token subject ↔ active access-token-introspection `sub`
  equality requirement; no email/username matching fallback.
- Live BFF default-deny routing, strict callback parameter parsing, strict
  cookie parsing, and an optional **private**, sanitized four-client binding
  probe. The probe proves actual OIDC callback binding, not business scopes.
- Cases resource/role read-only bootstrap and existing-role verification;
  application roles remain scoped to their respective OIDC applications.
- A journaled, narrowly scoped SCIM Roles v2 PATCH remediation for preexisting
  Business Administrator WEB/APP roles. The stage requires fresh readbacks,
  a plan digest and explicit confirmation, and stops on uncertain outcomes.
- Isolated BFF test harness using test-only OIDC clients and an ephemeral HTTPS
  signing fixture, including a positive signed callback and rejection of
  cross-subject introspection. Production BFF security code was **not** relaxed
  to repair outdated regression tests.

## Verified local evidence (2026-10-28)

| Gate | Evidence | Interpretation |
|---|---|---|
| Real four-client BFF subject binding | 4/4 exact session/token subject proofs | Identity-bound callbacks, not business authorization |
| Existing Aurora/Brisa Cases API resources | Identifier `urn:ciampoc:service-requests:v1` and all four scopes | Already existed; **not** owned/adopted by the new bootstrap |
| Four application API authorizations | All four case scopes, RBAC policy readback | API client authorization alone does not confer user grants |
| Customer/seller role memberships | Ten existing case-scope roles inventoried; expected direct customer/seller members | Not evidence of effective federation/transitive access |
| Local SCIM groups | One enumerated per tenant, zero references to Cases roles | Not proof that all possible external groups are absent |
| Administrator approval remediation | Four one-per-role PATCH responses and verified readbacks | `approve` removed; `read` and `review` retained; role IDs and memberships preserved |
| BFF unit/integration regressions | **77 passed, 0 failed, 0 skipped** | Local test suite green; not a live WSO2 business API test |
| WSO2 conditional update enforcement | Not independently verified; no ETag in observed role readbacks | Concurrency caveat remains |

The four administrator PATCH operations changed role permissions **in the
local WSO2 environment**, not in Git. The code and tests for their guarded
remediation are versioned; private write-ahead journals and role identifiers
are not. There are no new Cases API/role resources created by this checkpoint.

## Reproduce source checks without changing WSO2

```bash
npm --prefix services/identity-bff test
python3 -m unittest discover -s deploy/ciam-v10/cases-rbac/tests -p 'test_bootstrap.py' -v
python3 -m unittest discover -s deploy/ciam-v10/cases-rbac/tests -p 'test_existing_roles.py' -v
python3 -m unittest discover -s deploy/ciam-v10/cases-rbac/tests -p 'test_admin_approval_remediation.py' -v
./scripts/ciam-v10.sh test
```

The Cases provisioning scripts have separate `plan`, `verify`, and `apply`
behaviors. **Do not run additive Cases resource/role `apply` on this
pre-provisioned environment:** the objects already exist and are not journal-owned
by that bootstrap. The administrator-remediation `apply` is a **write**, and its
specific four-role change has already been completed and verified on this lab.
Do not replay it or reset the private journal.

## Incomplete acceptance gates

1. Run real business-service positive and negative authorization requests:
   customer create/read, Aurora seller review/approve, administrator denial,
   revoked/expired token denial, self-approval denial and cross-tenant denial.
2. Attest MFA/step-up assurance for seller approval on the **actual live** token
   and business API path; a role holding `approve` does not prove MFA occurred.
3. Characterize federated/transitive role access and WSO2 conditional-update
   concurrency guarantees separately. A missing SCIM `groups` role field is
   **not** evidence of zero possible inherited permissions.
4. Keep sensitive state out of the public repository:
   `~/wso2-ciam-v10/private/`, `~/wso2-ciam-v10/inspection/`, local client
   secrets, access/ID tokens, certificates, and browser cookies.
