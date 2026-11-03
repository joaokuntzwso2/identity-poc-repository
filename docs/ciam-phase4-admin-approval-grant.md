# Phase 4 — authorized administrator approval grant (2026-11-03)

## Approved authorization policy

**Aurora and Brisa Web/Mobile business administrators may approve customer cases.**
This matches the original, SHA-pinned Phase 4 `desired.json`: administrator
roles must have exactly `ciam:cases:read`, `ciam:cases:review`,
and `ciam:cases:approve`.

The operator's fresh GET-only audit found four administrator roles with only
`read` and `review`. Customer and seller roles, all role IDs, audiences, and
memberships matched. This change grants only the missing `approve` scope to
those **four journaled administrator roles**; it does not add members, create
roles, change application/API authorization, or update the Phase 4 desired
specification or existing private journals.

A granted scope **is not sufficient to approve**: the existing BFF requires
an authenticated, correct-tenant authorized user, denies self-approval, and
requires a freshly verified WSO2 TOTP step-up at approval time. Positive MFA
approval is still not tested and must not be reported as a pass.

## New reconciliation tool

- `scripts/ciam-admin-approval-grant.py --plan` (default) performs GET-only
  verification of the Phase 4 source digests and spec-journal SHA, both WSO2
  API resources and their scopes, four application RBAC authorizations, all
  ten journaled business roles, their users and audiences, and administrator
  pre-grant states. No remote or local journal writes.
- `--apply` requires a clean Git tree **and** explicit environment confirmation.
  It creates a new separate `0600` journal under
  `~/wso2-ciam-v10/private/bootstrap-admin-approval-grant-v1.private.json`
  (or the existing, explicitly configured `CIAM_V10_HOME`) before the first
  mutation and fsyncs before each SCIM v2 PATCH.
- PATCH payload uses *only* `add` on `permissions` with value
  `ciam:cases:approve` for the four exact journaled role IDs. It does not
  replace the permissions collection (which could remove other grants).
- A fresh GET confirms audience, role ID/name, unchanged membership, and the
  **exact** three-scope role state after each PATCH. Success is not inferred
  from the HTTP response alone. Original Phase 4 `verify` must also succeed.
- `--verify` is GET-only; it requires the supplemental migration journal and
  confirms all four final grants. No browser, TOTP, case mutation, or database
  consistency acceptance is claimed.
- On timeout, 403, unexpected HTTP response, or uncertain write the journal
  retains `patch-started`, and **automatic retry is refused**. If an operator
  deliberately reruns `--apply` later, a fresh exact remote readback can
  reconcile a previously committed grant, but it will never repeat a PATCH
  whose outcome was ambiguous and whose scope is still missing. Stop for
  manual incident review in that case.

SCIM 2 Roles v2 reference:
https://is.docs.wso2.com/en/7.3.0/apis/role-management/roles-v2-rest-api/

## Installation and execution

1. Apply source ZIP via its dry-run / `--apply` installer. Commit the three new
   files before any WSO2 writes.
2. Inspect the read-only plan:

   ```bash
   python3 scripts/ciam-admin-approval-grant.py --self-test
   python3 -m unittest discover -s tests -p test_ciam_admin_approval_grant.py -v
   python3 scripts/ciam-admin-approval-grant.py --plan
   ```

   It must report all four administrator roles as `missing` and no other drift.
   **Stop if the plan is unexpected.**
3. Only after confirming this exact policy and plan, authorize the four specific
   scope grants:

   ```bash
   WSO2_CIAM_ADMIN_APPROVAL_CONFIRM=GRANT_CIAM_CASES_APPROVE_TO_FOUR_JOURNALED_ADMIN_ROLES \
     python3 scripts/ciam-admin-approval-grant.py --apply
   ```

   A nonzero exit is a stop signal, not permission to run original Phase 4
   `apply` or retry an uncertain PATCH.
4. Verify read-only:

   ```bash
   python3 scripts/ciam-admin-approval-grant.py --verify
   python3 deploy/ciam-v10/phase4/business-bootstrap.py verify
   DEMO_EXPECTED_COMMIT="$(git rev-parse HEAD)" npm run demo:preflight -- --deep-readback --no-browser
   ```

   Only management/role readback can pass at this stage. Seller/admin real
   token issuance, negative/positive MFA, business persistence/durability,
   WCAG keyboard/AT and other manual gates remain unverified.

## Operational precautions

- Do not rerun full bootstrap or replace the original Phase 4 journal.
- Do not delete the supplemental journal or its lock after an uncertain
  outcome; reconcile under change control. Existing private journals are
  never rewritten by this migration.
- Access tokens already issued before new role permissions were granted may
  retain their old scopes. Require **new login / token issuance** for any
  subsequent administrator acceptance tests.
- Commit of source files changes Git provenance: restart only the BFF with
  `bash scripts/ciam-demo-start-profile.sh` when you need release preflight
  provenance to match. Never restart WSO2 or reset databases for this change.
