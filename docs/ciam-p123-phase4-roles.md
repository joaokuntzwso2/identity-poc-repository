# P1.23 — Phase 4 business role drift (2026-11-03)

## Live, GET-only evidence from operator

`ROLE_PERMISSIONS_DRIFT` in `business-bootstrap.py verify` was independently inspected
with ten journaled SCIM v2 roles. Six roles match the desired Phase 4 contract exactly:
all four customer roles, plus the two Aurora seller roles. Four roles do not match:
Aurora Web, Aurora App, Brisa Web and Brisa App **administrator** roles have
`ciam:cases:read` and `ciam:cases:review` but lack `ciam:cases:approve`.

Both an ordinary GET and a GET with `attributes=permissions` yielded the same
missing scope. IDs, audiences and memberships matched. This is real remote
permission-state drift, **not** an output projection problem.

The current desired contract still expects administrator approval. Because
`desired.json` is bound to the private Phase 4 journal through `specSha256`, do
not silently edit the desired contract, manually change the journal checksum,
or rerun `apply` to reconcile. The absent grant may be an intentional revocation.

## Security decision required before modifying privileges

- If administrators **should not approve**: preserve the least-privileged WSO2
  state, explicitly approve a change to the *desired authorization contract*,
  and design a journaled, readback-verified policy revision with retained history.
  A metadata-only manifest edit would break the existing journal contract.
- If administrators **must approve**: obtain authorized change approval for the
  four specific application-bound roles; verify current grants and API resources,
  then use a separately reviewed, journaled, least-privileged scoped mutation with
  exact readback. This patch never regrants approval.
- Seller approval scopes were present in both Aurora seller roles; current
  remote evidence does **not** prove the MFA-protected approval transaction.

## Behavior of this patch

The main Phase 4 verifier remains the source of truth and continues to FAIL
when any configured permission set drifts. The preflight now *also* runs a
read-only, sanitized role audit on verifier failure and reports a specific
`live.business_role_readback` finding. It never converts missing approval
permissions into a passing release. If the original verifier returns JSON
with the exact `CIAM_BUSINESS_V4` / `VERIFY` / `VERIFIED` schema, preflight
accepts that **management readback only**; `businessRuntime: NOT_TESTED` remains
an explicit limit. No browser, data persistence, seller, or MFA acceptance is
inferred from any management readback.

The audit invokes only GET calls to the existing WSO2 management APIs. It reads
pre-existing private journals in memory to prove role IDs, audiences, members
and source digests; raw remote role records, private IDs, and unknown permission
names are not printed. This patch has no remote writes, no business mutations,
and no role/API/tenant/identity changes.

## Operator command

```
DEMO_EXPECTED_COMMIT="$(git rev-parse HEAD)" npm run demo:preflight -- --deep-readback --no-browser
```

Expected while current remote role permissions persist:

- `live.profile_authority_readback`: PASS (with correct v2 journal readback)
- `live.business_readback`: FAIL (the original verifier remains strict)
- `live.business_role_readback`: FAIL with the four missing administrator scopes
- `live.client_readback` / `live.carbon_super`: still BLOCKED unless separately
  implemented strict management evidence parsers are accepted
- All deferred human-authenticated seller/MFA, ledger durability and manual
  WCAG acceptance gates remain blocked.

The currently verified four customer OIDC sessions and 25/25 anonymous axe runs
are separate historical evidence; `--no-browser` neither reruns nor invalidates
those checks.
