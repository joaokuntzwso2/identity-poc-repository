# P1.23 — strict client + Carbon Super management readback

This **source-only** patch closes the two evidence-parser gaps in `scripts/demo-preflight.mjs`. It does not modify WSO2, OIDC app registrations, private journals, roles, token policy, cases or MFA.

## Producers (existing, unchanged)

- `scripts/ciam-v5-four-client-readback.py`: GET-only readback of four OIDC applications and authorized business APIs.
- `scripts/ciam-carbon-super-readback.py`: GET-only, bounded Carbon Super inventory. Individual HTTP failures may be embedded in a JSON response even when its exit code is zero.

## Acceptance policy

`live.client_readback` is `PASS` only for exactly `aurora-web`, `aurora-app`, `brisa-web` and `brisa-app`, with WSO2 JWT token configuration, RBAC policy, exact business scopes, profile audience, cases audience, and explicit producer verification all positive. The producer marks positive browser authentication as **NOT_TESTED**; this gate never upgrades it.

`live.carbon_super` is `PASS` only when all five management inventories are `FULL_FIRST_PAGE`, their reported totals match the observed bounded item counts, both `aurora.identity.test` and `brisa.identity.test` appear in the complete tenant inventory, the Carbon Super admin SCIM account is observed, and all published collection fields are complete. Additional valid Carbon Super resources/roles are permitted; none are invented or assigned.

- `FAIL`: field-level security configuration or verified expected-state drift.
- `BLOCKED`: incomplete/partial, malformed, unrecognized or unsupported inventory; **not** falsely successful.
- `PASS`: strict valid evidence from the existing producer, never from an exit code alone.

The summary prints only static, controlled reason codes and never client IDs, role names, user names, tokens, private URLs or raw subprocess output.

## Install and verify

```bash
python3 ~/Downloads/ciam-final-management-readback-v1/install.py --repo "$PWD"
python3 ~/Downloads/ciam-final-management-readback-v1/install.py --repo "$PWD" --apply
node --check scripts/demo-preflight.mjs
node --test tests/p123-management-readback-evidence.test.mjs
npm run demo:test
git diff --check
```

Commit the four source files, then restart **only** the BFF using `bash scripts/ciam-demo-start-profile.sh` to align startup SHA provenance. Re-run:

```bash
DEMO_EXPECTED_COMMIT="$(git rev-parse HEAD)" npm run demo:preflight -- --deep-readback --no-browser
```

A `BLOCKED` Carbon collection may reflect an unavailable management endpoint or incomplete first page rather than a security regression. Inspect its output locally and do not downgrade strict checks to make a presentation look ready. The separately deferred browser, real business persistence, positive/negative MFA and manual WCAG 2.2 AA gates remain `BLOCKED` until tested with new, scoped evidence.
