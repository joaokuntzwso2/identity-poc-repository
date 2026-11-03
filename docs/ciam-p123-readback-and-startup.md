# P1.23: profile startup and live evidence (v1)

The original customer demonstration operates at http://127.0.0.1:4400 with existing
WSO2 IS 7.3 at https://localhost:9444. There are four independently authenticated
browser OIDC clients. The mobile routes are browser previews, not native apps.

## Verified current milestones (operator reports, 2026-11-03)

- Four Aurora/Brisa web/mobile OIDC browser sessions authenticated with their
  own tenant-local `ana.costa` identities. Each had granted `ciam:profile:read`,
  protected profile 200, cases 200 OWNER_ONLY, and wrong-brand cases 403.
- Automated axe-core audit was 25/25 with zero violations on the audited anonymous routes.
- Profile authority was reconciled GET-only against the journal-pinned SCIM Roles API v2.
- Previous report `--deep-readback --no-browser` showed business readback FAIL;
  client and Carbon Super command exits 0 were not parsed as field-level acceptance.

Do not infer that any untested manual accessibility, seller, MFA, persistence,
ledger durability, consent or delegated identity features are accepted.

## Reliable startup after an operator stops the existing BFF

Use `bash scripts/ciam-demo-start-profile.sh`. It refuses a dirty checkout or
an already healthy BFF, reads the existing authority journal without printing its
contents, and compares the journal-pinned version with fresh read-only WSO2
profile-resource/role reconciliation. Only when this succeeds does it invoke
the existing approved local `~/Downloads/start-ciam-existing.sh` workflow with
`WSO2_BUSINESS_API_AUDIENCE`, `WSO2_AUTHORITY_OIDC_SCOPE` and the pinned Roles API
version. The helper does not terminate processes or write WSO2 resources.

## Read-only deep evidence

```
DEMO_EXPECTED_COMMIT="$(git rev-parse HEAD)" npm run demo:preflight -- --deep-readback --no-browser
```

`live.profile_authority_readback` now has strict field-level verification.
The pre-existing client, Phase 4 business and Carbon Super readbacks remain
**BLOCKED** when their command succeeds without a trusted structured acceptance
parser. On nonzero exit, only sanitized machine error identifiers and exit codes
are included; raw output stays private. A failing business readback is still a
FAIL, not automatically converted into PASS. A separate `--rehearse` run gives
fresh real browser evidence but does not itself accept deferred manual tasks.

For troubleshooting, inspect the failing read-only command **locally**; do not
share secrets, identities, journal files, tokens or raw authentication responses.
Never `apply` or rebootstrap to fix a report. Manual authenticated seller and
MFA acceptance is intentionally deferred until an operator explicitly approves it.
