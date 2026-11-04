# P2.24–P2.31 source test evidence (not WSO2 acceptance)

**Date:** 2026-11-04  **Environment:** isolated Linux artifact-building container, Node.js built-in test runner. **Connection to Mac/WSO2:** none. **GitHub push:** none.

## Executed checks

```text
node --check overlay/scripts/p2/cli.mjs                PASS
node --check overlay/services/identity-bff/src/live-p2-advanced.js    PASS
node --test overlay/tests/p2/guarded-org.test.mjs       9 PASS / 0 FAIL
```

The offline tests use controlled fake HTTP responses and exercise:

1. Aurora-only tenant URL and HTTPS path confinement;
2. no bearer submission to another host or over redirects;
3. unambiguous root/child ID and parent matching;
4. absent partner planning without write;
5. existing partner idempotent readback and wrong-parent denial;
6. journal intent before single organization POST and readback;
7. child organization-scoped SCIM inventory and incomplete-page refusal;
8. exact-user read, suspend PATCH and readback;
9. refusal to suspend a user from another organization.

These tests **do not establish** that actual WSO2 7.3.0 GA has the needed features/scopes enabled, that a real management token has correct organization context, or that browser/step-up/passwordless/federation/consent/deactivation/evidence-pipeline scenarios operate end-to-end. They neither deploy nor mutate a WSO2 installation. See `P2_24_31_ACCEPTANCE_RUNBOOK.md` to collect real, sanitized proof and to record positive/negative authorization decisions before promoting any capability to `VERIFIED_LIVE`.
