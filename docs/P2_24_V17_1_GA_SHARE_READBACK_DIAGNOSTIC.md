# P2.24 V17.1 — GA application-sharing schema diagnostic

WSO2 7.3.0 GA has returned an omitted organization-sharing collection for the newly registered Aurora partner portal. V17's write-ahead safeguards correctly refuse to infer that it is empty and refuse to POST before verifying the prewrite state.

This read-only tool is a diagnostic, **not** a sharing grant, workaround for missing rights, completion test, or reason to delete a private journal. It verifies the V16.3 portal and V13 partner fingerprints via the existing V17 dependencies and pinned TLS, then performs up to five bounded `GET` calls: baseline sharing, filtered sharing for the exact partner, policy attributes, shared app mappings, and application details. It reports field presence/types/counts only. It does not print response bodies, usernames, app/org UUIDs, URLs or credentials.

Run from the repository root:

```bash
python3 scripts/p2/partner_share_ga_probe_v17_1.py inspect
```

Keep the existing startup sequence `V13 → V14.1 → V15 → V16.3 → V17 → ledgers → BFF`. The V17 journal remains absent unless the prewrite verifier can independently certify an empty sharing state and the previously authorized bootstrap later performs its single approved POST. Do not weaken that prewrite gate based only on an omitted collection.

If the probe returns the recognized `V17_1_GA_SHARING_SCHEMA_DIAGNOSTIC` code, share the sanitized JSON output for a follow-on evidence-driven GA adapter. **No changes to Brisa, Carbon Super, login, users, roles, scopes, or sharing policies are made.**
