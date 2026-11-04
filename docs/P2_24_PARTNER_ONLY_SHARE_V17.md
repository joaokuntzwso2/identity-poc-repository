# P2.24 V17 — Aurora partner-only application sharing

## Approved immutable targets

- Root: Aurora (`aurora.identity.test`), fingerprint `4548812d1a94a3ff`.
- Partner: Aurora Returns & Fulfillment Partner, fingerprint `a9c40a10acabab52`.
- App: `P2 Aurora Returns Partner Business Portal`, fingerprint `7b4495d1ff5af7fd`.
- Registered callback remains at fingerprint `3673f8ef2a1f66e1`.
- Only one POST to `POST /t/aurora.identity.test/api/server/v1/applications/share`.
- The JSON request contains exactly one organization, `policy=SELECTED_ORG_ONLY`, and `roleSharing.mode=NONE` (no role sharing).

## Automatic bootstrap

V13 → V14.1 → V15 → V16.3 → V17 → existing business ledgers → BFF.
Both `npm run start:bff` and `./scripts/ciam-v10.sh bff-start` run V17. Its first eligible start records an owner-only, fsynced intent before a single POST. On future starts it does GET-only reconciliation; it never repeats that POST.

## Acceptance

HTTP 202 confirms only that WSO2 accepted the asynchronous work. Completion requires **both** `GET /applications/{id}/share` and `GET /applications/{id}/shared-apps` to show exactly one organization, the intended partner, with `SELECTED_ORG_ONLY` and **no shared roles**. Unknown, omitted, or incomplete collections do **not** prove absence or completion; they yield `PENDING` and no new management write. Any broad/global or cross-partner sharing is a hard failure.  Because WSO2 7.3 GA may omit empty collections, a first run can report `V17_PREWRITE_SHARING_EVIDENCE_INCOMPLETE`; do not force it to write without stronger independent evidence.

## Commands

- `python3 scripts/p2/partner_share_v17.py status`: read-only preflight.
- `python3 scripts/p2/partner_share_v17.py bootstrap`: first eligible one-time approved POST; later GET-only.
- `python3 scripts/p2/partner_share_v17.py reconcile`: GET-only; completes intent after exact remote readback.

No extra credentials need entry; only an existing Aurora-qualified authority Basic credential is used, through the path-constrained POST transport. It does not broaden either M2M client. A separate stage is still required for login activation, scopes, users, roles and delegated administration. Private journal `~/wso2-ciam-v10/private/p2-aurora-partner-only-share-v17.private.json` must not be committed, edited, deleted or retried after an uncertain request.
