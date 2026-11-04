# P2.24 V16.3 — Distinct Aurora partner OAuth callback and approved registration

This increment is approved **only** for registration of one new dedicated Aurora
application `P2 Aurora Returns Partner Business Portal`. The source-only installer
adds an isolated BFF callback and switches both startup entrypoints from V16.1
to a guarded V16.3 registration. It leaves V16 and V16.1 intact for audit.

The original V16 check failed because `/auth/aurora-web/callback` is handled
by the existing customer client. BFF source analysis confirms that reusing
that URI for a different OAuth client is not justified. V16.3 derives only
the *origin* of the established, independently read-back Aurora Web callback,
then registers the dedicated `/auth/aurora-partner-web/callback` URI. The
endpoint is explicitly implemented by `partner-portal-route.js` and covered by
positive and negative route tests.

## One-time bootstrap

- `npm run start:bff`, `./scripts/ciam-v10.sh bff-start`:
  V13 → V14.1 → V15 → **V16.3** → original ledger/BFF startup.
- First eligible boot: one durable `INTENT` (0600, fsync) before one WSO2
  application POST. No sharing or scope changes.
- Next boot: GET-only re-verification of application detail, exact OIDC
  protocol (confidential, authorization_code only, mandatory PKCE S256), and
  `authorized-apis: []`. A failed readback remains blocked.
- Existing V16/legacy journal, uncertain POST or unowned app collision never
  causes a duplicate or implicit adoption. `reconcile` is GET-only and
  `finish --readback-only` can conclude an independently proved single new app.
- No WSO2 upgrade, Brisa/Carbon Super write, broad scopes, permissions,
  partner app sharing, users or roles.

## Callback login gate (intentionally disabled)

The new endpoint implements state, nonce, PKCE, exact redirect/client binding,
RS-signed ID-token validation, client-bound token introspection, one-use state,
and isolated non-business session storage. **V16.3 does NOT enable partner login.**
It creates neither the verified sharing receipt nor the confidential-client
secret sidecar needed for this endpoint to begin OAuth. Calls correctly return
503 until a separate, approved, verified targeted-sharing step. The existing
four Aurora/Brisa OIDC clients and their callbacks remain unchanged.

## Recovery

```bash
python3 scripts/p2/partner_portal_v16_3.py reconcile
python3 scripts/p2/partner_portal_v16_3.py finish --readback-only
```

The second command is only for a verified exact orphan of the original single
POST. Never delete the journal or rerun an uncertain POST. No secrets or raw
OAuth tokens are reported by the acceptance output.

**Live WSO2 registration and runtime compatibility are pending on the Mac.**
