# P2.24 V13 — Aurora partner organization: one-time bootstrap + startup verification

## Authorized effect and exclusions

Approved goal: establish **one** child organization named **Aurora Returns & Fulfillment Partner**
(handle `aurora-returns-fulfillment`) under the pre-verified Aurora tenant root.
This implementation authorizes only the corresponding `POST /t/aurora.identity.test/o/api/server/v1/organizations`.
It does **not** register apps, change authorizations, grant delegated admin roles, provision users,
mutate Brisa or Carbon Super, upgrade WSO2, or activate update-gated features.

## Runtime contract

- The image, TLS certificate, v2 role API journal, v8 view-only M2M and v12 creator M2M
  are reverified before any organization write.
- View access tokens are used for root, organization-list and child-detail GETs. A separate
  short-lived token with **only** `internal_org_organization_create` is used for the single POST.
- The private `p2-aurora-partner-create.private.json` file is written/fsynced in `INTENT`
  **before** the mutation, and marked `VERIFIED` only after a second independently
  authenticated GET proves exact ID, name, handle, status and parent.
- Every restart re-verifies the existing child. **No second creation POST** is issued.
- An `INTENT` record after a crash or ambiguous result blocks all automatic writes. Use
  `python3 scripts/p2/partner_v13.py reconcile` for GET-only evidence, then review the
  original write; do not delete the journal or run blind retries.
- No user input, client ID/token printing, root UUID output, or private file publication.

## Startup integration

The installer appends the V13 `ensure` preflight **before** the existing root
`prestart:bff` command, preserving all pre-existing script behavior. It also attaches
`ensure` immediately before `./scripts/ciam-v10.sh bff-start`. In both cases V13 must
pass before the BFF starts. The existing `./scripts/ciam-v10.sh bootstrap` and all
inspection/test commands remain unchanged; they do **not** automatically create a
partner during the base v10 identity bootstrap.

The project can start through the existing `npm run start:bff` or
`./scripts/ciam-v10.sh bff-start` paths. Any external custom launcher that bypasses
both paths must explicitly run the new bootstrap before exposing business routes.
The first launch may create one partner; subsequent launches verify only.

## Acceptance

```bash
node --test tests/p2/partner-io-v13.test.mjs
python3 -m unittest discover -s tests/p2 -p 'test_partner_v13.py' -q
python3 scripts/p2/partner_v13.py plan
python3 scripts/p2/partner_v13.py ensure
python3 scripts/p2/partner_v13.py verify
npm test
npm run build
git diff --check
```

Before `ensure`, `plan` must return `V13_PARTNER_READY_FOR_SINGLE_APPROVED_CREATE`.
First successful ensure returns `V13_PARTNER_CREATED_ONCE_AND_READBACK_VERIFIED` and
`managementWrites: 1`. Later ensure and verify return
`V13_PARTNER_ALREADY_CREATED_AND_REVERIFIED` and `managementWrites: 0`.
A readback failure never becomes a synthetic success.

### Scope of the startup promise

The V13 hook covers **this partner organization prerequisite**; it does not implicitly
mark all P2.24–P2.31 capabilities complete. Delegated admin, group/user sharing,
passkeys, consent, federation and lifecycle acceptance must have their own approved
and version-verified bootstrap steps before they can be represented as working.

### Documentation

WSO2 7.3 API: `POST /t/{tenant-domain}/o/api/server/v1/organizations` requires
`internal_org_organization_create`, payload `name`, optional `orgHandle`, `description`
and `parentId`. GET organization detail requires the independent view permission.
See WSO2 Identity Server Organization Management API (v1).
