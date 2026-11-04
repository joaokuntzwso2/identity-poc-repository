# P2.24 V16: Dedicated Aurora partner portal registration, automatic bootstrap

Scope approved: register exactly one new tenant-root Aurora OIDC application named
**P2 Aurora Returns Partner Business Portal**. This stage does **not** share it,
authorize an API, create a partner user, grant a business role, or enable BFF login
with that new client ID. The project's existing Aurora Web login remains bound
to its existing client and callback, which is not modified. The new registration
reuses a callback that must be verified in BOTH the existing registered Aurora
Web OIDC application and the installed BFF source. If that proof is unavailable,
the bootstrap fails before any application POST.

Only the first eligible startup executes a single POST `/t/aurora.identity.test/api/server/v1/applications`.
It first writes an `INTENT` with `0600` permissions and fsyncs it. An unexpected
HTTP response or process interruption permanently blocks automatic POST retries.
A fresh complete application inventory, exact application detail, dedicated
OIDC inbound readback (auth code only, confidential, mandatory PKCE S256) and
empty `authorized-apis` are required before state `VERIFIED`.

Subsequent starts perform read-only verification. Both `npm run start:bff` and
`./scripts/ciam-v10.sh bff-start` gate on V13 → V14.1 → V15 → V16, then follow
the existing startup sequence. No code alters the Docker image, TLS pin, Brisa,
Carbon Super, existing OAuth clients, private journals or BFF authorization.

If startup reports `V16_CREATE_INTENT_EXISTS_RECONCILE_NO_RETRY`, do not reissue
any create request. Run `python3 scripts/p2/partner_portal_v16.py reconcile`.
If it reports `V16_EXACT_NEW_APP_OBSERVED_GET_ONLY_FINISH_AVAILABLE`, use
`python3 scripts/p2/partner_portal_v16.py finish --readback-only`.
If callback evidence is blocked, the application has not been created; inspect
only sanitized error codes and fix the project's callback evidence before retry.

**Security distinction:** A registered app is not a working partner portal or
business authorization. The V14/V15 incomplete sharing evidence remains pending,
particularly when GA omits sharing collections. No claim of unshared status is
inferred from those omissions. Future portal callback wiring and target-specific
sharing will be approved and tested separately.
