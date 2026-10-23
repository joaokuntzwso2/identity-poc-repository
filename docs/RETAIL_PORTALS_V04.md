# Aurora & Brisa — Standalone Retail Experiences v0.4

## Status

Fully interactive **synthetic preview**, not customer authentication or a completed Identity Server PoC. All brands, customers, prices, addresses, profiles and payments are fictional. These portals remain accessible only via loopback in the local development setup.

## Open the real website entries

- `http://127.0.0.1:5173/aurora.html` — fictional technology retailer, editorial/cool-blue visual system.
- `http://127.0.0.1:5173/brisa.html` — fictional home/lifestyle retailer, warmer serif/terracotta system.
- `http://127.0.0.1:5173/` — existing Experience Center, which links into the full brands with persona context.

The pages have dedicated HTML entry points, independent page-title/SEO metadata, React retail UI and deep-linkable `?view=...` navigation. They build to `dist/aurora.html`, `dist/brisa.html`, and the existing center `dist/index.html`.

## Implemented journeys

- Landing page with editorial hero, category navigation, curated collection, featured product and mobile navigation.
- Search/filter, product detail page, price display, favorites, quantity-controlled cart.
- Checkout preview: server-side price recalculation, pending review, explicit approve or deny, lifecycle in persisted orders. No payment credentials or money processed.
- Synthetic order history, shipping statuses, delivery address management.
- Account hub with editable fictional name, city and phone; reserved `.example` email is not editable in the preview.
- Security page: **synthetic action events only** for password rotation, TOTP enable/disable, passkey enrollment and device revocation. No secrets, passkeys, OTPs or sessions actually provisioned or revoked.
- Marketing preferences and notification switches persisted separately for Aurora and Brisa.
- Consent lifecycle integrated with pre-existing synthetic consent store and immutable events.
- Attribute-level provenance, assurance state, independent phone/address update; no whole-person verified checkbox.
- Persona switching is **navigation in a demo** and must never be confused with login or authorization.

## API contract

Loopback-only API endpoints (all responses disclose `synthetic-preview`, mutation requests require `X-Experience-Preview: yes`):

- `GET /api/retail/{aurora|brisa}/bootstrap?persona=customer-ana`
- `POST /api/retail/{brand}/profile` with `{persona,changes:{displayName,city,phone}}`
- `POST /api/retail/{brand}/preferences` with `{persona,changes:{email,sms,orderAlerts,personalization}}`
- `POST /api/retail/{brand}/addresses` with `{persona,action:add|remove,values:{...}}`
- `POST /api/retail/{brand}/wishlist` with `{persona,productId}`
- `POST /api/retail/{brand}/security` with `{persona,action,id?}` — action limited to synthetic preview actions
- `POST /api/retail/{brand}/checkout` with `{persona,action:request|approve|deny,items?,orderId?,previewAcknowledged?}`
- Existing `GET/POST /api/experience/consents`, `GET/POST /api/experience/assurance` reused unchanged

Backend persistence: same local SQLite file as Experience Center v0.3 (`var/identity-preview.sqlite`), isolated by **persona + brand** with append-only activity records. Cart state lives only in browser sessionStorage and is likewise namespaced.

## WSO2 integration boundary

Later replace synthetic selection by a verified server-side principal; accounts, sessions, credentials, passkeys, MFA, SSO, Token Exchange and session revocation MUST be performed by a real Identity Server integration. For brand isolation use actual tenant/sector behavior, never synthetic persona IDs. Do not forward untrusted browser persona IDs to protected backend APIs. Consent and assurance functions require actual verified subject mapping and authorized canonical resolution. No current page may claim real authentication or compliance.

## Testing

- `./experience.sh preview-test`: SQLite domain and API tests (including isolation, negative tests, and forged price handling).
- `./experience.sh test`: preview and prior BFF test suites.
- `./experience.sh build`: existing center build, then branded Vite multipage build into the same `dist` without erasing the center.
- Playwright scenarios: `apps/experience-center/tests/retail-v04.spec.ts`, requiring Vite and the preview API, with Chromium installed.
- Verify security/publication scan before commit, especially `docs/`, `config/`, `.env*` and sample data.
