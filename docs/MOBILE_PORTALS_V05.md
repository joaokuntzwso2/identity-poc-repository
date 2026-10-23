# Two independent mobile application previews (v0.5)

Aurora Mobile and Brisa Mobile are **separate React/Vite entry points** with their own app IDs, navigation, visual systems and state namespaces. The shared product/account backend is intentional: a person may use the same brand via web and mobile, while data remains separated between brands. Each future application must be **registered as its own OAuth/OIDC client**, using PKCE and validated redirects. This package does **not** configure Identity Server or simulate authentication tokens.

## Local addresses

- Aurora native-style preview: `http://127.0.0.1:5173/aurora-mobile.html`
- Brisa native-style preview: `http://127.0.0.1:5173/brisa-mobile.html`
- Aurora website: `http://127.0.0.1:5173/aurora.html`
- Brisa website: `http://127.0.0.1:5173/brisa.html`
- Experience Center: `http://127.0.0.1:5173/`

Run from repository root: `npm ci && ./experience.sh dev`. To compile **all five pages** run `./experience.sh build` then `./experience.sh serve` (HTTP port 4317). See `./experience.sh mobile-test` for backend tests plus structure checks. Browser-level Playwright tests: `cd apps/experience-center && npx playwright install chromium && npx playwright test tests/mobile-v05.spec.ts` while dev server is running.

## Presenter journeys

1. Select Ana in both apps; demonstrate two independent applications and device shells.
2. Browse catalog, favorite products, add to cart, approve or deny a *synthetic* transaction. View order history.
3. Open account → personal data, saved delivery addresses, preferences, privacy/consent, assurance, and security.
4. Save brand-specific preferences on Aurora Mobile and confirm Aurora's website sees the same persisted data. Brisa preferences remain independent.
5. Simulate passkey/TOTP settings, password-rotation events and preview device revocation; demonstrate that no actual password or OTP is requested.
6. Compare mobile and website channels for a single brand. **Do not** claim proven pairwise subject continuity before WSO2 is available.

## Interface and trust boundaries

Both mobile apps are **browser-driven mobile simulations in realistic phone frames**, not native iOS/Android binaries, App Store packages, or public internet websites. The device shell can switch between iPhone-like and Android-like styling and display a lock screen; there is no platform biometric API, mobile secure enclave or actual device enrollment.

The same loopback-only synthetic API and SQLite database from v0.4 are used. Requests include explicit preview intent headers for writes. The selection of a fictional persona is not authentication, and the local app **must never** be Internet-exposed. No real payment, bearer token, password or biometric credential is collected. All order approvals and security actions display preview disclaimers and are not accepted as live identity evidence.

### Future identity wiring

| App | Candidate client id | Channel | Sector boundary |
|---|---|---|---|
| Aurora Web | `aurora-web` | browser website | Aurora sector |
| Aurora Mobile | `aurora-mobile` | independent native client candidate | **Same Aurora sector** |
| Brisa Web | `brisa-web` | browser website | Brisa sector |
| Brisa Mobile | `brisa-mobile` | independent native client candidate | **Same Brisa sector** |

Each mobile client must get its own authorization registration. Before claiming four-client acceptance, verify that signed tokens show equal pairwise subject within a brand and different subject across brands, with authorized canonical-identity mapping inside the IdP. Native client redirect URIs and platform-specific OAuth protections must be tested in actual native applications later.

## Privacy and public repository

Keep only generic fictional brands/personas and sample metrics. Never upload confidential documents, operational figures, private acceptance requirements, secrets, email addresses outside `.example`, live issuer/tenant IDs or customer-specific demo evidence. Run the repo's staged scanner **and manual review** before commit.
