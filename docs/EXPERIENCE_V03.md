# Identity Experience Center v0.3 — public/generic implementation

> **Not a WSO2-integrated product demo.** This version is a professional UX and an intentionally restricted synthetic local preview. It does **not** authenticate anyone, mint tokens, prove session continuity, or satisfy live product acceptance criteria.

## Install and run from repository root

Install the overlay using the separately distributed `install.sh` (see package README). After installation:

```bash
node --version                          # Requires Node.js 22.16+ with node:sqlite; Node.js 24 preferred
npm ci                                  # Existing repository dependencies
./experience.sh test                    # Domain/API tests + existing BFF suite
./experience.sh dev                     # API on 127.0.0.1:4317 + Vite dev UI
./experience.sh build                   # Produce Vite dist
./experience.sh serve                   # Serve dist from 127.0.0.1:4317
```

In `dev`, open the address printed by Vite (typically `http://localhost:5173`). In `serve`, open `http://127.0.0.1:4317`.

## Screens and functionality

- **Experience Center:** six scenario launchers, presenter/technical mode, guided steps, business objective, persona, controls, required evidence and required negative checks. The `Live Verified` designation is never generated offline.
- **Aurora & Brisa:** distinct realistic fictional storefronts; responsive desktop and browser-based mobile simulation; product details, shopping cart, illustrative transaction/step-up experience, orders, profile, security and privacy settings.
- **Eight synthetic personas:** persisted as structured JSON for deterministic scenario design. No real customer records, usable CPF/CNPJ or meaningful secrets.
- **Consent:** local SQLite durable states `pending → granted|denied`, `granted → revoked|expired`, `denied|revoked|expired → pending` for a new request. Each change is transactional with an append-only event. Consents are scoped by fixture persona plus origin/target/purpose/scope.
- **Assurance:** independent records with source, level, verified time, expiry and version. A phone/address self-declared edit invalidates **only that attribute** in the synthetic preview. Other attributes retain their levels and audit remains append-only.
- **Canonical correlation boundary:** internal-only module. It requires a trusted service context and an explicit cross-brand grant. **No public route exposes the synthetic canonical mapping.** A later WSO2 adapter must derive the trusted principal from cryptographically validated workload credentials; browser-supplied flags must never be used for authorization.
- **Evidence Center:** seven technical demonstration cards remain `Aguardando WSO2` or `Preview offline parcial` until evidence is collected.

## Operating restrictions and security

- The synthetic API **only listens on loopback** (`127.0.0.1`). It will not start without `EXPERIENCE_PREVIEW_ACK=YES_LOCAL_SYNTHETIC_ONLY`.
- API calls from unexpected browser origins are rejected. Mutations also require a custom preview intent header (defense-in-depth, **not authentication**).
- Browser persona selection is **not an authorization mechanism**. All data is synthetic and may be freely modified on this local development instance. Never expose this preview service on a public interface or behind a production gateway.
- `var/identity-preview.sqlite*` must remain untracked, including backup/archive files. The installer adds these patterns to `.gitignore`.
- Do **not** route any real OAuth token, customer ID, PII or authentication session into this preview service.
- Browser stores do not claim completed real auth, approval or consent. Visual completion explicitly says the action is illustrative.
- For real consent authorization, bind every operation to the verified WSO2 session and authorized client, and integrate with WSO2 consent semantics or a formally approved extension. This overlay does not replace the existing Identity BFF consent implementation.
- The native/mobile design is a **browser simulation**. Real native app behavior is not tested.

## Integration contract when WSO2 is provisioned

1. Validate first-class topology, OIDC pairwise sector behavior and SSO across brand domains **before** applying any canonical subject assumptions.
2. Implement BFF server-side `IdentityProviderAdapter` with discovery, PKCE, validated ID tokens, issuer/client allowlists and secure session storage. Never trust a browser-provided `role`, `sub` or `verified` boolean.
3. Replace local persona selection with real session principal resolution; keep personas only as test data, outside the authentication path.
4. Integrate live consent with tenant/application policies. Durable fixture events are **not proof** of WSO2 consent isolation.
5. Protect canonical identity resolution with server-to-server workload authentication, explicit source/target authorization and purpose-specific grants. Audit every resolution attempt, including denials.
6. Replace illustrative step-up with a real re-authentication journey and verify `acr`/`amr` with tokens cryptographically verified server-side.
7. Add real MFA, federation, user stores, tenant onboarding, migration and performance evidence separately.
8. Attach signed execution evidence to all acceptance scenarios; never mark `PASS` because a UI page loaded.

## Unverified in this environment

- WSO2 runtime, pairwise identity, tenant organization boundaries, SSO and actual tokens.
- Real authentication/MFA/step-up, consent integration, cross-brand canonical resolution.
- Real payment authorization or order placement.
- Playwright browser test and original app integration (must be executed in the target checkout).
- AWS, 1,000 RPS performance, multi-region SLA and contractual documentation.

## Public repository hygiene

This document contains no customer-specific requirement details. Keep any private RFP, acceptance matrix, operational volumes or customer metrics outside the public repository. Run the existing `scripts/security/check_public.py` and human-review the staged diff before committing.
