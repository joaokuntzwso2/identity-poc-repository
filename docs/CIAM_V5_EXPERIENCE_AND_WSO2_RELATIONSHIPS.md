# CIAM v5 – Experience Center, websites and WSO2 trust boundaries

Source basis: repository source snapshot from `main` at `4a99dd5a49e4ace0f3eda16fd8150bcd34dc0b15` and original Experience Center from its parent commit, supplied on 2026-10-28. This document describes code, not unobserved successful browser flows.

## Why v5 exists

The original React Experience Center had six guided journeys, branded storefronts, mobile presentations, privacy/assurance visualizations and operations/provider laboratories. It read from `/api/experience/*` and client-side persona fixtures. The safe v3/v4 implementation retired those synthetic entry points and replaced `src/main.tsx` with a two-portal handoff. The `/api/experience/*` routes deliberately return 503 in the live BFF; they must **not** be reopened as fake identity providers. The original CSS is reused in v5, and the original six narrative topics are preserved and updated to distinguish real evidence from pending scope.

## The live architecture

```
                          Experience Center (/ and /lab)
                           /      /       /       \\
                  Aurora Web Aurora Mobile Brisa Web Brisa Mobile
                      |            |         |         |
              aurora-web     aurora-app   brisa-web  brisa-app
                      \            /         \         /
                 Aurora tenant             Brisa tenant
                         \                    /
                          WSO2 IS 7.3 (9444)
                                   |
                      OAuth2/OIDC / code+PKCE / ID token verification
                                   |
                       identity-bff (127.0.0.1:4400)
                                   |
                    Server-side sessions + introspection per request
                                   |
                 +-----------------+---------------------------+
                 |                 |                           |
              UserInfo         Business cases              Evidence
     GET /brands/{brand}/profile     /cases         GET /api/identity/me
                 |                 |                           |
       WSO2-released attrs    JSONL application data        live scopes/claims
                                    |
                  audience/issuer/client/scope/MFA gate (WSO2)
```

### Tenant vs OIDC client vs API resource

- `aurora.identity.test` and `brisa.identity.test` are separate WSO2 tenant namespaces; each contains Web and Mobile OIDC clients. WSO2 user identities, assignments, registered apps and issuing URLs are scoped appropriately.
- OIDC **client ID and ID-token audience** identify the authenticating application; the server verifies the ID token's signature, issuer, client and nonce at callback.
- An OAuth **API-resource identifier** is an audience for access tokens. Profile: `https://api.ciam-v10.test/profile`; cases: `urn:ciampoc:service-requests:v1`. `inspectAccessToken` requires this audience, active/exp, client ID and issuer, then required scope.
- The Phase 4 roles were created and readback verified in WSO2. **Scopes** on active tokens determine BFF authorization; client-side visual role text never grants permission. A `roles` display is shown only if WSO2 emitted it in a verified ID token.
- WSO2 UserInfo returns only claims the actual tenant releases. In today's prior test it returned `sub` only for Ana. Lack of released name/email must not be filled in with a mock persona.
- Web and mobile are *distinct browser OIDC client flows*. `/portal/{brand}/mobile` is a responsive browser demonstration of the Mobile client, **not a native app or proof of a native PKCE flow**.

### Business-data ownership

- `/api/brands/{brand}/cases` is persisted in a private append-only JSONL ledger by the BFF, not in WSO2. This is real *application business data*, not identity fixture data.
- Read requires `ciam:cases:read`, brand review additionally requires `ciam:cases:review`, create requires `ciam:cases:create`, approve requires `ciam:cases:approve` **and** verified ID-token TOTP AMR and fresh auth_time. The BFF additionally blocks self-approval and cross-tenant clients.
- The catalog entries in the storefront are **display-only static merchandise** inherited conceptually from the original UI. They are explicitly marked as illustrative, have no checkout and are not presented as WSO2 data. No fake orders, addresses, preferences or assurance levels are returned.

## Implemented v5 navigation / routes

| Route | UI role | Identity source |
|---|---|---|
| `/` and `/lab` | Main Experience Center, six guided journeys, evidence, privacy/assurance/B2B/delegation explanations | `/api/identity/me` and `/api/wso2-status` |
| `/experience` | Main Experience Center alias | same |
| `/portal/aurora/web` | Branded Aurora web catalog, account, UserInfo, requests | `aurora-web` |
| `/portal/aurora/mobile` | Branded responsive Aurora mobile browser view | `aurora-app` |
| `/portal/brisa/web` | Branded Brisa web catalog, account, UserInfo, requests | `brisa-web` |
| `/portal/brisa/mobile` | Branded responsive Brisa mobile browser view | `brisa-app` |
| `/portal/aurora` and `/portal/brisa` | Backward-compatible v3 portals | existing client selector |

The login routes are `/auth/{brand}-web/login` and `/auth/{brand}-mobile/login`. Redirects are allowlisted to the associated brand and **matching channel**; no external URL or cross-brand `returnTo` is allowed. OAuth code flow, state, nonce, PKCE and callback checks remain in existing BFF source. The new UI does not store tokens or user identity in localStorage or sessionStorage.

## Demo status: proven vs still requiring acceptance

Already proven from prior local browser outputs (Aurora Web only): Ana's `ciam:cases:create/read` and profile scopes, profile 200, cases `OWNER_ONLY` 200, case create 201 and persisted readback; Marcos's `read/review/approve` scopes, `BRAND_REVIEW` 200, customer-only create 403, and approval without fresh TOTP 403 `fresh_wso2_totp_required`.

**Not established** by installation or anonymous HTTP tests: a positive authenticated login through each of Aurora Mobile, Brisa Web and Brisa Mobile; business API audiences for those other clients; their actual role assignments and UserInfo releases; a successful TOTP step-up/approval; consent preference APIs and v2 policies; organization creation/delegation and partner access; real agent/token exchange; cross-tenant pairwise identifier semantics; native mobile client behavior. Their UI surfaces must not claim these tests passed.

## Deployment and rollback

1. Unpack v5 overlay at repo root; `python3 scripts/install-live-experience-v5.py --check`; `--apply`; `--verify`.
2. Run existing `node --test tests/live-userinfo.test.mjs tests/live-cases-v4.test.mjs` and `node --test tests/live-experience-v5.test.mjs`. Run `python3 scripts/zero-mock-gate.py .`.
3. Restart only the confirmed `services/identity-bff/src/server.js` process via the established `ciam-v10.sh` guarded stale-PID flow. No Docker, tenant or SCIM reset.
4. `bash scripts/live-experience-v5-acceptance.sh` checks anonymous paths and compatibility. Real acceptance requires logging in separately to each of the four clients and checking positive/negative operations; browser logins must not be automated with fabricated credentials.
5. Local source rollback: stop BFF, compare committed diff and restore `services/identity-bff/src/server.js.pre-live-experience-v5.bak` *only if v5 is the most recent BFF patch*. Do not delete journals, identity resources or business ledgers. Old v3 portals remain available under their original paths.

## Security and privacy

All identity reads are performed through the BFF and WSO2. The static frontend does not call a fictional profile, supply roles, set token scopes, mark MFA successful or fabricate consent records. HTTP failures remain failures. The BFF `IDENTITY_MODE=live-wso2` guard, `liveApiDenial` default deny, CSRF/origin checks for writes, tenant/client checks and issuer/audience/scope introspection remain unchanged.
