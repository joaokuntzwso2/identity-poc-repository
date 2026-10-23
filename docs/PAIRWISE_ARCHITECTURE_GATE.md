# Architecture gate — pairwise subject / organization isolation (B-01, B-02, B-03)

## Grounded fact vs. unverified combined behavior

WSO2 IS 7.3 documents **Subject type: Pairwise** under Applications > User Attributes > Subject type and permits a Sector Identifier URI to group applications that should receive the same pairwise identifier for the same user. Official source: <https://is.docs.wso2.com/en/latest/guides/authentication/user-attributes/enable-attributes-for-oidc-app/>.

The documentation does **not** by itself establish that a shared root profile, across separate WSO2 root tenants or child organizations, will result in the four-token predicate specified by the RFP. It also does not establish that organizations meet all root-tenant isolation expectations, or that white-label login domains preserve browser SSO cookies.

### Candidate architectures

**A: Root tenant with two child organizations.** Prefer only if the login model for both brands actually shares a canonical person and application policies/consent remain isolated with true `sub` sector behavior. Child organizations are not automatically interchangeable with Carbon tenant isolation.

**B: Independent WSO2 tenants and a private identity-link broker.** Use if strict brand partitioning is required. Build/verify explicit federation, consented linking, and issuer-specific policy before claiming one identity; independent per-tenant accounts can make the display look correct while failing the canonical-identity requirement.

### Fixture and acceptance predicates

| Registered client | Brand | Channel | Sector URI | Expected sub |
|---|---|---|---|---|
| aurora-web | Aurora | Web | `https://demo.example/oidc/sector/aurora.json` | SA |
| aurora-app | Aurora | Mobile-style browser | same as Aurora Web | SA |
| brisa-web | Brisa | Web | `https://demo.example/oidc/sector/brisa.json` | SB |
| brisa-app | Brisa | Mobile-style browser | same as Brisa Web | SB |

Require `SA = sub(aurora-web) = sub(aurora-app)` AND `SB = sub(brisa-web) = sub(brisa-app)` AND `SA != SB`. All four ID tokens must have valid JWKS signatures, valid nonce, issuer, audience, exp/iat. **A second independent step must prove identical canonical person**, e.g. privileged admin user sharing evidence, *never* a common person ID exposed in brand tokens. The UI labels the canonical proof as NOT_VERIFIED until a supported secure mechanism is designed and run.

### Procedure

1. Record the WSO2 7.3.0 distribution and update level, and available org login model. Verify WSO2 source and API signatures before implementing provisioning payloads.
2. Create Aurora and Brisa, two OIDC clients each. Set redirect URIs exactly to `${PUBLIC_ORIGIN}/auth/<client>/callback`.
3. Register public HTTPS sector JSON documents. Both applications in each brand must refer to their **identical** brand-specific URI. `GET /oidc/sector/aurora.json` and `/brisa.json` from this project serve the corresponding redirect URI arrays. Do not use plain HTTP outside loopback development.
4. Configure Pairwise and minimal attributes in WSO2 for each application; disallow unapproved PII.
5. Copy assigned client IDs to BFF environment. Verify issuer matches the exact Discovery `issuer` response. Do not use an external IP alias or an issuer with private `localhost` advertised to reviewers.
6. Configure trusted certificates, not `-k`, TLS-off, or disabled hostname checks. For self-signed local WSO2 CA, explicitly import the local CA into the backend trust chain via `NODE_EXTRA_CA_CERTS` rather than skipping verification.
7. Run `node scripts/verify-oidc.mjs` to test discovery, JWKS reachability, and `subject_types_supported=pairwise`.
8. Authenticate **the same person** in four clients (use WSO2 browser login): `/auth/aurora-web/login`, `/auth/aurora-app/login`, `/auth/brisa-web/login`, `/auth/brisa-app/login`.
9. Inspect `/api/subjects/compare` or Identity Inspector dashboard; store signed evidence of the test result, issuer, client ID, sector configuration, anonymized subject fingerprints, org/tenant boundary, and canonical-person linkage attestation (private).
10. Repeat test after fresh session, adding a third brand, credential change, issuer policy change; deny attempts to look up cross-brand subject without consent.

**Stop/go:** Do not construct a production tenant architecture on the assumption that the four `sub` values will satisfy the predicate across separate organizations. Demonstrate against actual WSO2 IS or record BLOCKED and escalate.
