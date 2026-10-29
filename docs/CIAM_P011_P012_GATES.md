# P0.11–P0.12 CIAM acceptance / security gates

## Scope and status

This is an **additive safety/acceptance increment** on the repository's `deploy/ciam-v10/cli.py` and its existing P0.08–P0.10 tests. It does not create new tenants, identity resources or a substitute identity provider. No historical or mocked run proves current live WSO2 acceptance. The readiness command deliberately remains **BLOCKED** when mandatory live negative cases or independent case audit validation are missing.

Machine-readable reports, evidence and write-ahead journals are placed under `${CIAM_V10_HOME:-~/wso2-ciam-v10}/inspection` with directory mode `0700` and file mode `0600`. Never commit these files. `sourceGitSha` is exact local HEAD; the report also includes dirty-worktree status and a Docker+BFF runtime identity where available. Evidence hashes are SHA-256 of canonical JSON excluding the embedded checksum field; external P010 evidence is separately hashed in the reference and reverified. Changes to SHA, runtime identity, content, freshness or file mode invalidate evidence.

## Commands

All calls go through the existing `./scripts/ciam-v10.sh` front door:

```bash
./scripts/ciam-v10.sh offline-test
./scripts/ciam-v10.sh security-audit
./scripts/ciam-v10.sh inventory
./scripts/ciam-v10.sh readiness
```

The first command runs the existing Node BFF tests, existing v10 Python tests, P010 browser-driver syntax and new Python safety tests. These are `UNIT`, `MOCKED_INTEGRATION` and `STATIC` evidence only. In CI, run `npm ci` first. `security-audit` scans Git **index blobs**, separately from private sanitized inspection output. Findings disclose only filename, classification and line number. This is an additional check; keep using the existing `scripts/security/check_public.py` before publication, with its private pattern file. A fully exhaustive customer-PII review still requires external private patterns and human review.

`inventory` performs GET-only BFF and WSO2 preflight readbacks, local port checks and Docker inspection; it never assumes a TCP listener is proof of service health. The existing P010 policy-readback validates all four registrations and PKCE. The commands bound local I/O and never disable TLS validation globally.

`readiness` writes JSON and Markdown gates with exactly one top-level outcome: `READY`, `NOT_READY`, `BLOCKED`. `BLOCKED` means live evidence unavailable/incomplete; `NOT_READY` means a demonstrable failure (for example an exposed tracked secret or dirty worktree). Missing proof is never a positive test. The bundled incremental gate **cannot** report READY yet: complete live negative matrix, SSO/logout and independent audit verification are not implemented by P010.

## Operator-assisted live acceptance

The existing `scripts/ciam-p010-interactive-acceptance.mjs` drives four real WSO2 logins, UserInfo and Aurora seller TOTP approval. It creates a new persistent business case. Only an authorized operator should run:

```bash
CIAM_P011_LIVE_CONFIRM=INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE \
  ./scripts/ciam-v10.sh live-acceptance
./scripts/ciam-v10.sh readiness
```

This runs the P010 preflight, checks a clean source, exact container/BFF identity, opens the genuine browser authentication, then attaches source/runtime provenance to the newly created P010 artifact. It checks the original P010 driver results against exact expected HTTP statuses and 4 clients. It **does not** perform additional live negative scenarios, TOTP enrollment, logout, replay, or independent case-ledger readback. P010 currently hardcodes the default private runtime location, so a custom `CIAM_V10_HOME` is refused for this command. Operator credentials and TOTP remain exclusively inside WSO2 login UI. No tokens or OTP seeds are copied into provenance.

Repeated live runs generate **new business records**; they do not auto-delete or modify old cases. The existing P010 runner uses a timestamp title but does not yet have a case fixture lifecycle/retention policy. Require per-run operator authorization and consider periodic *reviewed*, application-owned-only archival; never delete preexisting user cases.

## Provisioning: narrow, guarded existing authority stage only

`provision-plan` wraps the existing `authorization-plan` implementation and its `automation.verify_plan`. It does **not** authorize provisioning an entire lab, Cases roles, or changes to established resources. The caller must pin `WSO2_CIAM_V10_ROLE_API=v3`, and the stage must return a read-only safe plan. Store the reported private plan file path in `CIAM_P012_PLAN_FILE` for the separately approved `provision-apply` operation:

```bash
WSO2_CIAM_V10_ROLE_API=v3 ./scripts/ciam-v10.sh provision-plan
# Review the plan in the secure inspection directory, with no secret output.
WSO2_CIAM_V10_ROLE_API=v3 \
 CIAM_P012_PLAN_FILE="$HOME/wso2-ciam-v10/inspection/<exact-plan-name>.json" \
 CIAM_P012_APPLY_CONFIRM=APPLY_THIS_FRESH_AUTHORIZATION_PLAN \
 ./scripts/ciam-v10.sh provision-apply
```

Approval must happen within 10 minutes with a clean, unchanged source. The apply wrapper re-reads the real authority plan and requires identical SHA-256 digest. Before any authority write it creates a private, fsynced write-ahead record. It invokes the **existing** authority stage's journaled `authorization-apply` exactly once, then the existing GET-only `authorization-reconcile` and `verify_reconcile`. The plan is one-use: any recorded attempt, including timeout or ambiguous failure, blocks replay. Never delete journals or retry uncertain writes. WSO2 tenant/cases scope collision detection and per-resource exact readback remain the responsibility of the existing dedicated plan and bootstrap components; no broad provisioning capability is implied.

## Positive/negative acceptance coverage matrix

`PASS` here refers only to tests inside this additive module or to reusable existing tests when actually executed. A named historical runner is a *coverage mechanism*, not fresh proof. `BLOCKED` means **not yet covered by executable live P0.11 evidence**.

| Scenario | Execution/test mapping | Evidence class | Current boundary |
|---|---|---|---|
| Source checkout SHA, dirty status | `readiness` / `core.source_identity` | STATIC | Implemented; must run on target Mac |
| Four OIDC registrations, callback and PKCE S256 | `inventory` → P010 preflight/policy readback | LIVE_READBACK | Requires local WSO2 |
| Issuer, audience, signature, nonce, state, token subject binding | Existing BFF Node security tests via `offline-test` | UNIT/MOCKED_INTEGRATION | Rerun locally; mocks do not prove live |
| Token introspection, missing scopes, tenant/client isolation | Existing BFF Node integration tests via `offline-test` | MOCKED_INTEGRATION | Existing suite, scenarios require local test inventory |
| Session expiration/rotation, callback replay, CSRF | Existing BFF Node tests via `offline-test` | UNIT/MOCKED_INTEGRATION | Fresh local suite needed; full branch matrix not audited here |
| Customer ownership, seller review, self-approval denial | Existing BFF Node Cases tests via `offline-test` | MOCKED_INTEGRATION | Self-approval not independently proven live |
| Case transitions and append-only audit events | Existing BFF suite and P010 runner | MOCKED_INTEGRATION/BROWSER_E2E | Independent ledger readback BLOCKED |
| Signed ACR/AMR/auth_time, stale/wrong/missing assurance | Existing P010-aware BFF security tests via `offline-test` | UNIT/MOCKED_INTEGRATION | Full live negative matrix BLOCKED |
| Four real logins + UserInfo | Existing P010 browser driver behind `live-acceptance` | BROWSER_E2E | Real operator required; no mock PASS |
| Customer case creation/owner read + Brisa denial | Existing P010 browser driver | BROWSER_E2E | Mutates application-owned records with separate approval |
| Seller review, WSO2 TOTP step-up, approval readback | Existing P010 browser driver | BROWSER_E2E | New record each run, fresh provenance required |
| Callback replay, canceled/expired step-up, revocation | Not implemented by existing P010 live driver | LIVE_AUTHENTICATION | BLOCKED |
| Client-specific SSO/logout and outage recovery | Not implemented by P010 live driver | BROWSER_E2E | BLOCKED |
| Tracked secret leakage, `.env` and private keys | `security-audit` + `RedactionTests` | STATIC/UNIT | Implemented; high-entropy/structured patterns, not exhaustive |
| Private evidence leaks, tampered/stale/mismatched proof | `audit_inspection` + `EvidenceTests` | UNIT | Implemented (new evidence validator) |
| Provisioning one-use approval, v3 pin, plan digest | `provision-plan` / `provision-apply` + `ProvisionTests` | STATIC/UNIT | Implemented, uses existing authority stage only |
| Version-pinned Cases resource collision / idempotent reconcile | Existing `cases-rbac/bootstrap.py`, `admin-approval-remediation.py` and tests | UNIT/LIVE_READBACK | Existing dedicated modules; do not rerun applies |
| Test fixture lifecycle and unique case ID | Existing P010 uses a timestamp title and WSO2-backed case ID | BROWSER_E2E | Fully traceable fixture cleanup/retention BLOCKED |

## Recovery and troubleshooting

A `BLOCKED` report is expected when WSO2 localhost, `npm ci`, Playwright, private credentials or manual interaction are unavailable. Inspect filenames/classification only; never paste private P010 JSON, browser traces or `~/wso2-ciam-v10/private` contents. Run `./scripts/ciam-v10.sh bff-diagnose` for the BFF and the current read-only `authorization-reconcile`/`authority-status` for provisioning drift. On failed or ambiguous apply, keep the existing journal and investigate WSO2 state manually. No automatic replay or Docker/DB reset is permitted.

## Increment after source review (`91a0b922b546`): independent live readbacks

The repository's Cases bootstrap `verify` remains **BLOCKED** if the private
`bootstrap-cases-rbac-v10.private.json` provisioning journal is missing. The
journal must not be synthesized or reconstructed to imply historical ownership.

The additional `CASES_RBAC_CONFIG_READBACK` is **GET-only** and independent of
that journal: it validates the exact pinned Cases API audience on **both**
tenants, HTTPS resource details, authorized scopes, OIDC application grants,
SCIM role audience, SCIM membership, active users and exact permissions. This
proves configuration readback but **not signed-token effective authorization**,
client-specific SSO, or historical resource ownership. Results carry no remote
object IDs, credentials or PII. Missing/ambiguous resources, mismatched scopes,
roles or grants fail closed to `BLOCKED`.

The existing P010 real-browser runner now records its generated application
case UUID (not tokens, cookies, subject identifiers or case contents), and
asserts three additional real denials: customer approval forbidden, anonymous
Cases GET denied, and wrong-client/tenant Cases GET denied. The independent
`AUDIT_EVENT_READBACK` uses the **same current, checksummed P010 artifact** and
only passes if the private on-disk business ledger has exactly one creation
and one subsequent approval event for that UUID, distinct hashed actors,
expected WSO2 step-up assurance and a valid `authTime`. File ownership and
permissions are checked. Ledger discovery is bounded and refuses ambiguous
paths; set `CIAM_P011_BUSINESS_LEDGER_DIR` to the *existing* absolute business
ledger directory only if auto-discovery cannot locate it. **No ledger state is
created or removed by readiness.** Old P010 artifacts without a UUID remain
`BLOCKED` for this gate. Fresh actual browser interaction is still required.

The three new live-denial gates are separate from `FULL_LIVE_NEGATIVE_MATRIX`.
That mandatory matrix remains `BLOCKED` pending independent live evidence of
callback replay, expired/revoked tokens, canceled/stale/invalid MFA, SSO and
logout, and service-outage recovery. Do not describe any of these as live
PASS based on unit tests, mocks or the three additional browser denials.

This increment is **source-only** until installed and exercised on the Mac.
On a local checkout, run `./scripts/ciam-v10.sh offline-test`,
`./scripts/ciam-v10.sh security-audit`, then `inventory` and `readiness`.
Running `live-acceptance` creates a persistent business record and still
requires a separately authorized operator to interact with genuine WSO2 login
and TOTP; it is never launched by the source installer.
