# Magalu v10 security stage: guarded bootstrap and Console review

## Target and non-destructive boundary

**Only** the persistent `wso2/wso2is:7.3.0` CIAM v10 deployment on
`:9444`, with pre-existing Aurora and Brisa root tenants and exactly four
existing `*-web` and `*-app` OIDC clients. Do not use `wso2-lab.sh`, the
Update18+ `:9443` lab, `fresh`, `fresh-bootstrap`, or broad `bootstrap` on a
persistent home.

The upstream repository was not mounted in the source-generation environment.
This is a **mergeable source overlay**, not a committed change or a deployed
WSO2 bundle. Its source was created from the provided architecture assessment;
a live GA 7.3 binary-compatible OSGi build is deliberately gated.

## Merge and entry point

Merge this overlay into the root of `identity-poc-repository`. **Never overwrite
an existing file except after a reviewed diff.** After merge:

```bash
# Adds only an early security-* dispatcher before any existing P2 prehook:
# No manual dispatcher edits are required; the apply wrapper installs it.

# Read-only local/docker inventory (no need for Console changes):
./scripts/ciam-magalu-bootstrap.sh inventory

# Bind the existing tenant-owner identities and the pinned v10 TLS CA certificate
# from your existing operator secret store, not from app/browser/user input:
export MAGALU_AURORA_ADMIN_USER='existing-tenant-owner'
export MAGALU_AURORA_ADMIN_PASSWORD='from-existing-private-operator-secret'
export MAGALU_BRISA_ADMIN_USER='existing-tenant-owner'
export MAGALU_BRISA_ADMIN_PASSWORD='from-existing-private-operator-secret'
export CIAM_V10_CA_CERT='/secure/path/to/existing-v10-ca.pem'

# Read-only management API inventory and planned diffs for all four applications
# and both tenants. Writes only a 0600 local plan journal, NO WSO2 changes:
./scripts/ciam-magalu-bootstrap.sh plan

# Operator reviews exact plan SHA, then a single command handles compilation,
# shared state database, native policies, OSGi deploy/restart, app PATCH/readback:
./scripts/ciam-magalu-bootstrap.sh bootstrap --approve '<sha256-from-plan>'

# Machine-readable runtime / Console configuration verification:
./scripts/ciam-magalu-bootstrap.sh verify

# If a live rollout needs to be undone, require the ORIGINAL reviewed plan SHA:
./scripts/ciam-magalu-bootstrap.sh rollback --approve '<original-plan-sha256>'
```

Both `security-bootstrap` and `security-apply` invoke the same guarded stage.
No `cp` into WSO2 or manual Console setup is part of that stage. The bootstrap
**refuses to proceed** if runtime is inaccessible, has wrong image/ports,
applications are missing/duplicated, policies/scripts drifted, GA binaries
cannot compile the adapter, required credentials/CA are unavailable, or OSGi
activation cannot be observed. A refused install is a non-success; it must not
be reported as completed deployment.

### Automatic materialization

On a successful guarded apply, the stage is designed to:

1. Validate the image and service labels, existing containers, secure TLS,
   tenant owner authorization, exact application IDs, current authentication
   sequences, and governance connector property IDs. Preserve their original
   settings in the 0600 private plan/journal.
2. Extract the **running** GA image's plugin/lib JARs automatically and invoke
   `build-extension.sh` to compile the custom function/event handler. This is
   a strict binary compatibility check, **not** a guessed Maven dependency
   version or successful activation by itself.
3. Generate risk HMAC and database secrets into
   `$CIAM_V10_HOME/private/magalu-risk/secrets.env` (mode 0600). Create the
   separate `ciam_risk` database and `magalu_risk.events` table on existing
   persistent PostgreSQL. Do not touch WSO2 identity/shared DB schemas.
4. Stage `aurora.properties` and `brisa.properties` in the private home and
   generate a `compose.magalu-risk.yaml` override that mounts the compiled
   OSGi bundle, policy files and a derived private deployment.toml, with the
   `[[event_handler]]` registration and bounded risk JDBC environment. A
   risk-retention sidecar prunes pseudonymized event rows; the Java event spool
   is bounded and stays under the WSO2 logs directory.
5. Start/restart **only** the v10 service and risk retention component. Require
   `MAGALU_RISK_ACTIVE` from the running DS activation before touching any
   login sequence. The event handler collects success/failure signal telemetry;
   the JS function is the post-credential enforcement gate.
6. PATCH/readback the **native account-lock** governance connector per tenant
   (Aurora 8 attempts/5 min, Brisa 12 attempts/3 min, factor 2) with bounded
   temporary durations. It is not the distributed attack detector.
7. PATCH/readback only the existing four `authenticationSequence` objects,
   preserving app IDs, credentials, callbacks and OIDC configuration. Aurora's
   existing seller approval ACR/TOTP path must match known content; unknown
   or concurrently changed sequences are rejected. Brisa adds a TOTP stage.
8. Verify private JAR SHA, runtime mounts, activation marker, risk schema,
   pruning service, two sets of native governance values and four Console
   login-flow readbacks. Emit a structured JSON result with separate evidence
   labels: `OFFLINE_TEST`, `MANAGEMENT_READBACK`, `LIVE_WSO2` (not performed).

**The apply workflow is not yet production-proven:** it has not been executed
on the actual GA v10 host. Do not run it on customer identities without a
controlled maintenance window, backup, test identities and live negative
acceptance. Live token-issuance denial and challenge enforcement cannot be
inferred from a configuration readback.

## Visual inspection — native WSO2 IS Console

Open <https://localhost:9444/console> (not `:9443`). Switch to the appropriate
root tenant, then inspect:

- **Applications → aurora-web → Login Flow:** Basic step 1, TOTP step 2,
  Conditional Authentication script containing `magaluRiskCheck` and the
  original seller-approval `requestedAcr` condition.
- Repeat **aurora-app**, then switch to Brisa and inspect **brisa-web** and
  **brisa-app**. All four must show the risk function in their login scripts.
- **Login & Registration → Login Security → Login Attempts:** native policy
  Enabled with Aurora 8 / Brisa 12 max failures and brand-specific temporary
  lock duration. These settings are bootstrapped through the documented
  governance management API, not by editing via Console.

These native Console views display **configured login flow and governance**, not
per-event risk decisions or OSGi service health. There is no proven GA 7.3
Console plugin API in this source-only environment to embed a proprietary
risk dashboard. For decisions, use sanitized, access-controlled evidence in
`repository/logs/magalu-risk-events.jsonl`, the private risk DB, and the
`security-verify` readback. Do **not** claim a risk-score table is present in
stock Console, nor enable an unverified UI extension just to satisfy a demo.

## Enforcement limitations / acceptance classification

| Control | Source present | Real GA integration evidence |
| --- | --- | --- |
| Sliding-window multi-account network spray, correlated rotating IP/device/agent cadence | Java `Engine` with offline checks | NOT VERIFIED |
| Tenant-specific normal/deviation baselines, HMAC privacy, trusted proxy checks | Java `Engine`, `Pseudonymizer`, `TrustedClientIp` | NOT VERIFIED |
| Bounded shared state | Separate PostgreSQL `PgStore`, schema, retention | NOT VERIFIED |
| Failure/success collection | `Wso2RiskEvents`, GA event handler config | Event payload compatibility NOT VERIFIED |
| ALLOW/DENY decision in WSO2 conditional flow | `Wso2RiskFunction`, `Wso2RiskComponent`, JS script | GA binary + live token test NOT VERIFIED |
| STEP_UP, CHALLENGE | Both mapped to TOTP, fail if not completed | Distinct bot challenge is NOT IMPLEMENTED; live proof needed |
| DELAY | Immediate WSO2 denial, retry when pressure reduces; no sleep | Not a true timed admission delay; PARTIAL |
| Native temporary account locking | Automated tenant governance connector reconciliation | Readback/live lock NOT VERIFIED |
| Antifraud external outage | No antifraud HTTP dependency in Java decision path | OFFLINE check only |
| Security logs | Bounded local pseudonymous spool | SIEM delivery/acknowledgement NOT IMPLEMENTED |
| Visual WSO2 Console views | Login Flow and Login Attempts | Configuration visibility only, NOT VERIFIED in runtime |

Important: a JavaScript post-Basic gate cannot reject guesses **before** Basic
credential verification and the failure event payload may not be available for
nonexistent users. This overlay does not satisfy a full pre-Basic bot gate,
real bot interactive proof or comprehensive enumeration timing acceptance.
Do not use it as a completed production Magalu RFP acceptance until the
version-pinned extension and real WSO2 negative tests pass.

## Offline verification

```bash
bash extensions/magalu-wso2-risk/build-core.sh
python3 -m unittest discover -s deploy/ciam-v10/security/tests -v
bash -n scripts/ciam-v10-security.sh extensions/magalu-wso2-risk/build-extension.sh
node --check deploy/ciam-v10/security/scripts/magalu-risk-flow.js
```

`build-core.sh` compiles only pure Java source, **not** the WSO2 API adapter.
The actual bundle requires `WSO2_HOME` to point to the exactly shipped GA
runtime plugin/lib inventory, together with its pinned image ID. On the v10
host, `security-bootstrap` extracts those automatically and runs the builder.
