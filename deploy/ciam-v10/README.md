# WSO2 CIAM v10 — repository-owned lab bootstrap

**Scope:** local WSO2 Identity Server 7.3 lab on `localhost:9444`, persistent PostgreSQL and isolated BFF `127.0.0.1:4400`. This is **not a production deployment template**: local TLS, fixed ports, and two lab domains are intentional. All configuration resources are version-controlled; credentials, journals, database state, and runtime deployments are **never** committed.

Run every command from the Git repository root:

```bash
./scripts/ciam-v10.sh test
./scripts/ciam-v10.sh status
./scripts/ciam-v10.sh bff-diagnose
```

Runtime remains at `${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}`. The bootstrap's private state is already established there on the current workstation. This repository update **does not re-create or move that state**.

## Reproducing on a NEW empty machine

1. Install Docker/Compose, Python 3.11+, and Node compatible with the project's BFF. Pin/check the WSO2 container and JDBC dependency provenance before wider deployment.
2. Ensure loopback ports 9444 and 4400 are unused.
3. From the repository root run:

```bash
WSO2_CIAM_V10_FRESH_CONFIRM=CREATE_NEW_ISOLATED_PERSISTENT_LAB ./scripts/ciam-v10.sh fresh
```

This constructs private runtime Compose files, creates PostgreSQL databases and applies the vendor SQL scripts extracted from `wso2/wso2is:7.3.0`, configures the server and starts the **isolated** new WSO2 instance. It refuses to run if the runtime path already exists. The script never invokes `docker compose down -v` and never resets PostgreSQL or the existing H2-backed WSO2 container. Verify `https://localhost:9444/console` is reachable before proceeding.

4. Then run the guarded resource bootstrap:

```bash
WSO2_CIAM_V10_DEPLOY_CONFIRM=BOOTSTRAP_RECORDED_LAB_RESOURCES \
  ./scripts/ciam-v10.sh bootstrap
```

This reuses three existing journal-aware provisioners in order: **tenant owners**, **management M2M scopes and non-admin SCIM users**, **four OIDC apps**. Each script preflights remote identities, uses journaled writes, and refuses uncertain operations. It publishes the private BFF manifest without starting a browser login or marking acceptance verified. It is designed to resume the CURRENT workstation's successfully provisioned state without recreating those resources.

5. Diagnose and start BFF:

```bash
./scripts/ciam-v10.sh bff-diagnose
./scripts/ciam-v10.sh bff-start
```

If a prior BFF launch left a dead PID, the diagnostic reports `pidState: STALE`. **Only** if `STALE` and the port is not listening:

```bash
WSO2_CIAM_V10_STALE_PID_CONFIRM=CLEAR_DEAD_PID_ONLY ./scripts/ciam-v10.sh bff-clear-stale
./scripts/ciam-v10.sh bff-start
```

This only removes a dead local PID file; it never kills a live process or restarts WSO2.

## Acceptance requirements still open

The BFF and four OIDC registrations must survive a **real browser authorization-code/PKCE login** with each tenant's `ciam_*` account and verify signed ID token, issuer, nonce, audience, and BFF session. `authenticated:false` prior to login is expected. All four BFF channels need end-to-end testing, and separate HTTPS brand sector documents/cross-tenant SSO remain unverified. API readback alone does not establish any of those claims.

## Git hygiene

- Commit only `scripts/ciam-v10.sh` and `deploy/ciam-v10/`.
- Never `git add -A` as a shortcut in this repo.
- Do not commit anything from `~/wso2-ciam-v10`, `var/wso2`, `.env`, database volumes, extracted SQL files, `*.pem`, `*.log`, or `*.private.json`.
- `git diff --cached --name-only` and `git diff --cached --check` must be reviewed before committing.
- Do **not** run the older v8 bootstrap or v9 permission probe against port 9444. The v10 code is the canonical versioned source.

<!-- CIAM_V10_REVIEW_V2 -->
## Full architecture, failure handling and acceptance

The top-level [end-to-end v10 runbook](../../docs/CIAM_V10_END_TO_END.md) documents the trust boundaries, full bootstrap sequence, port/process ownership, private state, safe-resume rules and the distinction between resource provisioning and browser acceptance. Track missing cases in the [scenario matrix](../../docs/CIAM_V10_SCENARIO_MATRIX.md).

For a same-browser, four-channel signed-login **evidence summary** (not independent cryptographic re-verification), use `python3 scripts/ciam-v10-acceptance.py` with the sanitized `/api/identity/me` JSON piped to standard input. Do not commit or share the JSON; it includes CSRF/session metadata.
