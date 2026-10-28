# CIAM v10 — Read-only repository baseline and WSO2 inventory (P0.01–P0.03)

This utility inspects a **fixed Git HEAD** and a running, separately managed **local WSO2 IS 7.3 v10** deployment. It never provisions, deletes, restarts, rotates credentials or changes WSO2 configuration. The server's tenant and application authority remains WSO2, and the existing bootstrap scripts remain canonical for writes.

## Repository root commands

```bash
pwd    # Must be your poc-implementation repository root
python3 -m unittest discover -s tests -p 'test_ciam_v10_inspect.py' -v
python3 scripts/ciam-v10-inspect.py --mode source
python3 scripts/ciam-v10-inspect.py --mode runtime --skip-tests
python3 scripts/ciam-v10-inspect.py --mode all --with-runtime-negative
```

`--mode all` executes the existing `./scripts/ciam-v10.sh test`, `status`, and `bff-diagnose` commands. `--with-runtime-negative` additionally runs the existing negative (not positive browser-login) acceptance stage. `--skip-tests` disables the offline test stage, not WSO2 inventory. All console output is allowlisted: no credential or journal contents are printed.

Reports are stored with mode 0600 under `${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}/inspection/<UTC>-<Git SHA>-<pid>/` (directory mode 0700); **do not add them to Git**. Exit code 0 means this **inspection** had no recorded blockers, not that interactive authentication, TOTP, consent or cross-channel SSO passed. Exit code 2 means findings or missing proof. Exit code 3 indicates an inability to create the inspection report.

## Verified inputs and boundaries

- Source components: `deploy/ciam-v10/cli.py`, `tenants/provision.py`, `resources/bootstrap.py`, `oidc/bootstrap.py`, `authority/bootstrap.py`, `identities/bootstrap.py`, `services/identity-bff/src/`, and the root `README.md`.
- Runtime home: `${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}`. Source reports are hashed by Git HEAD. Uncommitted files are explicitly flagged.
- Auth: existing private `admin.private.json` and `bootstrap-tenants-v10.private.json`; no credentials entered as command arguments and no secret values in JSON output. Private JSON files must be owned by the current user, be regular non-symlink files, and have mode 0600.
- Local TLS: the already retained `${CIAM_V10_HOME}/private/wso2-9444-leaf.pem` must exist. The WSO2 server leaf certificate must match its SHA-256 fingerprint **before an authenticated request is sent**. If not, the scan stops instead of accepting arbitrary local TLS certificates. A legitimate certificate rotation requires a separate approved certificate trust refresh, not a silent new pin.
- API reads: Carbon Super tenant/owner inventory; tenant-qualified application, API-resource/scope, SCIM Users, Groups, Roles readbacks; four OIDC client details; per-tenant OIDC discovery. Management permissions are observed through API authorization success or failure; a 403/404 is reported as **blocked**, not evidence that an object is absent. Cursor-based catalogs and SCIM pagination are bounded and fail closed if incomplete.

## WSO2 7.3 compatibility

This inventory confirms what the running management APIs and discovery endpoints actually return. It checks authorization code, mandatory PKCE, confidential client setting, pairwise subject, callbacks, issuer/JWKS endpoint domains, and application role audience for the four provisioned clients.

**The Docker tag `wso2/wso2is:7.3.0` cannot establish an exact WSO2 product update level.** The tool records container image identity and base-version evidence; exact update level remains `NOT_PROVEN`. To close this gap, retrieve authoritative update-manager or WSO2-provided product build/update metadata from the installed instance through an approved operational channel and attach an independently reviewed, sanitized attestation to the release evidence. Do not infer that consent v2 is supported just because a diagnostic path returns a response.

A management configuration GET is not successful OIDC browser authentication, nor is a local unauthenticated probe proof of real user login. Positive MFA, browser login, emitted-token claims and consent behavior require separate runtime acceptance tasks.

## Decision workflow

1. Before installation, record the current `git rev-parse HEAD` and inspect `git status --short`; don't discard local modifications.
2. Install this package into the **matching repo root** and run its offline tests.
3. Run `--mode source`; note the pre-commit dirty state, canonical component existence, legacy inventory and README heuristics.
4. Run `--mode runtime` against the live **v10** instance. Review each `BLOCKED`, `ACTION_REQUIRED`, `NOT_PROVEN` finding and the full private JSON, while retaining its privacy.
5. Inspect the exact staged files (`git diff --cached --name-only`, `git diff --cached --check`) and commit only the new scripts, tests and this guide plus the README entry. Do not stage journals, reports or secrets.
6. Re-run the source inspection **after committing** to capture the pinned clean HEAD of the new baseline. Keep both before/after evidence under private runtime storage.

## Current scope limitations

The source files describe explicit `aurora.identity.test` and `brisa.identity.test` tenants; `web` and `app` are separate confidential **browser-backed** OIDC clients. `app` is not proof of a native mobile app. The security review of session behavior and actual token issuance belongs to later work items. The old preview API remains outside WSO2 authority and should not be treated as live IAM evidence.

Do not run `fresh`, `bootstrap`, `authorization-apply`, `consent-apply`, database reset, or container deletion as part of this inspection. Never commit `~/wso2-ciam-v10/`, `var/wso2/`, access tokens, secrets or API response dumps.
