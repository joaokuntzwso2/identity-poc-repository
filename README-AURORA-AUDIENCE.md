# WSO2 CIAM v10 — Aurora Web audience-only update

**Scope:** exactly one existing application, `aurora.identity.test` / `aurora-web`, hosted by the verified v10 WSO2 container on host port 9444. **No Docker restart, PostgreSQL reset, original port-9443 access, role/permission updates, secret rotation, or changes to other three apps.**

The files in this archive are additive. The repository must already contain `deploy/ciam-v10/oidc/audience_plan.py` from the previous, successful plan package. The updater pins its SHA-256 to `104702e05bd926d730227fdc0b2bfd432c640d3ef54cba7d0bc22741c3301a94` so unreviewed edits to that helper are refused. The Git HEAD is pinned by that helper to `04f4751525f02535f4f8b9880b776eb98e2f6f1d`. Unrelated worktree changes are not touched.

The prior verified readback fingerprints are also pinned:

- Application: `cfe9d0b5e3f69e85a0470826e76010f2f504ed66a79dcb6fc0481264d41732e7`
- OIDC: `71c84fa9138ab5fee976e46ba785dad5c8b4ab9dc3f8bee0ede2fc87e3394c53`

These are *fingerprints of the view-only REST GET responses*, not authorizations or proof that an access token contains the business audience.

## Install without overwriting existing files

Download the ZIP to `~/Downloads/aurora_audience_guarded.zip` and from the repository root execute:

```sh
unzip -l ~/Downloads/aurora_audience_guarded.zip
unzip -n ~/Downloads/aurora_audience_guarded.zip -d .
python3 -m unittest discover -s tests -p 'test_audience_apply.py' -v
python3 -m unittest discover -s tests -p 'test_audience_plan.py' -v
python3 deploy/ciam-v10/oidc/audience_apply.py plan
```

**Stop on any failure.** `Ran 0 tests — OK` does not qualify; this package contains 15 tests and the original plan package 6. `plan` makes only management OAuth token requests and GETs. It requires three WSO2 scopes (`internal_application_mgt_view`, `internal_application_mgt_update`, `internal_application_mgt_client_secret_view`) on the **existing Aurora management application**. It must not provision those scopes, and refuses if they are missing.

The privileged response must include an unmasked `clientSecret` matching the preexisting private OIDC journal. No private secrets or raw API documents are printed. The proposed OIDC request is built from the full, secret-visible GET document and changes only `idToken.audience` from `[]` to `["https://api.ciam-v10.test/profile"]`. It refuses unknown GET fields and excludes the known read-only `clientSecretExpiresAt` field from the PUT payload. Because exact WSO2 runtime update semantics are not verified live, even this guarded full-document PUT carries residual risk; compare documentation with your installed deployment before authorization.

## **Explicitly authorized** one-time apply (NOT automatic)

**Do not execute this step merely to test the package.** Only after reviewing the successful live `plan` result, full backup strategy, scope grant and potential ID-token audience impact, explicitly authorize one Aurora Web update:

```sh
python3 deploy/ciam-v10/oidc/audience_apply.py apply --approve I_AUTHORIZE_V10_AURORA_WEB_AUDIENCE_ONLY --expected-app-sha cfe9d0b5e3f69e85a0470826e76010f2f504ed66a79dcb6fc0481264d41732e7 --expected-oidc-sha 71c84fa9138ab5fee976e46ba785dad5c8b4ab9dc3f8bee0ede2fc87e3394c53
```

Applying runs all readbacks twice (including one refresh after obtaining the local lock), preserves all known fields and the journaled client secret, writes a new 0600 private backup and an **attempted write** journal to `~/wso2-ciam-v10/private/audience-aurora-web-v1/`, then sends at most **one** `PUT /t/aurora.identity.test/api/server/v1/applications/{appId}/inbound-protocols/oidc`. Full management readback must show only the intended custom-audience delta with unchanged client secret. Never print/open/share the private backup; it contains a client secret.

This is **not a server-side atomic compare-and-swap**; a concurrent external admin update in the narrow time window cannot be ruled out. Do not run it while other operators are changing this application. Any uncertainty leaves the journal in the state `PUT_MAY_HAVE_STARTED_OUTCOME_UNKNOWN` and apply **must never be retried automatically**.

## Read-only recovery if the PUT outcome is ambiguous

```sh
python3 deploy/ciam-v10/oidc/audience_apply.py reconcile
```

`reconcile` inspects the private backup and current GET responses without sending another `PUT`. Its `EXPECTED_AUDIENCE_READBACK_VERIFIED` means only that the management representation is in the anticipated state. It does **not** mean a new token has been issued, that the JVM used the custom audiences, or that the profile API has authorized a user.

## Acceptance after a successful management readback

Use a **fresh** Aurora Web authorization-code browser login; do not reuse a prior token. Keep token material, cookies, authorization codes, JWT payloads and introspection responses private. The existing repo's issuer-bound and client-bound, signature-verified validation and trusted introspection flow must independently prove the audience **`https://api.ciam-v10.test/profile`** and granted scope **`ciam:profile:read`**. The existing live BFF `/api/identity/me` result is not enough: protected profile API must return a real HTTP 200 with the authenticated session. Test ID token validation after changing the audience, since WSO2 documents this setting under ID token. Only after that should additional channels or revocation-denial checks be considered; Consent v2 remains blocked.

## Before publishing new sources

Review local changes, stage **only** the two new implementation/test files and README if desired, then run the repository security checks. Never stage `init.json`, private runtime paths or unreviewed local files:

```sh
git status --short
python3 -m unittest discover -s tests -p 'test_audience_apply.py' -v
python3 -m unittest discover -s tests -p 'test_audience_plan.py' -v
git add -- deploy/ciam-v10/oidc/audience_apply.py tests/test_audience_apply.py README-AURORA-AUDIENCE.md
git diff --cached --check
python3 scripts/security/check_public.py --staged
```

Do not publish or merge until the full existing CIAM offline suite passes, the diff is reviewed, and any unrelated staged files are removed. No commit or push is performed by this package.

**Reference:** WSO2 IS 7.3 Application Management REST API documents OIDC `PUT` and `internal_application_mgt_update`, and separately requires `internal_application_mgt_client_secret_view` to GET the secret. WSO2 describes the custom audience in the ID-token section; installed bundle bytecode and startup configuration audits provide supporting evidence for the access-token path but do not prove live issuance.
