# P0.10 — Aurora conditional TOTP assurance policy (guarded stage)

This stage targets **only two existing applications** in tenant
`aurora.identity.test`: Aurora Web and Aurora Mobile Browser. It preserves
Brisa's two Basic login flows, application IDs, OIDC registrations, API
authorizations, roles, direct memberships, customer data, and audit ledger.

## Verified inputs and limitations

The live capability audit of 2026-10-28 reported enabled local TOTP
in Aurora and Brisa. The application management readback reported all
four clients using `DEFAULT` Basic-only authentication.

The reviewed, pinned WSO2 adaptive script is
`deploy/ciam-v10/p010/aurora-acr-totp-adaptive.js`.
It leaves standard logins at Step 1 (BasicAuthenticator). An explicit approval
request containing `urn:ciampoc:assurance:totp:v1` runs Step 1 then Step 2
(`totp`). It sets the ACR only in Step 2's `onSuccess` callback.

This code does **not** claim the actual WSO2 7.3 GA runtime has executed TOTP,
nor that AMR `totp` appears in a real signed ID token. The BFF must continue
to reject approval until both the exact ACR and independently verified TOTP
AMR plus fresh `auth_time` are available on the same signed subject-bound
transaction. Seller enrollment and operator-entered TOTP are still required.

## Automatic local install (no WSO2 writes)

From repository root after downloading and extracting the package:

```bash
python3 "$HOME/Downloads/ciam-p010-aurora-adaptive-v4/install.py" --check
python3 "$HOME/Downloads/ciam-p010-aurora-adaptive-v4/install.py" --apply
```

`--apply` above means **source installation only**. The installer runs
offline unit tests and JavaScript checks and rolls back its new files if
they fail. It does not restart processes or mutate identity/business state.

## Read-only fresh live WSO2 plan

```bash
python3 scripts/ciam-p010-aurora-adaptive.py plan
```

The stage reads the existing tenant/OIDC private journals, both tenant
TOTP catalogs, all four application configurations and OIDC protocols.
It refuses a missing tenant/app, changed PKCE/client/callback, unknown
script, unsupported app sequence, missing TOTP enablement, or a changed
Brisa authentication flow. It prints only fingerprints and the scope of
changes; no secrets. The script creates a local permission-0600 lock file,
but performs no WSO2 writes in `plan` mode.

## Changes requiring an explicit, separate WSO2-write authorization

The implementation contains an **approval-gated** `apply-approved` mode, but
**DO NOT RUN IT** until the operator has reviewed a fresh live plan and
explicitly approved these exact two application authentication sequence
changes. No manual WSO2 Console edits or copy/pasting plan hashes are needed.

This executor uses `PATCH /t/aurora.identity.test/api/server/v1/applications/{id}`
with ONLY the `authenticationSequence` field, preserving supported existing
step metadata, and checking the OIDC configuration and other app security
fields after each change. A separate mode-0600 write-ahead journal at
`~/wso2-ciam-v10/private/p010-aurora-mfa-policy.private.json` binds expected
app IDs and script SHA-256. A network failure, unexpected response or
readback drift marks the write `uncertain` and **blocks automatic retries**.

The current WSO2 GET output has not established that `If-Match` is enforced.
The executor therefore refuses a missing ETag without a separate operator
acknowledgement of the resulting concurrency risk. Never edit/delete the
journal to bypass a refusal. Freeze concurrent application edits during any
approved update.

## After configuration

- Re-read both Aurora flows; verify two step definitions and pinned script SHA.
- Re-read both Brisa flows; verify no changes.
- Enroll the actual Aurora seller in WSO2 TOTP using the tenant's supported
  self-service/authenticator process (no OTP seed in source or artifacts).
- Configure BFF runtime `WSO2_TOTP_STEPUP_ACR` **only after** the new ACR is
  proven in a real signed ID token; configure `WSO2_TOTP_STEPUP_AMR` based on
  the exact issuer-issued method reference (default often `totp`, but it can
  be mapped). These values are not sensitive, yet they must be attested.
- Run Playwright real-browser customer request and seller approval with
  operator-entered TOTP; record sanitized readbacks, positive and negative
  authorization, freshness, same-session/subject, and case state transition.

Reference: WSO2 Application Management REST API PATCH authenticationSequence;
WSO2 ACR-based conditional authentication; WSO2 ACR/AMR documentation.
