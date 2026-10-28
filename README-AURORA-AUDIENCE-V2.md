# Aurora Web OIDC Audience Guard v2 — PLAN FIRST

This is a narrowly corrected version of `deploy/ciam-v10/oidc/audience_apply.py`.
It is NOT an authority for general-purpose application mutation.

## Why v1 refused

WSO2's OIDC GET representation can contain documented `hybridFlow` configuration
and response metadata `state`, `multipleClientSecretsConfigured`, plus
`clientSecretExpiresAt` (which appears in the API update schema but is
deliberately excluded under this guard when its value is zero). The v1
allowlist omitted `hybridFlow` and the first two response metadata fields. The v2 updater preserves `hybridFlow` in a full-document PUT,
and accepts only strictly validated GET metadata (never silently strips unknown
configurations). It refuses inactive clients, multiple active secrets, and
expiring client secrets because the unchanged-client contract is not established
for those conditions.

## Install (do not overwrite existing scripts)

From the repository root:

    unzip -l ~/Downloads/aurora_audience_apply_v2.zip
    unzip -n ~/Downloads/aurora_audience_apply_v2.zip -d .
    python3 -m unittest discover -s tests -p 'test_audience_apply_v2.py' -v
    python3 deploy/ciam-v10/oidc/audience_apply_v2.py plan

A successful `plan` is READ-ONLY and reports a minimal intended audience change
for Aurora Web only. It requests management OAuth tokens and GETs from the
pinned WSO2 v10 instance on port 9444; it does not change WSO2 or Git.

Do NOT run apply as part of this step. Application audience mutation requires
separate explicit approval after the live plan passes. Do NOT re-run any `apply`
when a journal or backup already exists. Use the `reconcile` mode to inspect any
previous uncertain attempt.

## Protections preserved

- Pinned repo HEAD and original read-only planner SHA.
- Private journal application identity, client ID, callback, PKCE and JWT guards.
- The previously verified full GET SHA-256 fingerprints.
- Only the documented `hybridFlow` field is added to writable allowlist.
- `clientSecret` must be genuinely available and match the private journal.
- `clientSecretExpiresAt` must be 0 if present; `state` ACTIVE; no multiple secrets.
- All other unexpected GET fields remain blocked.
- Single-attempt PATCH/PUT behavior with private, immutable backup and journal,
  reusing the SAME v1 journal directory (no bypass of prior attempts).
- No Docker/WSO2 restart, user changes, secret generation or tenant changes.

## Unverified acceptance

Neither the local tests nor the plan prove newly issued JWT audience or protected
HTTP 200. Re-check a fresh legitimate OIDC code flow only after a separately
approved OIDC audience mutation and authoritative management readback.

The WSO2 API uses a full-document OIDC PUT; further runtime-managed extra fields
might still cause refusal and must be reviewed rather than guessed.
