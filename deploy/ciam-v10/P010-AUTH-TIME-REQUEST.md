# P0.10: Signed authentication time request (v10)

## Observed live state

The operator completed four real OIDC browser login checkpoints and the Aurora seller TOTP enrollment/step-up interaction. The BFF returned `fresh_wso2_totp_not_attested`, with `SIGNED_AUTH_TIME_MISSING_OR_INVALID`. The subsequent browser closure does not attest a successful approval. Do not interpret the QR screen alone as MFA completion.

## Source-only change

`beginApprovalChallenge` retains `max_age=0`, `prompt=login`, PKCE S256, nonce, state, and fixed Aurora ACR. When the live issuer's OIDC Discovery explicitly advertises `claims_parameter_supported: true`, it additionally requests `claims={"id_token":{"auth_time":{"essential":true}}}`. This is a request, not proof. The resulting ID token **must** still be signed and validated, match subject/issuer/audience/client, contain configured ACR and TOTP AMR, and have a numeric fresh `auth_time` and `iat` after step-up transaction start. None are inferred from token issuance or from the URL.

The denial diagnostic now distinguishes missing `auth_time` from a wrong-type claim, without logging values or tokens. No new WSO2 permissions, application changes, roles, business writes, or credential operations.

## After installation

Restart only the verified local v10 BFF with its established P0.10 assurance environment. Run operator-assisted browser acceptance again. It creates a new persistent request. Do **not** close Chromium when the step-up callback shows an error; report the `attestationGate` label, not the URL or token.

If `SIGNED_AUTH_TIME_MISSING` persists, do not weaken validation. Inspect the live tenant's Discovery `claims_parameter_supported` and WSO2 ID-token claim release / auth-time processing read-only before proposing any further WSO2 configuration changes. If `SIGNED_AUTH_TIME_WRONG_TYPE`, investigate WSO2 claim encoding and retain the numeric requirement. If step-up returns 403, no approval event may be created.

## Trust boundary

No private files staged, no role/scope changes, no WSO2 PATCH, no Docker restart, no Git command. The included installer backs up only its one modified source file and rolls it back if tests fail.

## v11 regression-compatibility correction

The first v10 installer correctly rolled back because the existing v9 diagnostic
unit test expected the old combined label `SIGNED_AUTH_TIME_MISSING_OR_INVALID`,
while v10 intentionally emits the more specific `SIGNED_AUTH_TIME_MISSING`.
The v11 installer changes only that expected label and adds wrong-type/noninteger
tests to the existing diagnostic test. It also installs the v10 source and new
test as a single rollback-guarded unit. No signed assurance check is weakened.

After an actual success, validate the final persisted case and audit event.
A new step-up attempt and new test request may be required; no prior attempt
should be counted as approved.
