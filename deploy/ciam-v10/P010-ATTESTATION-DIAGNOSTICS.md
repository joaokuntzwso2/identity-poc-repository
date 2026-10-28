# P0.10 — Privacy-safe WSO2 step-up attestation diagnostics (v9)

The real Aurora Web seller reached WSO2 TOTP enrollment/challenge but the
approval callback returned `fresh_wso2_totp_not_attested`. The original BFF
collapsed all signed ACR/AMR/time evidence failures into this one code.

This scoped diagnostic preserves the original 403 and business denial while
adding an `attestationGate` enumeration to the callback's JSON response:

- `SIGNED_ACR_MISSING` / `SIGNED_ACR_MISMATCH`: selected ACR not returned as the expected signed value
- `SIGNED_AMR_MISSING_OR_INVALID` / `SIGNED_AMR_TOTP_NOT_PRESENT`: signed method evidence unavailable or not TOTP
- `SIGNED_AUTH_TIME_MISSING_OR_INVALID`, `SIGNED_AUTH_TIME_BEFORE_TRANSACTION`, `SIGNED_AUTH_TIME_IN_FUTURE`, `SIGNED_AUTH_TIME_TOO_OLD`: authentication-time evidence absent or not fresh
- `SIGNED_IAT_MISSING_OR_INVALID` / `SIGNED_IAT_BEFORE_TRANSACTION`: token issuance time not valid for the approval transaction

Only constant classification labels are returned; no ID token, raw claim values,
OAuth code, nonce, state, TOTP seed, password, cookie, or user identifier is
logged or stored by the new code. No claim is fabricated and no check is
removed or relaxed. This is a diagnostic stage, NOT a WSO2 policy repair.

## Operator sequence

1. Install via the guarded installer (`--check`, then `--apply`).
2. Restart only the verified BFF using the existing P0.10 seller live gate.
3. Rerun the browser acceptance with a correctly authorized Aurora customer
   and an independent Aurora seller. Complete the WSO2 TOTP enrollment fully:
   scan the QR code, continue, then enter the one-time password in WSO2.
4. If the browser shows `fresh_wso2_totp_not_attested`, report **only** the
   `attestationGate` label. Do not paste a full callback URL or token.
5. Do not repeat an approval or modify business data just to test claims.

WSO2 uses `context.selectedAcr` and the actual authenticator methods for
OIDC `acr`/`amr`; the supported first-time TOTP enrollment requires completing
the OTP verification after QR scanning. Whether an `auth_time` claim appears
in the local signed ID token must be independently demonstrated.
