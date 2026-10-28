# One-time WSO2 audience recovery (historical)

`ciam-v4-audience-bootstrap-v4_4.py` is the **exact bounded recovery source** used to reconcile the Aurora Web OIDC audience in the existing v10 demo on 2026-10-28. It is retained for source history and auditability, **not** as a generic installer for a fresh WSO2 instance.

The script validates a previously saved private pre-change OIDC configuration and an existing recovery journal already at two recorded unsuccessful attempts. It uses a narrowly restricted in-memory HTTPS PUT transport and readback before treating any change as verified. Do **not** delete/reset its private journal to force a new write or run it against a new tenant, another app, or an unknown version of the shared HTTPS helper. The source is allowed to fail closed.

The successful live result was `businessAudienceConfigured: true`, `readback: VERIFIED`, `bff: RESTARTED`; a subsequent fresh real Ana login separately confirmed HTTP 200 for both profile and cases APIs. Tests of the recovery code are in `tests/test_audience_bootstrap_v4_4.py` and use local simulated HTTP fixtures; no fake identity is used in runtime.

See [`../../docs/CIAM_V10_IMPLEMENTATION_MAP.md`](../../docs/CIAM_V10_IMPLEMENTATION_MAP.md) for intended token authority relationships.
