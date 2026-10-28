# CIAM v10 Aurora Web Audience Updater v3

## Purpose and evidence

The existing v2 **read-only** updater stops at `OIDC_UNDOCUMENTED_GET_FIELDS_REFUSE`.
The user ran `audience_oidc_schema_probe_v1.py` and obtained one and only one
unknown GET field on both view-only and privileged representations:
`cibaAuthenticationRequest`. The earlier application and OIDC fingerprints
still matched `cfe9d0b5e3f69e85a0470826e76010f2f504ed66a79dcb6fc0481264d41732e7`
and `71c84fa9138ab5fee976e46ba785dad5c8b4ab9dc3f8bee0ede2fc87e3394c53`.

WSO2 Identity Server 7.3 supports CIBA as a product capability. However, the
published management API reference checked here did not establish the exact
`cibaAuthenticationRequest` property or show that the running endpoint accepts
it in an OIDC PUT. Treat the planned PUT as **not live-contract-verified**.

This v3 updater copies v2, adding this **one** observed property to the bounded
configuration allowlist. The value is preserved unchanged in the proposed full
PUT document (it is not silently dropped or locally synthesized). It refuses
unexpected shapes, excessively large values, or use of the CIBA grant on the
target application. Other unrecognized properties still refuse. Before/after
readback requires the CIBA value, all other OIDC fields and application metadata
to remain unchanged except `/idToken/audience`.

## Installation (no overwrite)

Run these from the checkout root after downloading the ZIP to `~/Downloads/`:

```bash
unzip -l ~/Downloads/aurora_audience_apply_v3.zip
unzip -n ~/Downloads/aurora_audience_apply_v3.zip -d .
python3 -m unittest discover -s tests -p 'test_audience_apply_v3.py' -v
python3 deploy/ciam-v10/oidc/audience_apply_v3.py plan
```

**Do not run apply yet.** A new explicit authorization is required for the Aurora
Web OIDC application change, separate from the previously approved management
scope update. A passing plan does **not** prove that the server accepts the
full-document PUT with `cibaAuthenticationRequest`; it only proves that the
server currently returns the expected values and our candidate preserves them.
Do not change the installed WSO2 runtime, restart Docker, attempt to repair
secrets, or touch port 9443. Never repeat an ambiguous PUT: use `reconcile`.

If the plan reports `CIBA_CONFIGURATION_SHAPE_REQUIRES_REVIEW`, do not amend
the allowlist without another read-only verification of *shape* (types and keys,
not values). Do not send secrets, response bodies, or tokens to chat.

## Source scope

Files:
- `deploy/ciam-v10/oidc/audience_apply_v3.py`
- `tests/test_audience_apply_v3.py`

The updater reuses the **same** existing `audience-aurora-web-v1` private write
journal and immutable backup, so a version change cannot bypass the original
one-attempt guard. It does not modify the original private journals. The only
intended audience is `https://api.ciam-v10.test/profile` in Aurora Web.

After a separately approved application update, require an authoritative
management readback, a fresh browser OIDC authorization-code login, a properly
verified API-bound access token with `ciam:profile:read`, real protected HTTP
200, and controlled WSO2-driven denial. Consent v2 stays `BLOCKED`.
