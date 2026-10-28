# P0.10 — Operator-assisted local WSO2 certificate pinning

Status: local browser infrastructure only, **NOT live MFA acceptance**.

The running local WSO2 7.3 server at `https://localhost:9444` uses an HTTPS
certificate which Chromium did not trust (`net::ERR_CERT_AUTHORITY_INVALID`).
This is *not* an OIDC or TOTP failure. The v6 source repair supports Chromium's
**SPKI (subject public key) SHA-256 allowlist**, rather than the global
`--ignore-certificate-errors` switch or Playwright `ignoreHTTPSErrors:true`.

On explicitly opted-in P0.10 browser runs, the runner connects only to
`127.0.0.1:9444` with TLS SNI `localhost`, reads its public certificate,
requires the certificate's hostname to match `localhost` and validity dates
to cover the current time, computes its SHA-256 SPKI hash, and launches a new
Chromium process with just `--ignore-certificate-errors-spki-list=<base64>`.
All browser contexts retain `ignoreHTTPSErrors:false`; certificates elsewhere
are still verified normally. This is a **local trust-on-first-use exception**
for an interactive development test, not public CA validation and not a
production browser configuration. The operator should ensure that the loopback
port belongs to the expected local WSO2 runtime before confirming trust.

The runner records only the public certificate's SHA-256 fingerprint and the
selected trust mode. It does not save passwords, OTP seeds, access tokens,
authorization codes or cookies. It refuses non-local callback redirects and
converts unexpected browser exceptions to sanitized error codes.

```sh
# Run from the root of your existing repository checkout.

# The existing v5 gate checks both applied Aurora policies and four clients.
# Requires real operator credentials and TOTP in the WSO2 Chromium UI.
# Creates a persistent test case ONLY after the customer logs in successfully.
CIAM_P010_LOCAL_WSO2_TLS_CONFIRM=TRUST_CURRENT_LOCAL_WSO2_CERTIFICATE_FOR_BROWSER_TEST \
  python3 scripts/ciam_p010_seller_live_gate.py run-live \
  --confirm INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE
```

No WSO2 management PATCHes, BFF restarts or business data writes happen during
this source-only repair. The browser acceptance command is still a **separate
explicit business-write opt-in**. Positive acceptance requires four live OIDC
logins, trusted signed claims, operator-performed TOTP and durable approval.

If the certificate hostname is not `localhost`, is expired, or changes,
stop and inspect/reissue the WSO2 certificate instead of disabling validation
more broadly. The pin is recalculated for each approved local run; for hardened
multiuser environments use a pre-provisioned private CA or out-of-band audited
certificate pinning rather than this loopback TOFU mechanism.
