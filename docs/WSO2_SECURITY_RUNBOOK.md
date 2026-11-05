> **Installation note (revision 4f6227c):** Use `install-into-checkout.sh` from the revised `magalu-wso2-security-4f6227c.zip`; the original unified Git patch targets a different `cli.py` layout and must not be applied to this revision. The installer is source-only and does not perform a live WSO2 write.

# Magalu native security: WSO2 Identity Server 7.3.0 GA CIAM v10

**Status: source implemented, OFFLINE_TESTED only. NOT INSTALLED OR LIVE VERIFIED by the assessment author.**

The implementation is an additive stage inside `deploy/ciam-v10/cli.py`, dispatched by the existing `scripts/ciam-v10.sh`. It does not use `wso2-lab.sh`, Update 18, port 9443, a second tenant creator, a manual Console action, or WSO2 database changes. Existing tenant/app/client IDs, OAuth callbacks, PKCE, and passwords remain unchanged. Operator must review and test in an isolated GA v10 runtime before approving writes.

## Protected resources and desired policies

| Tenant | Max failed passwords | Initial lock | Lock multiplier | Step-up threshold | SSO reCAPTCHA |
|---|---:|---:|---:|---:|---|
| Aurora (`aurora.identity.test`) | 5 | 5 min | 2× | 3 prior failures | On after 2 failed attempts |
| Brisa (`brisa.identity.test`) | 6 | 10 min | 2× | 4 prior failures | On after 2 failed attempts |

Edit `deploy/ciam-v10/security/policy/{aurora,brisa}.json` **before** planning the change. The thresholds are sandbox examples, not a production anti-abuse guarantee. A successful password step leads to conditional step 2 when the WSO2 local `failedLoginAttemptsBeforeSuccess` claim is at or above the threshold. Aurora's `urn:ciampoc:assurance:totp:v1` request **always** invokes step 2 and sets `selectedAcr` only after genuine WSO2 TOTP success. Brisa never asserts Aurora's approval ACR. User TOTP enrollment and live signed `amr`/`auth_time` require separate acceptance.

The bot configuration uses documented GA `[recaptcha]` settings and tenant-specific Identity Governance SSO reCAPTCHA properties. This is a Google-backed challenge, **not a local bot scoring engine** and not a replacement for distributed credential-stuffing defense. WSO2 may call Google synchronously to validate a challenge. Configure a Google site key whose registered domains match the sandbox login host. The source requires keys; it never supplies dummy keys.

## Prerequisites

- An initialized, persistent **`wso2/wso2is:7.3.0`** v10 stack in `CIAM_V10_HOME` (default `$HOME/wso2-ciam-v10`), exact Docker Compose project `wso2-ciam-v10`, container `wso2-ciam-v10-is-1`, localhost TLS on 9444, and the existing three 0600 bootstrap journals for tenants, OIDC and resources.
- The four known OIDC applications already exist and are journal-owned; the `bridge-bff` stage has created `$CIAM_V10_HOME/private/wso2-9444-leaf.pem` (0600). The client **requires certificate-chain and hostname verification** with the pinned cert; certificate mismatch stops the stage.
- Both tenant owners (`labtenantadmin@<tenant>`) remain available via private journal credentials; no passwords are printed or rotated.
- The GA authenticator API reports the local TOTP authenticator enabled in both tenants; the live governance category/connector API exposes the properties named in the [official governance catalog](https://is.docs.wso2.com/en/7.3.0/apis/governance-connectors/).
- A private 0600 JSON file containing **real Google credentials**, at `$CIAM_V10_HOME/private/magalu-recaptcha.private.json`, OR pointed to by `MAGALU_RECAPTCHA_CREDENTIAL_FILE`. An external source path outside the repository is useful when performing `fresh-bootstrap` before `CIAM_V10_HOME` exists.
- Exclusive maintenance window for a guarded restart of the existing v10 Docker container; user session interruption is possible. `MAGALU_SECURITY_ALLOW_RESTART` must be explicitly set on incremental apply. Do not restart port 9443.

Example *format only* (do not use these placeholder strings or commit this file):

```json
{
  "version": "v3",
  "site_key": "REPLACE_WITH_REAL_GOOGLE_SITE_KEY",
  "secret_key": "REPLACE_WITH_REAL_GOOGLE_SECRET_KEY",
  "threshold": 0.5
}
```

Use `chmod 700` on the containing private directory and `chmod 600` on the JSON. Supported versions are `v2` and `v3`. The script never echoes credentials, never writes them into the Git checkout, and refuses a credential file inside the checkout. The private generated TOML and backup contain the keys and must be protected, encrypted at rest and excluded from backup publication.

## Read-only plan

From the existing repository checkout:

```bash
export CIAM_V10_HOME="${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}"
export MAGALU_RECAPTCHA_CREDENTIAL_FILE="$HOME/.config/wso2-ciam-v10/magalu-recaptcha.private.json"
umask 077
./scripts/ciam-v10.sh security-status
./scripts/ciam-v10.sh security-plan > "$CIAM_V10_HOME/private/magalu-security-plan.private.json"
python3 -m json.tool "$CIAM_V10_HOME/private/magalu-security-plan.private.json" >/dev/null
```

Plan is GET-only against WSO2 and `docker inspect`/`docker cp` read-only against **exact GA v10**. It prints connector IDs discovered live, desired differences, app sequence hashes, and `planSha256`; it never prints tokens, client secrets or Google keys. If a property is missing or an unowned script appears, it fails closed.

## Explicit apply and readback

```bash
export MAGALU_SECURITY_PLAN_SHA256="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["planSha256"])' "$CIAM_V10_HOME/private/magalu-security-plan.private.json")"
export MAGALU_SECURITY_CONFIRM=APPLY_MAGALU_NATIVE_SECURITY_TO_EXISTING_GA_V10
export MAGALU_SECURITY_ALLOW_RESTART=YES_RESTART_ONLY_V10_GA
# ONLY if the GA endpoint fails to return ETag AND exclusive access to app API is assured:
# export MAGALU_SECURITY_ACK_NO_ETAG=ACK_NO_HTTP_ETAG_EXCLUSIVE_MAINTENANCE_WINDOW
./scripts/ciam-v10.sh security-apply
./scripts/ciam-v10.sh security-verify
./scripts/ciam-v10.sh security-status
```

On a **new supported v10** installation, prepare real credentials **before** invoking the existing `fresh-bootstrap` command: export `MAGALU_RECAPTCHA_CREDENTIAL_FILE` pointing at a private source outside the repository. The authoritative `bootstrap_all()` automatically obtains a fresh security plan, applies it (and restarts only v10 if necessary), then verifies management readback **before** launching the BFF. Keep the existing v10 bootstrap consent/authorization environment confirmations unchanged. If you are applying to an existing state, use the dedicated commands instead of replaying `fresh`, `fresh-bootstrap`, `bootstrap` or `bff-start`.

An absent `If-Match` ETag is **not silently ignored**. The optional explicit acknowledgement permits the P0.10-style immediate GET/hash check and journaled readback only in a single-writer maintenance window; it is not an atomic compare-and-swap and must be risk-accepted. When unsupported endpoint/contract behavior is encountered, stop and investigate rather than upgrading WSO2 or editing tables.

## Durable journal and failure behavior

`$CIAM_V10_HOME/private/magalu-native-security.private.json` (0600) is the write-ahead journal. Each remote write goes through `pending → write-started → verified`; any exception after write start records `uncertain` and refuses automatic replay. A guarded TOML stage saves `magalu-deployment-before.private.toml`, writes the exact v10 configuration volume, verifies it, restarts the **GA** container, then verifies the original keys are staged. The journal is only marked `verified` after all management GETs match. Repeat apply is **verify-only** if the journal owns the exact effective state. Drift, unknown resources, attempts to adopt already-enabled unowned controls, or changed policies stop. No automatic rollback occurs after an uncertain write.

**Important:** there is no automated rollback command in this stage: rollback of a potentially successful but journal-uncertain remote write requires a new review, a pre-change snapshot, and live change authorization. Never force-retry after a timeout.

## Offline and live verification

```bash
python3 -m unittest discover -s deploy/ciam-v10/security/tests -v
node --test deploy/ciam-v10/security/tests/test_adaptive.mjs
# On actual GA v10 host only; management readback, NOT a live sign-in test:
MAGALU_LIVE_WSO2=YES_REAL_GA python3 -m unittest \
  discover -s deploy/ciam-v10/security/tests -p test_live_wso2.py -v
```

The runtime's `security-verify` asserts two separate tenant policy sets and all four app authentication sequences, checks the pinned GA Docker runtime, and compares the private `[recaptcha]` TOML against the running WSO2 volume. JDK 17 deployments may require WSO2 adaptive-authentication image preparation (`adaptive.sh`); neither a successful management API PATCH nor a sequence GET proves the JS engine executed. Do not disable a WSO2 guard or silently replace the GA v10 image; require a real sign-in that executes the conditional branch before claiming engine readiness. It **does not prove** that Google issued a challenge, that an account locks/unlocks after real failures, or that an enrolled user completed TOTP. For full acceptance, run controlled real-browser sign-in flows (including wrong passwords and post-lock correct passwords) against each tenant, verify expected lock duration and unlock, real Google challenge success/failure, genuine TOTP for threshold/approval, and signed `acr`/`amr` and `auth_time`. Record the results separately as `LIVE_WSO2`, not as `MANAGEMENT_READBACK`.

Do not lock the existing demo users. Use isolated test accounts and rate-limited scripted browser sessions. For locking tests verify `N−1`, `N`, correct-password while locked, time-based unlock, and independent tenant policy. For login-attempt-based step-up verify `threshold−1`, `threshold`, failed OTP and successful OTP. For bot verify the real Google response round-trip; an offline double cannot pass. Preserve existing P0.10 Aurora seller approval signed evidence and four BFF callbacks with real browser tests.

## WSO2 7.3 API and permission contracts

- Tenant Identity Governance `GET /t/{domain}/api/server/v1/identity-governance`, category GET, `/connectors` GET and connector `PATCH` with `{"operation":"UPDATE","properties":[{"name":"...","value":"..."}]}`. All category/connector IDs and effective property values are fetched live. The documented OAuth scopes are `internal_governance_view` (GET) and `internal_governance_update` (PATCH). Existing P119 uses the tenant owner's Basic API access; **no new M2M scopes are granted**. If migrating to OAuth, discover the exact governance resource scope from GA's API resource registry before authorization.
- Application `GET /t/{domain}/api/server/v1/applications/{id}`, OIDC inbound protocol GET, `PATCH /applications/{id}` for a new two-step sequence, and `PUT /applications/{id}/authenticationSequence/script` for an existing owned two-step flow. When using OAuth rather than existing tenant owner Basic, WSO2 documents `internal_application_mgt_view`, `internal_application_mgt_update`, and `internal_application_script_update`. This implementation deliberately does not modify the current M2M credentials or grant additional management scopes.
- `GET /t/{domain}/api/server/v1/authenticators` (or GA-compatible `/configs/authenticators?type=LOCAL`) must report enabled local TOTP. Neither authenticator listing nor sequence GET proves enrollment or token assurance.
- Supported GA references: [governance connectors](https://is.docs.wso2.com/en/7.3.0/apis/governance-connectors/), [login-attempt security](https://is.docs.wso2.com/en/7.3.0/guides/account-configurations/login-security/login-attempts/), [bot detection](https://is.docs.wso2.com/en/7.3.0/guides/account-configurations/login-security/bot-detection/), [login-attempt-based conditional auth](https://is.docs.wso2.com/en/latest/guides/authentication/conditional-auth/login-attempt-based-template/), [application management REST](https://is.docs.wso2.com/en/7.3.0/apis/application-rest-api/).

**Out of scope here:** distributed stuffing patterns, per-account behavioral baselines, SIEM export, a custom Java/OSGi risk engine, complete anti-enumeration controls and non-Google local bot detection. Native account locking plus Google reCAPTCHA do not satisfy those RFP requirements. No live runtime was accessible when this source patch was authored.
