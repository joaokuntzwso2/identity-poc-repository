# WSO2 v10: guarded introspection configuration

This source-owned correction does **not** weaken the introspection scope policy, assign an internal scope to existing OIDC applications, or prove protected API success. WSO2's supported client-ID/client-secret introspection requires `BasicClientAuthentication` and an authorized caller with `internal_oauth2_introspect`. The BFF currently uses each browser OIDC client's credentials, so the four client permissions must be reviewed before assuming that introspection is authorized.

## Fresh installations

`server/render.py` merges an exact `[[resource.access_control]]` introspection BasicClientAuthentication rule and explicitly pins `[resource_access_control.introspect].scopes = ["internal_oauth2_introspect"]`. It refuses conflicting or empty scopes. No second TOML is created. This policy does not itself grant the introspection scope to any application.

Future fresh bootstrap acceptance must check the introspection contract before declaring real access-token authorization. A bare anonymous HTTP negative-gate pass does not prove it. Do not grant introspection to all applications indiscriminately or bypass with `scopes = []`.

## Existing isolated v10

Run the plan first:

```bash
./scripts/ciam-v10.sh introspection-plan
```

The plan must prove the private TOML equals the mounted v10 config, the managed `wso2-ciam-v10_isconf` volume is present, and the container is the expected `wso2-ciam-v10-is-1` on local 9444. It never touches the original 9443 instance or the databases.

Staging makes a 0600 backup in the existing private runtime, writes a private pre-operation journal, and copies a validated TOML only into the v10 config volume. It does **not** restart WSO2:

```bash
WSO2_CIAM_V10_INTROSPECTION_CONFIG_CONFIRM=STAGE_VERIFIED_V10_INTROSPECTION_CONFIG_ONLY \
  ./scripts/ciam-v10.sh introspection-stage
```

When scheduled downtime is approved, restart ONLY the verified v10 WSO2 (existing sessions may be disrupted):

```bash
WSO2_CIAM_V10_INTROSPECTION_RESTART_CONFIRM=RESTART_ONLY_V10_WSO2_AFTER_INTROSPECTION_STAGE \
  ./scripts/ciam-v10.sh introspection-restart
```

Read status:

```bash
./scripts/ciam-v10.sh introspection-status
```

**Stop on any ambiguous stage or restart**; preserve the journal and backup for manual reconciliation. Do not repeat writes by removing the journal. The v10 PostgreSQL identity/shared/agent databases are not reset or modified by these commands.

## Mandatory post-restart acceptance

Use the previously validated capability probe with a randomly generated invalid access token against **each** tenant's introspection endpoint, using the corresponding application client credentials. A successful authenticated probe must yield HTTP 200 with `active: false`. A 401 or 403 means the handler or `internal_oauth2_introspect` authorization is still blocked. **Do not** configure `scopes = []`, substitute administrator credentials, or treat HTTP 401 as feature absence.

After that, perform a fresh OAuth login and verify the protected profile with WSO2's active, correctly bound access token; sanitize the response (never output raw tokens). WSO2's documented introspection response may omit `aud`; BFF audience binding must be reviewed separately and not disabled as a workaround. Also test token expiry, revocation and tenant separation. OAuth scope consent is distinct from Consent Management v2, which remains blocked on this GA image.

Status: configuration policy `TESTED_OFFLINE` after unit tests; live config stage and introspection authorization `BLOCKED` pending execution and scope grant verification.
