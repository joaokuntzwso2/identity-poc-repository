# WSO2 v10 BFF runtime identity recovery

This runbook addresses a verified source/runtime mismatch when the BFF at
`127.0.0.1:4400` returns demo-path results although Git contains the live
WSO2 route guards. It does not provision roles or enable WSO2 Consent v2.

## Observed evidence (2026-10-26)

`GET /api/scenarios` returned 200, `GET /api/consent` returned 401,
`GET /api/retail/customers` returned 502 and all four
`GET /api/protected/profile?client=...` requests returned 404.
These responses match the non-live branch of the reviewed BFF source.
They **do not** establish why the wrong mode/version is listening.

## Safety

The `bff-runtime-plan` command performs process and port checks only and
prints no environment variables, credentials, cookies or full process paths.
The `bff-restart` operation is allowed only when a 0600 PID file under the
existing private runtime root identifies a current same-user Node process,
whose arguments, cwd, port 4400 listener PID and start timestamp agree.
No missing or contradictory identity evidence may be bypassed. The script
sends SIGTERM (never SIGKILL) to **only** the verified v10 local BFF process,
waits for exit, then invokes the repository's existing guarded OIDC
`start-bff` routine. It never invokes Docker or interacts with WSO2 management
APIs. The WSO2 containers and all PostgreSQL volumes remain untouched.

**Important:** restarting the BFF clears in-memory BFF sessions and requires
users to log in again. It does not revoke WSO2 tokens, terminate WSO2 SSO,
or change registered applications. Plan a short disruption to port 4400.

## Commands from the original checkout

```sh
./scripts/ciam-v10.sh bff-diagnose
./scripts/ciam-v10.sh bff-runtime-plan
```

If `decision` is `MAY_RESTART_WITH_EXPLICIT_CONFIRMATION`, run:

```sh
WSO2_CIAM_V10_BFF_RESTART_CONFIRM=RESTART_ONLY_VERIFIED_V10_BFF_4400 \
  ./scripts/ciam-v10.sh bff-restart
./scripts/ciam-v10.sh runtime-acceptance
```

If the plan says `REFUSE_NO_CHANGES`, do not use kill/pkill/killall or clear the
PID file merely to force it. Identify the actual port owner and process launcher
first. If port 4400 is unused and PID file absent, the existing
`./scripts/ciam-v10.sh bff-start` is the safe new-start path.

`runtime-acceptance` now requires the live-mode identity evidence marker;
a generic anonymous 200 from a preview service cannot pass the check.
After runtime acceptance, validate all four real browser OIDC channels again.
No live authorization or consent success is implied by these negative tests.
