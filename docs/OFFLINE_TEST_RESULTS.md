# Execution record — 2026-11-05

Scope: source-only local overlay. Neither the GitHub repository checkout nor
persistent v10 Docker image, private journals, PostgreSQL or WSO2 Console were
reachable here. A positive result is **not** a real WSO2 integration pass.

| Evidence class | Check | Result |
| --- | --- | --- |
| OFFLINE_TEST | Java pure core `javac --release 11`, `AcceptanceTest` | PASS — 31 assertions |
| OFFLINE_TEST | Python `unittest discover` (auth sequence, governance, facade integration, compose generation, visual readback structure, safety) | PASS — 20 tests |
| OFFLINE_TEST | shell `bash -n` (bootstrap facade, extension builder) | PASS |
| OFFLINE_TEST | Node `--check` adaptive JS | PASS |
| OFFLINE_TEST | Python `py_compile` management/bootstrap modules | PASS |
| OFFLINE_TEST | `ciam-magalu-bootstrap.sh plan` with missing v10 home | correctly BLOCKED, exit 2 |
| GA_BINARY_BUILD | `build-extension.sh` exact WSO2 JAR/API compilation | NOT RUN — no running GA image and no Docker |
| MANAGEMENT_READBACK | four apps and two governance connectors | NOT RUN — no operator v10 runtime/credentials |
| OSGI_ACTIVATION | `MAGALU_RISK_ACTIVE` from GA restart | NOT RUN |
| LIVE_WSO2 | actual DENY/TOTP, blocked/challenged token issuance, tenant isolation | NOT RUN |
| CONSOLE_VISUAL | visual inspection of both tenant login flows / native login attempts | NOT RUN |
| GIT_REMOTE_WRITE | commit/push into `joaokuntzwso2/identity-poc-repository` | NOT RUN — no GitHub repository connection |

The offline detector models rotating IPs with correlated session/device/agent
and timing signals; native controls and request-origin trust rules remain
unverified until a real operator-host test. No separate bot proof-of-work,
true timed admission DELAY, or IS Console embedded risk-score dashboard is
claimed. The bootstrap is a guarded candidate, not a completed release.
