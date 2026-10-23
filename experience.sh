#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
cmd="${1:-help}"
case "$cmd" in
  dev)
    if [[ ! -d node_modules && ! -d apps/experience-center/node_modules ]];then echo 'Missing dependencies: run npm ci first.' >&2;exit 1;fi
    export EXPERIENCE_PREVIEW_ACK=YES_LOCAL_SYNTHETIC_ONLY
    node services/experience-api/server.mjs & api_pid=$!
    trap 'kill "$api_pid" 2>/dev/null || true' EXIT INT TERM
    (cd apps/experience-center && npm exec -- vite --config identity.dev.vite.config.ts --host 127.0.0.1 --port 5173 --strictPort)
    ;;
  serve)
    export EXPERIENCE_PREVIEW_ACK=YES_LOCAL_SYNTHETIC_ONLY
    exec node services/experience-api/server.mjs
    ;;
  build)
    npm --prefix apps/experience-center run build
    (cd apps/experience-center && npm exec -- vite build --config retail.vite.config.ts)
    (cd apps/experience-center && npm exec -- vite build --config mobile.vite.config.ts)
    (cd apps/experience-center && npm exec -- vite build --config operations.vite.config.ts)
    (cd apps/experience-center && npm exec -- vite build --config provider.vite.config.ts)
    (cd apps/experience-center && npm exec -- vite build --config wso2.vite.config.ts)
    ;;
  test)
    node --test services/experience-api/test/*.test.mjs
    npm test
    ;;
  operations-test)
    node --test services/experience-api/test/*.test.mjs scripts/operations/*.test.mjs
    ;;
  mobile-test)
    node --test services/experience-api/test/*.test.mjs scripts/mobile/*.test.mjs
    ;;
  preview-test)
    node --test services/experience-api/test/*.test.mjs
    ;;
  check)
    node --test services/experience-api/test/*.test.mjs
    if [[ -f scripts/security/check_public.py ]]; then python3 scripts/security/check_public.py --staged; fi
    ;;
  help|*)
    cat <<'HELP'
Identity Experience v0.6.2
  ./experience.sh dev           local API + React Vite development server
  ./experience.sh build         Experience Center + two branded websites + two mobile application previews
  ./experience.sh serve         locally serve built UI and API
  ./experience.sh operations-test  B2B/onboarding/authorization/evidence tests
  ./experience.sh mobile-test  retail and mobile domain/contract tests
  ./experience.sh preview-test  SQLite/consent/assurance/retail/API contract tests
  ./experience.sh test          preview tests and existing repository npm test
  ./experience.sh check         preview tests and staged publication check

Preview is synthetic, loopback-only, NOT a real identity provider.
  ./provider.sh status/test/verify  WSO2 adapter readiness and contract checks.
HELP
    ;;
esac
