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
    npm --prefix apps/experience-center run dev -- --host 127.0.0.1
    ;;
  serve)
    export EXPERIENCE_PREVIEW_ACK=YES_LOCAL_SYNTHETIC_ONLY
    exec node services/experience-api/server.mjs
    ;;
  build)
    npm --prefix apps/experience-center run build
    (cd apps/experience-center && npm exec -- vite build --config retail.vite.config.ts)
    ;;
  test)
    node --test services/experience-api/test/*.test.mjs
    npm test
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
Identity Experience v0.4
  ./experience.sh dev           local API + React Vite development server
  ./experience.sh build         Experience Center + two complete branded websites
  ./experience.sh serve         locally serve built UI and API
  ./experience.sh preview-test  SQLite/consent/assurance/retail/API contract tests
  ./experience.sh test          preview tests and existing repository npm test
  ./experience.sh check         preview tests and staged publication check

Preview is synthetic, loopback-only, NOT a real identity provider.
HELP
    ;;
esac
