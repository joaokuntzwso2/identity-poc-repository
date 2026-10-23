#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
case "${1:-help}" in
 status) node scripts/provider/status.mjs ;;
 test|contract) IDENTITY_MODE=offline-contract node scripts/provider/contract.mjs ;;
 verify) node scripts/provider/verify.mjs ;;
 build) ./experience.sh build ;;
 dev) ./experience.sh dev ;;
 check)
    node scripts/provider/contract.mjs
    node scripts/provider/status.mjs >/dev/null
    if [[ -f scripts/security/check_public.py ]]; then python3 scripts/security/check_public.py --staged; fi
    ;;
 *) cat <<'HELP'
Provider boundary v0.7 (no WSO2 instance required for local use)
  ./provider.sh status    mode and four-client readiness (no secrets)
  ./provider.sh test      offline contract test suite (NO live verification)
  ./provider.sh check     unit tests, status and optional privacy staging scan
  ./provider.sh build     build all Experience Center apps and provider-readiness page
  ./provider.sh dev       start local synthetic UI + extension API
  ./provider.sh verify    read-only WSO2 discovery validation (requires explicit opt-in configuration)
HELP
 ;;
esac
