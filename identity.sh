#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
usage(){ cat <<'HELP'
Usage: ./identity.sh COMMAND
  test           Local unit/security tests and original npm test (no WSO2 required)
  audit          All 132 RFP items/19 eliminatories evidence status, never auto-PASS
  require-ready  Fail closed if an eliminatory lacks independent attested evidence
  phase1         Real OIDC Discovery & sector configuration preflight (read only)
  db-migrate     Apply PostgreSQL append-only consent extension schema (authorized DB only)
  exchange       Real RFC 8693 subject+actor exchange (authorized WSO2 only)
  dev-bff        Start existing Node BFF
  dev-ui         Start existing Vite frontend
  live-pairwise  Open browser and run existing Playwright four-client scenario
  check          npm run check + local tests + release report

For external runtime commands, first run:
  set -a; source .env; set +a
HELP
}
case "${1:-help}" in
  test) npm test ;;
  audit) node scripts/identity/release-gates.mjs ;;
  require-ready) node scripts/identity/release-gates.mjs --require-ready ;;
  phase1) node scripts/identity/phase1-preflight.mjs ;;
  db-migrate) node scripts/identity/db-migrate.mjs ;;
  exchange) node scripts/identity/token-exchange-live.mjs ;;
  dev-bff) npm run start:bff ;;
  dev-ui) npm run dev ;;
  live-pairwise) npm run test:pairwise-live ;;
  check) npm run check; node --test services/identity-bff/test/identity-*.test.js; node scripts/identity/release-gates.mjs ;;
  *) usage ;;
esac
