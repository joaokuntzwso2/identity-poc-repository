#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo '=== POC v0.2: unit, HTTP and signed test-fixture integration tests ==='
npm test
echo '=== Static scenario and security checks ==='
node scripts/preflight.mjs
node scripts/secure-config-check.mjs
echo '=== Evidence inventory (NOT_VERIFIED, no fabricated pass results) ==='
node scripts/evidence-report.mjs
echo '=== Optional React compilation ==='
if [[ -x node_modules/.bin/vite && -x node_modules/.bin/tsc ]]; then
  npm run build
else
  echo 'SKIP React build: run npm install in a network-connected environment first.'
fi
echo '=== Live WSO2 acceptance ==='
echo 'NOT_EXECUTED. WSO2 7.3, four registered clients, and same-person browser logins are required.'
echo 'No claims about runtime WSO2 acceptance or AWS deployment are made.'
