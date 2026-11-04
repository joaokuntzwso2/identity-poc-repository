#!/usr/bin/env bash
set -euo pipefail
repo="$PWD"
[ -f "$repo/scripts/ciam-v10.sh" ] || { printf 'BLOCKED: RUN_FROM_PROJECT_ROOT\n' >&2; exit 2; }
node --test tests/p2/guarded-org.test.mjs tests/p2/org-inventory-v9.test.mjs
python3 scripts/p2/run-org-inventory-v9.py
