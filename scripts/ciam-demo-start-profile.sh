#!/usr/bin/env bash
# Verified CIAM profile startup. Never stops processes, migrates or writes WSO2.
# Run only after the already-running BFF has been stopped by an operator.
set -euo pipefail
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(CDPATH= cd -- "$HERE/.." && pwd)"
cd "$ROOT"
if [ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]; then
  echo 'PROFILE_START_STOP: checkout is not clean; commit/review first.' >&2
  exit 2
fi
if curl -fsS --connect-timeout 2 --max-time 5 -o /dev/null http://127.0.0.1:4400/api/health 2>/dev/null; then
  echo 'PROFILE_START_STOP: BFF already running. Do not assume its old environment changed.' >&2
  echo 'Stop only the verified BFF PID before using this startup helper.' >&2
  exit 2
fi
pin="$(node "$HERE/ciam-authority-check.mjs")" || exit 2
case "$pin" in v2|v3) ;; *) echo 'PROFILE_START_STOP: invalid authority pin.' >&2; exit 2;; esac
launcher="${CIAM_EXISTING_START_SCRIPT:-$HOME/Downloads/start-ciam-existing.sh}"
if [ ! -f "$launcher" ]; then
  echo 'PROFILE_START_STOP: existing non-destructive launcher not found.' >&2
  exit 2
fi
export WSO2_CIAM_V10_ROLE_API="$pin"
export WSO2_BUSINESS_API_AUDIENCE='https://api.ciam-v10.test/profile'
export WSO2_AUTHORITY_OIDC_SCOPE='ciam:profile:read'
export CIAM_BFF_NPM_SCRIPT=start:bff
printf 'PROFILE_START: journal-pinned %s authority readback verified; profile audience and scope request enabled.\n' "$pin"
printf 'PROFILE_START: launching existing BFF workflow; WSO2 scopes still enforced on live tokens.\n'
exec bash "$launcher"
