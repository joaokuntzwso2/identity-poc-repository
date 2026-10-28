#!/usr/bin/env bash
# Anonymous-only negative checks for the v10 strict identity surface.
set -euo pipefail
BASE="${CIAM_BFF_ORIGIN:-http://127.0.0.1:4400}"
case "$BASE" in http://127.0.0.1:4400|http://localhost:4400) ;; *) echo 'Refusing nonlocal BFF URL' >&2; exit 2;; esac
check() {
  local expected="$1" path="$2" actual
  actual=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "$BASE$path")
  printf '%-38s expected=%s actual=%s\n' "$path" "$expected" "$actual"
  test "$actual" = "$expected" || { echo 'FAIL: live BFF may serve mock route' >&2;exit 1; }
}
check 200 /api/identity/me
check 401 '/api/protected/profile?client=aurora-web'
check 503 /api/scenarios
check 503 /api/experience/meta
check 404 /b2b.html
check 404 /aurora.html
printf 'PASS: anonymous synthetic routes denied; this does NOT prove positive authentication.\n'
