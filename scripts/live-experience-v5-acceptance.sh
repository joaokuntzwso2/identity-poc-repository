#!/usr/bin/env bash
# Read-only anonymous verification; DOES NOT prove four positive WSO2 logins.
set -euo pipefail
ORIGIN="${CIAM_BFF_ORIGIN:-http://127.0.0.1:4400}"
case "$ORIGIN" in http://127.0.0.1:*|http://localhost:*) ;; *) echo 'REFUSED: expected loopback origin' >&2; exit 2;; esac
check() {
  local path="$1" expected="$2" actual
  actual=$(curl --silent --show-error --max-time 10 -o /dev/null -w '%{http_code}' "$ORIGIN$path")
  printf '%-50s expected=%s actual=%s\n' "$path" "$expected" "$actual"
  [[ "$actual" == "$expected" ]] || exit 1
}
check '/' 200
check '/lab' 200
check '/experience' 200
check '/portal/aurora/web' 200
check '/portal/aurora/mobile' 200
check '/portal/brisa/web' 200
check '/portal/brisa/mobile' 200
check '/portal/aurora' 200
check '/portal/brisa' 200
check '/live-experience-v5.js' 200
check '/live-experience-v5.css' 200
check '/live-retail-v5.css' 200
check '/api/identity/me' 200
check '/api/protected/profile?client=aurora-web' 401
check '/api/brands/aurora/cases?client=aurora-web' 401
check '/api/experience/meta' 503
printf 'PASS: v5 live routes, anonymous denials, old portal compatibility.\n'
printf 'NOT VERIFIED: four positive OAuth flows, token audience, userinfo, cases and MFA.\n'
