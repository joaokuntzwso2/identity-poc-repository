#!/usr/bin/env bash
set -euo pipefail
origin="${WSO2_CIAM_BFF_ORIGIN:-http://127.0.0.1:4400}"
check() {
  local route="$1" expected="$2" actual
  actual="$(curl -sS -o /dev/null -w '%{http_code}' "${origin}${route}")"
  printf '%-63s expected=%s actual=%s\n' "$route" "$expected" "$actual"
  [ "$actual" = "$expected" ]
}
check '/portal/aurora' 200
check '/portal/brisa' 200
check '/identity-live-v2' 200
check '/api/identity/me' 200
check '/api/brands/aurora/profile?client=aurora-web' 401
check '/api/brands/brisa/profile?client=brisa-web' 401
check '/api/brands/brisa/profile?client=aurora-web' 403
check '/api/protected/profile?client=aurora-web' 401
check '/api/scenarios' 503
check '/api/experience/meta' 503
check '/aurora.html' 404
check '/b2b.html' 404
printf '\nPASS: anonymous and cross-brand access denied. Real browser tests still required.\n'
