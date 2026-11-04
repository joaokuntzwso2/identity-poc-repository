#!/usr/bin/env bash
# P2.24: auto-reconcile dedicated authority from the existing v10 private owner.
# Refuse if trusted WSO2 TLS or authority prerequisites are missing.
set -euo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CERT="$REPO/var/wso2/tls/wso2-local.pem"
[[ -f "$CERT" && ! -L "$CERT" ]] || { echo 'BOOTSTRAP_TLS_CERT_BLOCKED' >&2; exit 1; }
EXPECTED='2B:A3:61:A0:32:FF:D4:B3:4F:7D:F0:66:DE:72:B6:1C:5E:83:6A:09:F7:A7:BD:71:05:EB:87:B4:09:4D:97:12'
ACTUAL="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | sed 's/^.*=//')"
[[ "$ACTUAL" == "$EXPECTED" ]] || { echo 'BOOTSTRAP_TLS_FINGERPRINT_CHANGED_BLOCKED' >&2; exit 1; }
[[ "${NODE_TLS_REJECT_UNAUTHORIZED:-1}" != '0' ]] || { echo 'BOOTSTRAP_TLS_BYPASS_BLOCKED' >&2; exit 1; }
export NODE_EXTRA_CA_CERTS="$CERT"
MODE="${1:-check}"
[[ "$MODE" == 'check' || "$MODE" == 'apply' ]] || { echo 'BOOTSTRAP_MODE_UNSUPPORTED' >&2; exit 2; }
V10_HOME="${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}"
[[ "$V10_HOME" = /* && -d "$V10_HOME/private" ]] || { echo 'BOOTSTRAP_V10_PRIVATE_HOME_UNAVAILABLE' >&2; exit 1; }
export CIAM_P2_BOOTSTRAP_AUTH_FILE="$V10_HOME/private/p2-bootstrap-authority.private.json"
# Only uses the preexisting tenant-owner privilege recorded by the v10 bootstrap.
# No Browser token, interactive Console step, or insecure fallback.
if [[ "$MODE" == 'check' ]]; then
  AUTH_REPORT="$(python3 "$REPO/scripts/p2-bootstrap-authority.py" check)"
  printf '%s\n' "$AUTH_REPORT"
  if printf '%s\n' "$AUTH_REPORT" | python3 -c 'import json,sys; x=json.load(sys.stdin); sys.exit(0 if x.get("stage")=="P2_AUTHORITY" and x.get("state")=="READY" and x.get("remoteWrites")==0 else 1)'; then
    node "$REPO/scripts/p2-bootstrap-auto.mjs" check
    node "$REPO/scripts/p224-delegate-auto.mjs" check
    exec node "$REPO/scripts/p224-user-token-auto.mjs" check
  fi
  exit 0
fi
python3 "$REPO/scripts/p2-bootstrap-authority.py" apply
node "$REPO/scripts/p2-bootstrap-auto.mjs" apply
node "$REPO/scripts/p224-delegate-auto.mjs" apply
exec node "$REPO/scripts/p224-user-token-auto.mjs" apply
