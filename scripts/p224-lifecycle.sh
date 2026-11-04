#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CERT="$ROOT/var/wso2/tls/wso2-local.pem"
[[ -f "$CERT" && ! -L "$CERT" ]] || { echo 'P224L_CA_MISSING' >&2; exit 1; }
EXPECTED='2B:A3:61:A0:32:FF:D4:B3:4F:7D:F0:66:DE:72:B6:1C:5E:83:6A:09:F7:A7:BD:71:05:EB:87:B4:09:4D:97:12'
ACTUAL="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | sed 's/^.*=//')"
[[ "$ACTUAL" == "$EXPECTED" ]] || { echo 'P224L_TLS_CERT_PIN_MISMATCH' >&2; exit 1; }
[[ "${NODE_TLS_REJECT_UNAUTHORIZED:-1}" != '0' ]] || { echo 'P224L_TLS_BYPASS_DENIED' >&2; exit 1; }
MODE="${1:-check}"
[[ "$MODE" == 'check' || "$MODE" == 'serve' || "$MODE" == 'recover-group-check' || "$MODE" == 'recover-group' || "$MODE" == 'recover-membership-check' || "$MODE" == 'recover-membership' ]] || { echo 'P224L_MODE_DENIED' >&2; exit 2; }
export NODE_EXTRA_CA_CERTS="$CERT"
V10_HOME="${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}"
[[ "$V10_HOME" = /* && -d "$V10_HOME/private" ]] || { echo 'P224L_PRIVATE_HOME_UNAVAILABLE' >&2; exit 1; }
AUTH_FILE="$V10_HOME/private/p2-bootstrap-authority.private.json"
[[ -f "$AUTH_FILE" && ! -L "$AUTH_FILE" ]] || { echo 'P224L_AUTHORITY_HANDOFF_MISSING' >&2; exit 1; }
export CIAM_P2_BOOTSTRAP_AUTH_FILE="$AUTH_FILE"
exec node "$ROOT/scripts/p224-lifecycle-service.mjs" "$MODE"
