#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"
if [ -f var/wso2/lab.env ];then
  set -a
  source var/wso2/lab.env
  set +a
fi
if [ -z "${NODE_EXTRA_CA_CERTS:-}" ]; then
  if [ ! -f "$ROOT/var/wso2/tls/wso2-local.pem" ];then
    printf '%s\n' 'PINNED_WSO2_CERTIFICATE_REQUIRED' >&2
    exit 2
  fi
  export NODE_EXTRA_CA_CERTS="$ROOT/var/wso2/tls/wso2-local.pem"
fi
if [ ! -f "$NODE_EXTRA_CA_CERTS" ];then
  printf '%s\n' 'PINNED_WSO2_CERTIFICATE_MISSING' >&2
  exit 2
fi
exec node scripts/wso2/ciam-bootstrap-v8.mjs "$@"
