#!/usr/bin/env bash
# Local WSO2 lab ONLY. Output: absolute path of a pinned public certificate.
# Does not change the server keystore, private journal, or remote resources.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd -- "$script_dir/../.." && pwd -P)"
certificate="$root/var/wso2/tls/wso2-local.pem"
container='wso2-identity-server-1'

# Only this fixed local WSO2 service is supported by TOFU.
case "${WSO2_BASE_URL:-https://localhost:9443}" in
  https://localhost:9443|https://127.0.0.1:9443) ;;
  *) echo 'TLS_BOOTSTRAP_REFUSED_UNEXPECTED_ORIGIN' >&2; exit 1 ;;
esac
for bin in docker openssl mktemp; do
  command -v "$bin" >/dev/null 2>&1 || { echo "TLS_BOOTSTRAP_MISSING_TOOL_$bin" >&2; exit 1; }
done
[[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" == true ]] || {
  echo 'TLS_BOOTSTRAP_EXPECTED_CONTAINER_NOT_RUNNING' >&2; exit 1;
}
port="$(docker port "$container" 9443/tcp 2>/dev/null)" || {
  echo 'TLS_BOOTSTRAP_EXPECTED_PORT_MAPPING_MISSING' >&2; exit 1;
}
[[ "$port" == '127.0.0.1:9443' ]] || {
  echo 'TLS_BOOTSTRAP_LOOPBACK_PORT_MAPPING_REQUIRED' >&2; exit 1;
}

# Read the server-presented *public* certificate; never read/export a private key.
# The first trust is tied to the explicitly acknowledged, loopback-only Docker lab.
mkdir -p -- "$(dirname "$certificate")"
umask 077
candidate="$(mktemp "${certificate}.candidate.XXXXXXXX")"
trap 'rm -f -- "$candidate"' EXIT
if ! openssl s_client -connect 127.0.0.1:9443 -servername localhost -showcerts \
    </dev/null 2>/dev/null | openssl x509 -outform PEM -out "$candidate" 2>/dev/null; then
  echo 'TLS_BOOTSTRAP_CANNOT_READ_SERVER_CERTIFICATE' >&2; exit 1
fi
if ! openssl x509 -in "$candidate" -checkend 0 -noout >/dev/null 2>&1; then
  echo 'TLS_BOOTSTRAP_CERTIFICATE_EXPIRED' >&2; exit 1
fi
# Self-signed *local* lab certificate must validate as a trust anchor for localhost.
if ! openssl verify -CAfile "$candidate" -verify_hostname localhost "$candidate" >/dev/null 2>&1; then
  echo 'TLS_BOOTSTRAP_LOCALHOST_CERTIFICATE_INVALID' >&2; exit 1
fi
if [[ -L "$certificate" ]]; then
  echo 'TLS_BOOTSTRAP_REFUSED_PIN_SYMLINK' >&2; exit 1
fi
if [[ -f "$certificate" ]]; then
  pinned="$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 2>/dev/null)" || {
    echo 'TLS_BOOTSTRAP_BAD_PINNED_CERTIFICATE' >&2; exit 1;
  }
  served="$(openssl x509 -in "$candidate" -noout -fingerprint -sha256 2>/dev/null)" || exit 1
  [[ "$pinned" == "$served" ]] || {
    echo 'TLS_BOOTSTRAP_CERTIFICATE_CHANGED_MANUAL_REVIEW' >&2; exit 1;
  }
else
  # A first-time trust pin must be operator-acknowledged; never silent on fresh machines.
  [[ "${WSO2_LAB_CONFIRM:-}" == CREATE_SYNTHETIC_RESOURCES ]] || {
    echo 'TLS_BOOTSTRAP_FIRST_PIN_REQUIRES_EXPLICIT_APPLY_ACK' >&2; exit 1;
  }
  # Refuse race/replacement. Newly pinned cert stays private in ignored var/.
  (set -o noclobber; cat "$candidate" > "$certificate") || {
    echo 'TLS_BOOTSTRAP_PIN_ALREADY_EXISTS' >&2; exit 1;
  }
  echo 'TLS_BOOTSTRAP_PUBLIC_CERTIFICATE_PINNED_LOCAL_ONLY' >&2
fi
printf '%s\n' "$certificate"
