#!/usr/bin/env bash
# Source-only companion to existing bootstrap. Does NOT restart/recreate WSO2 containers.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"
CMD="${1:-status}"
RUNDIR="$ROOT/var/wso2/runtime"
mkdir -p "$RUNDIR"; chmod 700 "$RUNDIR"
if [[ -f var/wso2/lab.env ]]; then set -a; source var/wso2/lab.env; set +a; fi
export IDENTITY_MODE=live-wso2 WSO2_INTEGRATION_ACK=yes
export PUBLIC_ORIGIN=http://127.0.0.1:4000 ALLOW_INSECURE_LOCAL=true PORT=4000 BIND_HOST=127.0.0.1 NODE_ENV=development
export WSO2_BFF_PRIVATE_MANIFEST="$ROOT/var/wso2/identity-bff-wso2.private.json"
if [[ -z "${NODE_EXTRA_CA_CERTS:-}" && -f scripts/wso2/bootstrap-local-tls.sh ]];then
  NODE_EXTRA_CA_CERTS="$(bash scripts/wso2/bootstrap-local-tls.sh)"; export NODE_EXTRA_CA_CERTS
fi
preflight(){ node scripts/wso2/bff-runtime-preflight.mjs; }
check_pid(){
  local label="$1" expected="$2" file="$RUNDIR/$label.pid" pid=""
  [[ -f "$file" ]] || return 1
  read -r pid < "$file"
  [[ "$pid" =~ ^[0-9]+$ ]] || { echo "INVALID_PIDFILE_$label" >&2; exit 2; }
  if kill -0 "$pid" 2>/dev/null;then
    if ! ps -p "$pid" -o command= | grep -Fq "$expected";then echo "PID_CONFLICT_$label" >&2; exit 2;fi
    return 0
  fi
  echo "STALE_PIDFILE_$label requires manual inspection: $file" >&2; exit 2
}
start_process(){
  local label="$1" expected="$2"; shift 2
  if check_pid "$label" "$expected";then echo "ALREADY_RUNNING_$label";return;fi
  # Write only locally in private runtime dir; never log credentials.
  (umask 077; nohup "$@" >"$RUNDIR/$label.log" 2>&1 & echo $! >"$RUNDIR/$label.pid")
  sleep 1
  if ! check_pid "$label" "$expected"; then
    echo "SERVICE_FAILED_$label: inspect $RUNDIR/$label.log" >&2; exit 2
  fi
  echo "STARTED_$label"
}
case "$CMD" in
  preflight) preflight;;
  status)
    for label in bff preview; do if [[ -f "$RUNDIR/$label.pid" ]];then echo "$label PIDFILE_PRESENT";else echo "$label NOT_STARTED_BY_LAB";fi;done
    ;;
  start)
    preflight # Strict validation before ANY service startup or local source modification
    if [[ ! -f apps/experience-center/dist/index.html ]];then
      if [[ ! -d node_modules ]];then npm ci;fi
      ./experience.sh build
    fi
    [[ -f apps/experience-center/dist/index.html ]] || { echo 'UI_NOT_BUILT' >&2;exit 2; }
    # Local-only preview: separate process, never an issuer or access-control service.
    start_process preview 'services/experience-api/server.mjs' env IDENTITY_MODE=story-preview EXPERIENCE_PREVIEW_ACK=YES_LOCAL_SYNTHETIC_ONLY node services/experience-api/server.mjs
    start_process bff 'services/identity-bff/src/server.js' node services/identity-bff/src/server.js
    echo 'LAB_BFF_RUNTIME_START_REQUESTED http://127.0.0.1:4000 (signed browser login NOT_VERIFIED)'
    ;;
  stop)
    # Stops only processes started and positively identified by this script. Never WSO2.
    for label in bff preview; do
      if [[ "$label" == bff ]];then expected='services/identity-bff/src/server.js';else expected='services/experience-api/server.mjs';fi
      if check_pid "$label" "$expected"; then
        read -r pid <"$RUNDIR/$label.pid"; kill "$pid"; rm -- "$RUNDIR/$label.pid"; echo "STOPPED_$label"
      fi
    done
    ;;
  *) echo 'Usage: runtime-identity.sh preflight|start|status|stop' >&2;exit 2;;
esac
