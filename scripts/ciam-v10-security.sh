#!/usr/bin/env bash
set -euo pipefail
# Safe additive CIAM-v10 security operator facade. This never invokes P2 partner
# setup, fresh, fresh-bootstrap, wso2-lab.sh, BFF mutations, or Console writes.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cmd="${1:-}"
case "$cmd" in
  security-inventory) action=inventory ;;
  security-auth-check) action=auth-check ;;
  security-plan) action=plan ;;
  security-bootstrap|security-apply) action=apply ;;
  security-verify) action=verify ;;
  security-rollback) action=rollback ;;
  *) echo 'Usage: ciam-v10.sh security-{inventory,plan,bootstrap,verify,rollback}' >&2; exit 2 ;;
esac
shift
exec python3 "$root/deploy/ciam-v10/security/bootstrap.py" "$action" "$@"
