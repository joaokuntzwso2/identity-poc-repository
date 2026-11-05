#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command="${1:-}"
case "$command" in
  inventory|plan|verify|auth-check)
    shift
    exec "$root/scripts/ciam-v10-security.sh" "security-$command" "$@"
    ;;
  grants-plan)
    exec python3 "$root/scripts/magalu-scope-reconcile.py" plan
    ;;
  grants-apply)
    shift
    exec python3 "$root/scripts/magalu-scope-reconcile.py" apply "$@"
    ;;
  grants-verify)
    exec python3 "$root/scripts/magalu-scope-reconcile.py" verify
    ;;
  upgrade-host)
    shift
    exec python3 "$root/deploy/ciam-v10/security/bootstrap.py" upgrade-host "$@"
    ;;
  upgrade-graal)
    shift
    exec python3 "$root/deploy/ciam-v10/security/bootstrap.py" upgrade-graal "$@"
    ;;
  bootstrap|apply|rollback)
    shift
    # The bootstrap includes safe existing-facade integration. No manual
    # edits to the operator facade/JAR, and no Console configuration.
    python3 "$root/scripts/magalu-install-dispatch.py"
    exec "$root/scripts/ciam-v10.sh" "security-$command" "$@"
    ;;
  *) echo 'Usage: ciam-magalu-bootstrap.sh {inventory|plan|bootstrap|upgrade-graal|upgrade-host|verify|rollback} [--approve HASH]' >&2; exit 2 ;;
esac
