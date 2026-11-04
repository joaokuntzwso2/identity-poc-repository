#!/usr/bin/env bash
set -euo pipefail
REPO="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# P2.24 V13: one-time approved Aurora partner initialization.
# Does not run for inspection, preflight, tests or the base v10 bootstrap.
if [[ "${1:-}" == "bff-start" ]]; then
  ( cd "$REPO" && python3 scripts/p2/partner_v13.py ensure )
fi
# P2.24 V14: read-only Aurora partner application-sharing evidence.
# No WSO2 management writes; absence is reported honestly, never authorized.
if [[ "${1:-}" == "bff-start" ]]; then
  ( cd "$REPO" && python3 scripts/p2/partner_access_v14.py status )
fi
# P2.24 V15: read-only GA shared-apps cross-check (no privileges granted).
if [[ "${1:-}" == "bff-start" ]]; then
  ( cd "$REPO" && python3 scripts/p2/partner_business_plan_v15.py status )
fi
# P2.24 V16: approved once-only Aurora portal OIDC registration; later GET readback.
if [[ "${1:-}" == "bff-start" ]]; then
  ( cd "$REPO" && python3 scripts/p2/partner_portal_v16_3.py bootstrap )
fi
# P2.24 V17: one-time approved partner-only share; GET-only on later starts.
if [[ "${1:-}" == "bff-start" ]]; then
  ( cd "$REPO" && python3 scripts/p2/partner_share_v17_2.py bootstrap )
fi

# P2.24 V18: non-admin partner users/groups; blocked until verified V17 sharing and actor.
if [[ "${1:-}" == "bff-start" ]]; then
  ( cd "$REPO" && python3 scripts/p2/partner_directory_v18.py bootstrap )
fi
exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"
