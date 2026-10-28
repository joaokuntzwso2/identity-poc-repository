#!/usr/bin/env bash
set -euo pipefail
REPO="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO"
exec python3 "$REPO/scripts/ciam-v10-inspect.py" "$@"
