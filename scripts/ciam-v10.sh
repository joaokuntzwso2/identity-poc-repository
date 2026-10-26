#!/usr/bin/env bash
set -euo pipefail
REPO="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"
