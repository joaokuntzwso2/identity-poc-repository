#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"
# Approved in the user conversation: exactly one Aurora-only creator M2M
# registration and exactly its org-create API authorization. No partner POST.
python3 -m unittest discover -s tests/p2 -p 'test_creator_m2m_v12.py' -q
python3 scripts/p2/creator_m2m_v12.py plan
python3 scripts/p2/creator_m2m_v12.py apply \
  --approve=APPROVE_AURORA_CREATOR_M2M_CREATE_ONLY_V12
