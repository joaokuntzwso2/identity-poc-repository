#!/usr/bin/env bash
# Approved P2.24 increment: no prompts, no arbitrary credentials, no partner writes.
set -euo pipefail
repo="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo"
python3 -m unittest discover -s tests/p2 -p 'test_m2m_*.py' -q
node --test tests/p2/m2m-root-guard.test.mjs
python3 scripts/p2/m2m_bootstrap.py plan
python3 scripts/p2/m2m_bootstrap.py apply --approve=CREATE_AURORA_ORG_VIEW_M2M
export P2_PRIVATE_DIR="${P2_PRIVATE_DIR:-$HOME/wso2-ciam-v10/private}"
export P2_TOKEN_FILE="$P2_PRIVATE_DIR/p2-aurora-root-token.private.txt"
export P2_ROOT_ORG_ID="$(python3 -c 'import json,os,pathlib,stat,sys; p=pathlib.Path(os.environ["P2_PRIVATE_DIR"])/"p2-aurora-orgview-bootstrap.private.json";s=p.lstat();assert stat.S_ISREG(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600;v=json.loads(p.read_text());assert v["phase"]=="COMPLETE" and v["tenant"]=="aurora.identity.test";print(v["rootId"])')"
node scripts/p2/cli.mjs plan-partner
