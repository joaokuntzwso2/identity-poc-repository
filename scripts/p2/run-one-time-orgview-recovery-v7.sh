#!/usr/bin/env bash
# Explicitly approved one-time continuation; NEVER rerun after a write attempt.
set -euo pipefail
repo="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo"
private="${P2_PRIVATE_DIR:-$HOME/wso2-ciam-v10/private}"
export P2_PRIVATE_DIR="$private"
export NODE_EXTRA_CA_CERTS="$private/p2-local-wso2-tls-pinned.pem"
python3 -m unittest discover -s tests/p2 -p 'test_m2m_*.py' -q
node --test tests/p2/m2m-root-guard.test.mjs
python3 scripts/p2/recover_orgview_v7.py plan
python3 scripts/p2/recover_orgview_v7.py apply \
  --approve=RECOVER_APPROVED_AURORA_ORGVIEW_SCOPE_ON_PINNED_APPLICATION
# After successful authorization, use the verified token and journal root UUID.
export P2_TOKEN_FILE="$private/p2-aurora-root-token.private.txt"
export P2_ORIGIN='https://localhost:9444'
export P2_ROOT_ORG_ID="$(python3 -c '
import json,os,pathlib,stat,re
p=pathlib.Path(os.environ["P2_PRIVATE_DIR"])/"p2-aurora-orgview-bootstrap.private.json"
s=p.lstat()
assert stat.S_ISREG(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600
j=json.loads(p.read_text())
assert j["tenant"]=="aurora.identity.test" and j["phase"]=="COMPLETE" and j["scope"]=="internal_org_organization_view"
v=j["rootId"]
assert isinstance(v,str) and re.fullmatch(r"[a-fA-F0-9-]{36}",v)
print(v)
')"
node scripts/p2/cli.mjs plan-partner
