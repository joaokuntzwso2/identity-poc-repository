#!/usr/bin/env python3
"""Single-run, fully automatic local sector plus WSO2 OIDC-client stage.

Does not replace the carbon.super, federation, or BFF integration bootstrap.
"""
import os
from pathlib import Path
import subprocess
import sys

if len(sys.argv)!=2 or sys.argv[1] not in ('check','run'):
    raise SystemExit('EXPECTED_check_or_run')
if Path.cwd().resolve() != Path('scripts/wso2').resolve().parent.parent:
    raise SystemExit('RUN_FROM_REPOSITORY_ROOT')
env=os.environ.copy()
if sys.argv[1]=='run' and env.get('WSO2_LAB_CONFIRM')!='CREATE_SYNTHETIC_RESOURCES':
    raise SystemExit('EXPLICIT_LAB_WRITE_CONSENT_REQUIRED')
for key,val in {
    'DEMO_AURORA_SECTOR_BASE_URL':'https://aurora-sector.identity.test',
    'DEMO_BRISA_SECTOR_BASE_URL':'https://brisa-sector.identity.test',
    'WSO2_LAB_SECTOR_BRIDGE':'docker-sidecar-v1',
    'WSO2_LAB_LOCAL_HTTP_CALLBACKS':'allow-loopback-v1'
}.items():
    if key in env and env[key]!=val:raise SystemExit('EXISTING_SECTOR_ENV_CONFLICT_'+key)
    env[key]=val
if sys.argv[1]=='check':
    raise SystemExit(subprocess.run(['python3','scripts/wso2/sector-sidecar-bootstrap.py','check'],env=env).returncode)
res=subprocess.run(['python3','scripts/wso2/sector-sidecar-bootstrap.py','ensure'],env=env)
if res.returncode:
    marker=Path('var/wso2/sector-host/trust-change-pending.json')
    if marker.is_file():
        print('SECTOR_TRUST_CHANGE_INCOMPLETE: attempting automatic rollback of WSO2 truststore',file=sys.stderr)
        recovered=subprocess.run(['python3','scripts/wso2/sector-sidecar-bootstrap.py','recover'],env=env)
        if recovered.returncode:
            print('SECTOR_TRUST_RECOVERY_REQUIRED: do not rerun provisioning',file=sys.stderr)
    raise SystemExit(res.returncode)
# Both management M2M workloads are already verified; this path uses Bearer
# and will never reopen Basic with matching management journals.
res=subprocess.run(['python3','scripts/wso2/temporary-basic-bootstrap.py','run'],env=env)
raise SystemExit(res.returncode)
