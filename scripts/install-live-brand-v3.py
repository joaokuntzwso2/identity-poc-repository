#!/usr/bin/env python3
"""Version-guarded zero-mock source upgrade. No outbound network or WSO2 API calls."""
from pathlib import Path
from datetime import datetime, timezone
import argparse, hashlib, json, os, shutil, sys, tempfile

parser=argparse.ArgumentParser()
group=parser.add_mutually_exclusive_group(required=True)
group.add_argument('--check',action='store_true')
group.add_argument('--apply',action='store_true')
args=parser.parse_args()
root=Path.cwd()
assert (root/'scripts/ciam-v10.sh').is_file(), 'REFUSED: not repository root'
assert (root/'services/identity-bff/src/server.js').is_file(), 'REFUSED: BFF missing'
asset=Path(__file__).resolve().parents[1] # same directory as copied scripts
# Payload files in the project tree are staged by the copy installer first.
rel=[
 'services/identity-bff/src/server.js',
 'apps/experience-center/src/main.tsx',
 'scripts/zero-mock-gate.py',
]
# In an extracted package, the replacement content is under scripts/zero-mock-v3-payload/
payload=root/'scripts/zero-mock-v3-payload'
for path in rel:
 if not (payload/path).is_file(): raise SystemExit(f'REFUSED: missing payload {path}')
expected={
 'services/identity-bff/src/server.js': {'eba2cccbaf254e07f0df3b67b10774a089d85d6b890f127494211bb71be32422'},
 'apps/experience-center/src/main.tsx': {'e76c62b33e53d028029d91e5de547780700585019d6f1519e43cde68998a047d'},
}
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
changes=[]
for relname in rel:
 src=payload/relname;dst=root/relname
 if not dst.exists(): raise SystemExit(f'REFUSED: target missing {relname}')
 if digest(dst)==digest(src): continue
 if relname in expected and digest(dst) not in expected[relname]:
  raise SystemExit(f'REFUSED: locally modified source differs from supplied upload: {relname}')
 changes.append(relname)
fixture=root/'apps/experience-center/src/data/personas.json'
if args.check:
 print(json.dumps({'stage':'LIVE_V3_PRECHECK','filesToReplace':changes,
    'fixtureToRetire':fixture.is_file(), 'noRemoteWrites':True},indent=2))
 sys.exit(0)
backup=Path.home()/'wso2-ciam-v10/private/zero-mock-source-backups-v3'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
backup.mkdir(parents=True,exist_ok=False)
for relname in changes:
 src=root/relname; b=backup/relname;b.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,b)
if fixture.is_file():
 b=backup/'apps/experience-center/src/data/personas.json';b.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(fixture,b)
# Replace only after every preflight check and backup succeeds.
for relname in changes:
 src=payload/relname;dst=root/relname
 tmp=dst.with_name('.'+dst.name+'.zero-mock-v3.tmp')
 tmp.write_bytes(src.read_bytes());os.replace(tmp,dst)
if fixture.is_file(): fixture.unlink()
print(json.dumps({'stage':'ZERO_MOCK_SOURCE_INSTALLED','filesReplaced':changes,
  'personaFixtureRemoved':not fixture.exists(),'backupDirectory':str(backup),
  'remoteWrites':0,'wso2ProvisioningUnchanged':True},indent=2))
