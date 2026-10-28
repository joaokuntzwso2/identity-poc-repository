#!/usr/bin/env python3
"""Guarded source-only installation of the CIAM v5 architecture/test documentation.

Usage: python3 scripts/install-ciam-v5-docs.py {check|apply|verify}
No WSO2 HTTP writes, BFF process changes, Git commits, or staging.
"""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

MARKER='<!-- CIAM_V5_CURRENT_ARCHITECTURE_START -->'
END='<!-- CIAM_V5_CURRENT_ARCHITECTURE_END -->'
ROOT=Path.cwd()
HERE=Path(__file__).resolve().parent.parent
CONTENT = {
 'docs/CIAM_V5_ARCHITECTURE_AND_OWNERSHIP.md': HERE/'docs/CIAM_V5_ARCHITECTURE_AND_OWNERSHIP.md',
 'docs/CIAM_V5_E2E_TESTING.md': HERE/'docs/CIAM_V5_E2E_TESTING.md',
 'scripts/ciam-identity-ops.py': HERE/'scripts/ciam-identity-ops.py',
 'scripts/ciam-carbon-super-readback.py': HERE/'scripts/ciam-carbon-super-readback.py',
}

class Refuse(Exception):pass

def verify_repo():
    for p in ('README.md','deploy/ciam-v10/identities/seed.json','deploy/ciam-v10/phase4/desired.json',
              'services/identity-bff/src/server.js','scripts/ciam-v5-four-client-readback.py'):
        f=ROOT/p
        if not f.is_file() or f.is_symlink():raise Refuse('REPOSITORY_BASELINE_FILE_MISSING_OR_UNSAFE_'+p)
    readme=(ROOT/'README.md').read_text()
    if readme.count(MARKER)>1 or readme.count(END)>1 or (MARKER in readme)!=(END in readme):
        raise Refuse('README_MARKER_AMBIGUOUS')
    return readme

def guard_target(path,content):
    if path.is_symlink():raise Refuse('SYMLINK_REFUSED_'+str(path))
    if path.exists() and path.read_bytes()!=content:
        raise Refuse('EXISTING_FILE_DIFFERS_'+str(path))

def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('check','apply','verify'):
        raise Refuse('USAGE_CHECK_APPLY_VERIFY')
    mode=sys.argv[1]
    readme=verify_repo()
    intro=(HERE/'README-CIAM-UPDATE.md').read_text()
    if intro.count(MARKER)!=1 or intro.count(END)!=1:raise Refuse('BANNER_INVALID')
    for rel,src in CONTENT.items():
        if not src.is_file() or src.is_symlink():raise Refuse('BUNDLED_SOURCE_MISSING_'+rel)
        guard_target(ROOT/rel,src.read_bytes())
    if MARKER in readme:
        head=readme.split(END,1)[0]+END
        if head!=intro.rstrip():raise Refuse('README_BANNER_DIFFERS_REFUSE_OVERWRITE')
        updated=readme
    else:
        updated=intro.rstrip()+'\n\n'+readme
    if mode=='check':
        print('CHECK_OK: README section, architecture guide, E2E guide, CLI and Carbon audit ready')
        print('REMOTE_WRITES: 0; GIT_WRITES: 0')
        return
    if mode=='apply':
        private_dir=Path(os.environ.get('CIAM_V10_HOME',str(Path.home()/'wso2-ciam-v10')))/'private'
        if private_dir.is_symlink() or not private_dir.is_dir() or (private_dir.stat().st_mode & 0o022):
            raise Refuse('PRIVATE_BACKUP_DIRECTORY_UNSAFE')
        # Pre-generate the inventory from current local source+journals BEFORE
        # making any repo change; catches mismatched ids, roles and source.
        with tempfile.TemporaryDirectory(prefix='ciam-doc-preflight-') as temp:
            inventory=Path(temp)/'inventory.md'
            subprocess.run([sys.executable,str(CONTENT['scripts/ciam-identity-ops.py']),
                            'inventory','--output',str(inventory)],cwd=ROOT,check=True)
            generated=inventory.read_bytes()
            invtarget=ROOT/'docs/CIAM_V5_TENANT_INVENTORY.md'
            if invtarget.is_symlink():raise Refuse('INVENTORY_OUTPUT_SYMLINK_REFUSED')
            # Create private backups for README and pre-existing inventory only.
            backup=private_dir/'README.pre-ciam-v5-docs.private.md'
            if backup.exists() or backup.is_symlink():raise Refuse('BACKUP_EXISTS_NO_OVERWRITE')
            backup.write_text(readme)
            os.chmod(backup,0o600)
            for rel,src in CONTENT.items():
                dest=ROOT/rel
                dest.parent.mkdir(parents=True,exist_ok=True)
                if not dest.exists():
                    dest.write_bytes(src.read_bytes())
            if invtarget.exists():
                invbackup=private_dir/'CIAM_V5_TENANT_INVENTORY.pre-ciam-v5-docs.private.md'
                if invbackup.exists():raise Refuse('INVENTORY_BACKUP_EXISTS_NO_OVERWRITE')
                invbackup.write_bytes(invtarget.read_bytes())
                os.chmod(invbackup,0o600)
            invtarget.write_bytes(generated)
            (ROOT/'README.md').write_text(updated)
            print('APPLIED: root README, full architecture, E2E guide, generated user/role inventory, password CLI, Carbon audit')
            print('README_BACKUP:',backup)
            print('REMOTE_WRITES: 0; GIT_WRITES: 0; SECRETS_EXPORTED: 0')
    if mode=='verify':
        if MARKER not in readme or intro.rstrip()!=readme.split(END,1)[0]+END:
            raise Refuse('README_NOT_INSTALLED')
        if not (ROOT/'docs/CIAM_V5_TENANT_INVENTORY.md').is_file():raise Refuse('INVENTORY_NOT_INSTALLED')
        for rel,src in CONTENT.items():
            if hashlib.sha256((ROOT/rel).read_bytes()).digest()!=hashlib.sha256(src.read_bytes()).digest():
                raise Refuse('INSTALLED_FILE_DRIFT_'+rel)
        subprocess.run([sys.executable,'-m','py_compile',str(ROOT/'scripts/ciam-identity-ops.py'),
                        str(ROOT/'scripts/ciam-carbon-super-readback.py')],check=True)
        print('VERIFIED: architecture/readme, inventory, end-to-end guide, scripts')
        print('REMOTE_WRITES: 0; GIT_WRITES: 0')

if __name__=='__main__':
    try:main()
    except (Refuse, subprocess.CalledProcessError, OSError, ValueError) as e:
        print('REFUSED:',str(e) if isinstance(e,Refuse) else type(e).__name__,file=sys.stderr)
        sys.exit(2)
