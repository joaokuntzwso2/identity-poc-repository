#!/usr/bin/env python3
"""Guarded source-only installer: v10 BFF runtime drift remediation.

Does not run Docker, signal processes, or access any private file. Uses exact
source anchors from main bbf31b4; refuses source drift before writing.
"""
from pathlib import Path
import os
import subprocess
import sys

ROOT=Path.cwd().resolve()
TARGETS=(
    'deploy/ciam-v10/cli.py',
    'deploy/ciam-v10/authority/acceptance.py',
)

# Each anchor is unique in the reviewed bbf31b4 source.
PATCHES={
    'deploy/ciam-v10/cli.py': [
        ("'consent-verify','consent-plan','consent-apply','authority-status','runtime-acceptance'],",
         "'consent-verify','consent-plan','consent-apply','authority-status','runtime-acceptance','bff-runtime-plan','bff-restart'],"),
        ("    elif command=='bff-diagnose':bff_diagnose()",
         "    elif command in ('bff-runtime-plan','bff-restart'):\n"
         "        root_guard()\n"
         "        run([sys.executable,HERE/'bff/restart.py',command])\n"
         "    elif command=='bff-diagnose':bff_diagnose()"),
        ("for d in ('server','tenants','resources','oidc','authority'):",
         "for d in ('server','tenants','resources','oidc','authority','bff'):"),
        ("consent-apply authority-status runtime-acceptance')",
         "consent-apply authority-status runtime-acceptance bff-runtime-plan bff-restart')"),
    ],
    'deploy/ciam-v10/authority/acceptance.py': [
        ("ok=code==200 and body.get('authenticated') is False",
         "ok=(code==200 and body.get('authenticated') is False\n"
         "                    and body.get('evidence')=='LIVE_INTROSPECTION_PER_REQUEST')\n"
         "                output['runtimeEvidence']=body.get('evidence') if body.get('evidence') in (\n"
         "                    'LIVE_INTROSPECTION_PER_REQUEST','BROWSER_CALLBACK_REQUIRED',\n"
         "                    'BFF_VALIDATED_SIGNED_ID_TOKEN') else 'UNRECOGNIZED'"),
    ],
}

def check_git():
    if subprocess.run(['git','rev-parse','--show-toplevel'],capture_output=True,text=True).stdout.strip()!=str(ROOT):
        raise SystemExit('STOP: run at repository root')
    if subprocess.run(['git','branch','--show-current'],capture_output=True,text=True).stdout.strip()!='main':
        raise SystemExit('STOP: expected main branch')
    for target in TARGETS:
        for args in (['git','diff','--quiet','--',target],['git','diff','--cached','--quiet','--',target]):
            if subprocess.run(args).returncode:
                raise SystemExit('STOP: target source has uncommitted changes: '+target)
    for required in ('deploy/ciam-v10/bff/restart.py',
                     'deploy/ciam-v10/bff/tests/test_restart.py',
                     'docs/WSO2_CIAM_V10_BFF_RUNTIME_RECOVERY.md'):
        path=ROOT/required
        if path.is_symlink() or not path.is_file():
            raise SystemExit('STOP: missing or unsafe runtime recovery payload: '+required)

def main():
    if len(sys.argv)>2 or (len(sys.argv)==2 and sys.argv[1]!='--apply'):
        raise SystemExit('USAGE: python3 tools/install-v10-bff-runtime-recovery.py [--apply]')
    check_git()
    changes={}
    for filename, rules in PATCHES.items():
        path=ROOT/filename
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o002:
            raise SystemExit('STOP: unsafe source path: '+filename)
        text=path.read_text()
        for old,new in rules:
            count=text.count(old)
            if count!=1:
                raise SystemExit('STOP: upstream drift in '+filename+' anchor='+repr(old[:80])+' count='+str(count))
            text=text.replace(old,new,1)
        changes[path]=text
    print('SOURCE_ONLY_CHANGE_PLAN:',*[str(p.relative_to(ROOT)) for p in changes],sep='\n  ')
    if len(sys.argv)==1:
        print('DRY RUN ONLY. Re-run with --apply to modify only listed files.')
        return
    for path,content in changes.items(): path.write_text(content)
    print('SOURCE_ONLY_PATCH_APPLIED: no process signals, credentials, Docker calls, or WSO2 writes')

if __name__=='__main__':main()
