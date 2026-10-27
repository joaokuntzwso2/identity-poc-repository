#!/usr/bin/env python3
"""Guarded source-only v10 introspection installer. Dry run by default."""
import argparse
import ast
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
EDIT = ['deploy/ciam-v10/server/render.py','deploy/ciam-v10/cli.py','README.md']

def replace_once(text, old, new, label):
    count=text.count(old)
    if count!=1: raise ValueError('SOURCE_DRIFT_'+label+'_MATCH_COUNT_'+str(count))
    return text.replace(old,new,1)

def change_source(path, original):
    if path.endswith('/render.py'):
        new=replace_once(original, 'import tomllib\n', 'import tomllib\nimport importlib.util\n', 'RENDER_IMPORT')
        new=replace_once(new,'    parsed = tomllib.loads(out)\n', '''    policy_file = Path(__file__).with_name('introspection_policy.py')
    policy_spec = importlib.util.spec_from_file_location('ciam_v10_introspection_policy', policy_file)
    policy = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy)
    out = policy.ensure_introspection_policy(out)
    parsed = tomllib.loads(out)
''','RENDER_POLICY')
        return new
    if path.endswith('/cli.py'):
        new=replace_once(original,"AUTHORITY = HERE / 'authority/bootstrap.py'\n", "AUTHORITY = HERE / 'authority/bootstrap.py'\nINTROSPECTION = HERE / 'server/introspection_maintenance.py'\n", 'CLI_CONST')
        new=replace_once(new,"'runtime-acceptance','bff-runtime-plan','bff-restart'],", "'runtime-acceptance','bff-runtime-plan','bff-restart',\n                            'introspection-plan','introspection-stage','introspection-restart','introspection-status'],", 'CLI_HELP')
        old = "    elif command=='runtime-acceptance':\n"
        additional = '''    elif command in ('introspection-plan','introspection-stage','introspection-restart','introspection-status'):
        repo_guard();root_guard()
        run([sys.executable,INTROSPECTION,command.split('-',1)[1]])
'''
        new=replace_once(new,old,additional+old,'CLI_DISPATCH')
        new=replace_once(new, "'safety':'Consent apply refuses until feature and API contract verified'", "'safety':'Consent apply refuses until feature and API contract verified',\n                 'introspection':'Separate confirmed config stage and WSO2 v10-only restart; runtime permission verification still required'", 'CLI_HELP_SAFETY')
        return new
    if path=='README.md':
        return original.rstrip()+'\n\nSee `docs/CIAM_V10_INTROSPECTION_CONFIGURATION.md` for the guarded v10 token-introspection configuration and restart workflow.\n'
    raise ValueError('UNEXPECTED_TARGET')

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--apply',action='store_true')
    args=p.parse_args()
    result=subprocess.run(['git','rev-parse','--show-toplevel'],cwd=REPO,text=True,capture_output=True,check=True)
    if Path(result.stdout.strip()).resolve()!=REPO:
        raise ValueError('NOT_EXPECTED_GIT_ROOT')
    result=subprocess.run(['git','diff','--quiet','--',*EDIT],cwd=REPO)
    if result.returncode!=0: raise ValueError('TRACKED_TARGET_HAS_LOCAL_CHANGES')
    updated={}
    for relative in EDIT:
        source=REPO/relative
        if source.is_symlink() or not source.is_file():raise ValueError('TARGET_MISSING_OR_SYMLINK_'+relative)
        new=change_source(relative,source.read_text())
        if relative.endswith('.py'):ast.parse(new)
        updated[source]=new
    for name in ('introspection_policy.py','introspection_maintenance.py'):
        path=REPO/'deploy/ciam-v10/server'/name
        if not path.is_file() or path.is_symlink():raise ValueError('NEW_MODULE_MISSING_'+name)
        ast.parse(path.read_text())
    print('INTROSPECTION_SOURCE_PLAN:')
    for path in updated: print('  '+str(path.relative_to(REPO)))
    if not args.apply:
        print('DRY_RUN_ONLY_NO_SOURCE_WRITES')
        return
    for path,content in updated.items():
        path.write_text(content)
    print('SOURCE_ONLY_APPLIED_NO_CONTAINER_OR_WSO2_WRITES')

if __name__=='__main__':
    try:main()
    except (ValueError, OSError, subprocess.CalledProcessError) as ex:
        print('CIAM_INTROSPECTION_INSTALL_STOP: '+str(ex),file=sys.stderr)
        sys.exit(1)
