#!/usr/bin/env python3
"""Exact-source guarded installer for commit 0a71e6b (not a deployment tool)."""
import argparse
import ast
import re
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]
CLI=Path('deploy/ciam-v10/cli.py')
README=Path('README.md')
OIDC=Path('deploy/ciam-v10/oidc/bootstrap.py')
SOURCE_NEW=(Path('deploy/ciam-v10/oidc/tests/test_role_audience.py'),
            Path('deploy/ciam-v10/automation.py'),
            Path('deploy/ciam-v10/automation_tests/test_automation.py'),
            Path('docs/CIAM_V10_AUTOMATED_FRESH_BOOTSTRAP.md'),
            Path('tools/install-v10-fresh-automation.py'))
COMMIT='0a71e6b'

OLD_BOOTSTRAP='''def bootstrap_all():
    repo_guard();root_guard()
    if os.environ.get('WSO2_CIAM_V10_DEPLOY_CONFIRM') != 'BOOTSTRAP_RECORDED_LAB_RESOURCES':
        raise Stop('EXPLICIT_BOOTSTRAP_CONFIRMATION_REQUIRED')
    stages=[(TENANTS,'WSO2_CIAM_V10_CONFIRM','CREATE_TWO_NEW_ROOT_TENANTS'),
            (RESOURCES,'WSO2_CIAM_V10_RESOURCE_CONFIRM','PROVISION_MANAGEMENT_AND_USERS'),
            (OIDC,'WSO2_CIAM_V10_OIDC_CONFIRM','CREATE_FOUR_V10_OIDC_APPS')]
    for script,key,val in stages:
        env=os.environ.copy();env[key]=val
        run([sys.executable,script,'apply'],env=env)
    run([sys.executable,OIDC,'bridge-bff','--repo',REPO])
    output({'stage':'RESOURCE_BOOTSTRAP_COMPLETED','resourceStages':'VERIFIED',
            'bff':'PRIVATE_MANIFEST_PREPARED', 'browserAuthentication':'NOT_VERIFIED'})
'''

NEW_BOOTSTRAP='''def bootstrap_all():
    repo_guard();root_guard()
    # One operator confirmation covers the complete declared bootstrap; the
    # deprecated v2 role contract still needs a separate explicit selection.
    version=automation.verify_intent(os.environ)
    # Never treat an unknown/stale BFF as ours or silently keep an old scope
    # manifest running. The fresh path expects port 4400 to be unused.
    if port_open():
        raise Stop('BFF_PORT_4400_ALREADY_USED_REFUSE_AUTO_RESTART')
    stages=[(TENANTS,'WSO2_CIAM_V10_CONFIRM','CREATE_TWO_NEW_ROOT_TENANTS'),
            (RESOURCES,'WSO2_CIAM_V10_RESOURCE_CONFIRM','PROVISION_MANAGEMENT_AND_USERS'),
            (OIDC,'WSO2_CIAM_V10_OIDC_CONFIRM','CREATE_FOUR_V10_OIDC_APPS')]
    for script,key,val in stages:
        env=os.environ.copy();env[key]=val
        run([sys.executable,script,'apply'],env=env)
    auth_report=automation.authorization_pipeline(AUTHORITY,ROOT,os.environ.copy())
    output(auth_report)
    # The BFF bridge must run AFTER the authority journal and WSO2 readback;
    # only then can it request the real ciam:profile:read scope.
    run([sys.executable,OIDC,'bridge-bff','--repo',REPO])
    run([sys.executable,OIDC,'start-bff','--repo',REPO])
    wait_bff()
    negative=automation.negative_runtime_acceptance(
        HERE/'authority/acceptance.py',ROOT,os.environ.copy())
    # Consent v2 is unavailable on the public GA WSO2 7.3 image.
    # Report the blocker without running consent-apply or creating a ledger.
    consent=automation.consent_capability(AUTHORITY,ROOT,os.environ.copy())
    output({'stage':'CIAM_V10_BOOTSTRAP_AUTOMATED','authorization':'READBACK_VERIFIED',
            'roleApiVersion':version,'bffNegativeTests':negative['status'],
            'consent':consent,'browserAuthentication':'NOT_VERIFIED_LIVE',
            'positiveBusinessAuthorization':'NOT_VERIFIED_LIVE',
            'permissionRevocation':'NOT_VERIFIED_LIVE'})
'''

OLD_README=('For an **entirely new** workstation only, `fresh` sets up isolated PostgreSQL/WSO2; '
            'after HTTPS is ready, `bootstrap` provisions tenants, M2M permissions, two SCIM users and four OIDC applications; '
            '`bff-start` starts the separate relying party. These write operations require explicit environment confirmations. '
            '**Do not run `fresh` or redo schemas against existing v10 state.** The legacy port-9443/H2 container is never an acceptable reset target.')
NEW_README=('For a **genuinely new, empty environment only**, `fresh-bootstrap` (one command with explicit confirmation) '
            'sets up persistent PostgreSQL and WSO2 on port 9444, waits for HTTPS, provisions both tenants, management/SCIM '
            'resources, all four OIDC clients, the `ciam:profile:read` business API/scope and WSO2 application roles, '
            'verifies authority readback, bridges and starts the BFF on port 4400, and checks anonymous fail-closed behavior. '
            '`bootstrap` runs the same guarded provisioning flow after an independently completed `fresh`. Both require an '
            'explicit `WSO2_CIAM_V10_ROLE_API` selection; on current GA 7.3 choose `v2` with its separate confirmation, '
            'never an automatic v3 fallback. WSO2 Consent v2 on the unupdated GA image remains BLOCKED and is never '
            'synthetically provisioned. See [automated fresh bootstrap](docs/CIAM_V10_AUTOMATED_FRESH_BOOTSTRAP.md). '
            '**Never use these write commands against an existing v10 installation.** The legacy 9443 container is untouched.')

class Stop(Exception):pass

def replace_once(src, old, new, label):
    if src.count(old)!=1:
        raise Stop('SOURCE_DRIFT_'+label+'_MATCH_COUNT_'+str(src.count(old)))
    return src.replace(old,new,1)

def changed_files():
    cli=(REPO/CLI).read_text()
    cli=replace_once(cli,'import secrets\n','import secrets\nimport automation\n','CLI_IMPORT')
    cli=replace_once(cli,OLD_BOOTSTRAP,NEW_BOOTSTRAP,'CLI_BOOTSTRAP')
    cli=replace_once(cli,"'fresh','bootstrap','status'", "'fresh','fresh-bootstrap','bootstrap','status'",'CLI_HELP')
    cli=replace_once(cli,"    elif command=='fresh':prepare()\n    elif command=='bootstrap':bootstrap_all()",
        "    elif command=='fresh':prepare()\n    elif command=='fresh-bootstrap':\n"
        "        repo_guard()\n        automation.verify_intent(os.environ, fresh=True)\n"
        "        automation.fresh_destination_preflight(ROOT)\n"
        "        prepare()\n        automation.wait_for_https()\n        bootstrap_all()\n"
        "    elif command=='bootstrap':bootstrap_all()",'CLI_DISPATCH')
    cli=replace_once(cli,"        output({'stage':'CIAM_V10_OFFLINE_TESTS_PASSED'})",
        "        run([sys.executable,'-m','unittest','discover','-s',HERE/'automation_tests','-v'],cwd=REPO)\n"
        "        output({'stage':'CIAM_V10_OFFLINE_TESTS_PASSED'})",'CLI_TEST')
    cli=replace_once(cli,'UNKNOWN_COMMAND: help fresh bootstrap status',
                     'UNKNOWN_COMMAND: help fresh fresh-bootstrap bootstrap status','CLI_USAGE')
    oidc=(REPO/OIDC).read_text()
    oidc=replace_once(oidc,
        "    if app.get('id')!=appid or app.get('name')!=node['name'] or app.get('description')!=node['description'] or app.get('isManagementApp') is not False:\n"
        "        raise Refuse('APP_REMOTE_IDENTITY_MISMATCH_'+brand+'_'+channel)\n",
        "    if app.get('id')!=appid or app.get('name')!=node['name'] or app.get('description')!=node['description'] or app.get('isManagementApp') is not False:\n"
        "        raise Refuse('APP_REMOTE_IDENTITY_MISMATCH_'+brand+'_'+channel)\n"
        "    if app.get('associatedRoles',{}).get('allowedAudience')!='APPLICATION':\n"
        "        raise Refuse('OIDC_APPLICATION_ROLE_AUDIENCE_NOT_VERIFIED_'+brand+'_'+channel)\n",
        'OIDC_AUDIENCE_READBACK')
    # Anchor on the actual two consecutive dictionary keys rather than on
    # handwritten indentation: the 0a71e6b upstream has different spacing.
    # Fail closed on any ambiguous or already edited source.
    lines=oidc.splitlines(keepends=True)
    anchors=[idx for idx,line in enumerate(lines)
             if re.fullmatch(r"[ \t]*'accessUrl':BFF_ORIGIN\+'/',\r?\n", line)]
    if len(anchors)!=1:
        raise Stop('SOURCE_DRIFT_OIDC_AUDIENCE_CREATE_MATCH_COUNT_'+str(len(anchors)))
    idx=anchors[0]
    following=lines[idx+1] if idx+1<len(lines) else ''
    if not re.fullmatch(r"[ \t]*'inboundProtocolConfiguration':\{'oidc':\{\r?\n",following):
        raise Stop('SOURCE_DRIFT_OIDC_AUDIENCE_CREATE_NEXT_KEY')
    indent=following[:len(following)-len(following.lstrip(' \t'))]
    eol='\r\n' if following.endswith('\r\n') else '\n'
    lines.insert(idx+1,indent+"'associatedRoles':{'allowedAudience':'APPLICATION','roles':[]},"+eol)
    oidc=''.join(lines)
    # Structural syntax checks before *any* tracked-source write.
    ast.parse(cli,filename=str(CLI))
    ast.parse(oidc,filename=str(OIDC))
    assert "'associatedRoles':{'allowedAudience':'APPLICATION','roles':[]}" in oidc
    assert "app.get('associatedRoles',{}).get('allowedAudience')!='APPLICATION'" in oidc
    readme=(REPO/README).read_text()
    readme=replace_once(readme,OLD_README,NEW_README,'README_FRESH')
    return {CLI:cli, OIDC:oidc, README:readme}


def main():
    p=argparse.ArgumentParser();p.add_argument('--apply',action='store_true');args=p.parse_args()
    if not (REPO/'.git').exists():raise Stop('EXPECTED_GIT_CHECKOUT')
    head=subprocess.check_output(['git','rev-parse','--short','HEAD'],cwd=REPO,text=True).strip()
    branch=subprocess.check_output(['git','branch','--show-current'],cwd=REPO,text=True).strip()
    if head!=COMMIT or branch!='main':raise Stop('REQUIRE_MAIN_AT_COMMIT_'+COMMIT)
    pathlist=[CLI,OIDC,README]
    for mode in ([],['--cached']):
        diff=subprocess.check_output(['git','diff',*mode,'--name-only','--',*[str(x) for x in pathlist]],cwd=REPO,text=True)
        if diff.strip():raise Stop('TRACKED_TARGET_IS_DIRTY_REFUSE')
    files=changed_files()
    for path in SOURCE_NEW:
        if not (REPO/path).is_file() or (REPO/path).is_symlink():raise Stop('PACKAGE_FILE_MISSING_OR_SYMLINK_'+path.name)
    print('AUTOMATED_FRESH_BOOTSTRAP_SOURCE_PLAN:')
    for path in (*pathlist,*SOURCE_NEW):print(' ',path)
    if not args.apply:
        print('DRY_RUN_ONLY_NO_SOURCE_WRITES');return
    for path,data in files.items():
        target=REPO/path
        fd,tmp=tempfile.mkstemp(prefix='.ciam-v10-',dir=target.parent)
        try:
            with os.fdopen(fd,'w') as f:
                f.write(data);f.flush();os.fsync(f.fileno())
            os.chmod(tmp, target.stat().st_mode & 0o777)
            os.replace(tmp,target)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    print('SOURCE_ONLY_APPLIED_NO_DOCKER_NO_WSO2_WRITES')

if __name__=='__main__':
    try:main()
    except (Stop,OSError,subprocess.CalledProcessError) as e:
        print('CIAM_V10_AUTO_INSTALL_STOP: '+(str(e) if isinstance(e,Stop) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
