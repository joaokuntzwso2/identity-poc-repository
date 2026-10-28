#!/usr/bin/env python3
"""One-command guarded install, local test and BFF restart. No WSO2 writes.

Usage: python3 scripts/ciam-v5-deploy.py deploy
       python3 scripts/ciam-v5-deploy.py source-only
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
SERVER=ROOT/'services/identity-bff/src/server.js'
SCRIPT=ROOT/'scripts/ciam-v10.sh'


def fail(reason):
    raise SystemExit('REFUSED: '+reason)


def run(args, env=None):
    print('RUN:', ' '.join(args), flush=True)
    subprocess.run(args,cwd=ROOT,env=env,check=True)


def output(args):
    return subprocess.check_output(args,cwd=ROOT,text=True).strip()


def prepare():
    p=['python3','scripts/install-live-experience-v5.py']
    source=SERVER.read_text()
    if 'CIAM_V5_LIVE_LAB' in source:
        run(p+['--verify'])
    else:
        run(p+['--check'])
        run(p+['--apply'])
        run(p+['--verify'])
    run(['node','--test','tests/live-experience-v5.test.mjs'])
    run(['python3','scripts/zero-mock-gate.py','.'])


def listener():
    p=subprocess.run(['lsof','-nP','-tiTCP:4400','-sTCP:LISTEN'],capture_output=True,text=True)
    if p.returncode not in (0,1):fail('LSOF_FAILED')
    ids=[x for x in p.stdout.splitlines() if x.strip()]
    if len(ids)>1:fail('MULTIPLE_PORT_4400_LISTENERS')
    return int(ids[0]) if ids else None


def start():
    env=os.environ.copy()
    env.pop('WSO2_AURORA_CASES_ONLY_DIAG',None)
    env.pop('WSO2_AUDIENCE_DIAG_FILE',None)
    env['CIAM_BUSINESS_DATA_DIR']=str(Path.home()/'wso2-ciam-v10/private/business-cases-v4')
    env['WSO2_CASES_API_AUDIENCE']='urn:ciampoc:service-requests:v1'
    env['WSO2_CASES_SCOPES_ENABLED']='1'
    Path(env['CIAM_BUSINESS_DATA_DIR']).mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(env['CIAM_BUSINESS_DATA_DIR'],0o700)
    pid=listener()
    if pid:
        command=output(['ps','-p',str(pid),'-o','command='])
        if 'node' not in command or 'services/identity-bff/src/server.js' not in command:
            fail('UNKNOWN_PROCESS_ON_4400_NO_KILL')
        print('STOP_KNOWN_BFF:',pid,flush=True)
        os.kill(pid,15)
        for i in range(30):
            if listener() is None:break
            time.sleep(0.2)
        if listener() is not None:fail('KNOWN_BFF_DID_NOT_EXIT')
    if not SCRIPT.is_file():fail('CIAM_V10_SCRIPT_NOT_FOUND')
    # Scoped stale-PID cleanup. This requires port free; the CLI refuses otherwise.
    info=json.loads(output(['./scripts/ciam-v10.sh','bff-diagnose']))
    print('BFF_DIAGNOSE:',json.dumps(info),flush=True)
    if info.get('pidState')=='STALE' and info.get('port4400Listening') is False:
        env['WSO2_CIAM_V10_STALE_PID_CONFIRM']='CLEAR_DEAD_PID_ONLY'
        run(['./scripts/ciam-v10.sh','bff-clear-stale'],env)
        env.pop('WSO2_CIAM_V10_STALE_PID_CONFIRM')
    elif info.get('port4400Listening') or info.get('pidState')=='PROCESS_EXISTS':
        fail('BFF_DIAGNOSE_UNEXPECTED_RUNNING_PROCESS')
    run(['./scripts/ciam-v10.sh','bff-start'],env)
    for _ in range(20):
        if listener():break
        time.sleep(0.25)
    if listener() is None:fail('BFF_DID_NOT_LISTEN_4400')
    run(['./scripts/ciam-v10.sh','bff-diagnose'],env)
    run(['bash','scripts/live-experience-v5-acceptance.sh'],env)
    print(json.dumps({'stage':'CIAM_V5_LIVE_EXPERIENCE','localSource':'INSTALLED',
       'anonymousRuntime':'VERIFIED','allFourPositiveWSO2Logins':'NOT_TESTED',
       'wso2Writes':0,'bff':'RESTARTED','entry':'http://127.0.0.1:4400/lab'},indent=2))


if __name__=='__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in ('deploy','source-only'):
        fail('USAGE_deploy_OR_source-only')
    os.chdir(ROOT)
    prepare()
    if sys.argv[1]=='deploy':start()
