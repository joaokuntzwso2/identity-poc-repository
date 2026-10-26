#!/usr/bin/env python3
"""Repository-owned v10 orchestration. Mutable state stays outside the checkout.
Never resets databases, destroys Docker containers, or blindly repeats uncertain writes.
"""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import secrets
import automation

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10'))).expanduser()
PRIVATE = ROOT / 'private'
OIDC = HERE / 'oidc/bootstrap.py'
RESOURCES = HERE / 'resources/bootstrap.py'
AUTHORITY = HERE / 'authority/bootstrap.py'
TENANTS = HERE / 'tenants/provision.py'
PROJECT = 'wso2-ciam-v10'

class Stop(Exception): pass

def run(args, *, env=None, cwd=ROOT):
    return subprocess.run(list(map(str,args)), cwd=cwd, env=env, check=True)

def repo_guard():
    if not (REPO/'wso2-lab.sh').is_file() or not (REPO/'services/identity-bff/src/server.js').is_file():
        raise Stop('RUN_ONLY_FROM_IDENTITY_PROJECT_CHECKOUT')
    # A new Git clone does not contain ignored var/wso2. Create it privately.
    vardir=REPO/'var'
    private_dir=vardir/'wso2'
    if vardir.is_symlink() or (vardir.exists() and not vardir.is_dir()):
        raise Stop('BFF_STATE_PARENT_UNSAFE')
    vardir.mkdir(mode=0o700,exist_ok=True)
    if private_dir.is_symlink() or (private_dir.exists() and not private_dir.is_dir()):
        raise Stop('BFF_PRIVATE_STATE_SYMLINK_OR_INVALID')
    private_dir.mkdir(mode=0o700,exist_ok=True)
    if stat.S_IMODE(private_dir.stat().st_mode)&0o022:
        raise Stop('BFF_PRIVATE_DIRECTORY_PERMISSIONS_UNSAFE')

def root_guard():
    if ROOT.is_symlink() or not ROOT.is_dir():
        raise Stop('V10_RUNTIME_HOME_NOT_INITIALIZED')
    if not (ROOT/'compose.yaml').is_file():
        raise Stop('V10_RUNTIME_COMPOSE_MISSING')

def safe_json(path):
    if path.is_symlink() or not path.is_file():
        raise Stop('PRIVATE_FILE_MISSING_OR_SYMLINK_'+path.name)
    meta=path.stat()
    if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_uid!=os.getuid():
        raise Stop('PRIVATE_FILE_MODE_OR_OWNER_'+path.name)
    if meta.st_size > 262144:
        raise Stop('PRIVATE_JSON_OVERSIZE')
    return json.loads(path.read_text())

def output(obj):
    print(json.dumps(obj,indent=2))

def port_open():
    try:
        with socket.create_connection(('127.0.0.1',4400),timeout=1):return True
    except OSError:return False

def http_check():
    # Request consumes no OAuth secrets; never print response body or Set-Cookie.
    try:
        with urllib.request.urlopen('http://127.0.0.1:4400/api/identity/me',timeout=2) as r:
            d=json.loads(r.read(262144))
            return {'http':r.status,'authenticated':d.get('authenticated'),
                    'configured':{k:v.get('configured') for k,v in d.get('clients',{}).items()}}
    except (OSError, ValueError, urllib.error.URLError):
        return {'http':'UNAVAILABLE'}

def pid_status():
    path=PRIVATE/'bff-v10.pid'
    if not path.exists() and not path.is_symlink():return ('ABSENT',None)
    if path.is_symlink():return ('UNSAFE_SYMLINK',None)
    try:
        if stat.S_IMODE(path.stat().st_mode)!=0o600 or path.stat().st_uid!=os.getuid():
            return ('UNSAFE_PERMISSIONS',None)
        pid=int(path.read_text().strip())
        if pid < 2:return ('INVALID_PID',None)
        os.kill(pid,0)
        return ('PROCESS_EXISTS',pid)
    except ProcessLookupError:return ('STALE',pid)
    except (PermissionError,ValueError,OSError):return ('UNKNOWN',None)

def bff_diagnose():
    report={'stage':'CIAM_V10_BFF_DIAGNOSE_READ_ONLY',
            'pidState':pid_status()[0], 'port4400Listening':port_open(),
            'sessionProbe':http_check()}
    log=PRIVATE/'bff-v10.log'
    if log.is_symlink():report['logState']='SYMLINK_REFUSED'
    elif log.is_file() and stat.S_IMODE(log.stat().st_mode)==0o600 and log.stat().st_uid==os.getuid():
        data=log.read_bytes()[-200000:]
        text=data.decode('utf-8',errors='replace')
        # Output only allowlisted error names and counts. Never raw trace, paths or secrets.
        checks={
            'WSO2_PRIVATE_VALIDATION':r'WSO2_PRIVATE_[A-Z_]+',
            'MODULE_LOAD_FAILURE':r'ERR_MODULE_NOT_FOUND|Cannot find module|MODULE_NOT_FOUND',
            'PORT_IN_USE':r'EADDRINUSE|address already in use',
            'TLS_FAILURE':r'CERT_HAS_EXPIRED|UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT',
            'FILE_MISSING':r'ENOENT|No such file',
            'CONFIGURATION_FAILURE':r'Invalid PUBLIC_ORIGIN|ALLOW_INSECURE_LOCAL|INVALID_[A-Z_]+',
            'UNHANDLED_EXCEPTION':r'uncaughtException|UnhandledPromiseRejection|^Error:',
            'START_LISTEN':r'listening on|Listening on|BFF.*started',
        }
        report['logBytesRead']=len(data)
        report['signals']={k:len(re.findall(p,text,re.I|re.M)) for k,p in checks.items()}
        report['errorCodes']=sorted(set(re.findall(r'\b(?:WSO2_PRIVATE_[A-Z_]+|ERR_MODULE_NOT_FOUND|EADDRINUSE|ENOENT)\b',text)))[:15]
    else:report['logState']='MISSING_OR_UNSAFE'
    output(report)

def wait_bff(seconds=25):
    for _ in range(seconds*2):
        if port_open():
            health=http_check()
            if health.get('http')==200:
                output({'stage':'BFF_READY','port':4400,'sessionProbe':health})
                return
        time.sleep(.5)
    bff_diagnose()
    raise Stop('BFF_START_FAILED_OR_EXITED_NO_NEW_RESOURCE_WRITES')

def bootstrap_all():
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

def prepare():
    # Fresh new runtime only. Never reset or adopt existing state implicitly.
    if os.environ.get('WSO2_CIAM_V10_FRESH_CONFIRM')!='CREATE_NEW_ISOLATED_PERSISTENT_LAB':
        raise Stop('EXPLICIT_FRESH_CONFIRMATION_REQUIRED')
    if ROOT.exists() or ROOT.is_symlink():raise Stop('RUNTIME_ALREADY_EXISTS_NO_FRESH_INIT')
    old = subprocess.run(['docker','inspect','wso2-identity-server-1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if old.returncode == 0:
        check=subprocess.run(['docker','inspect','-f','{{.State.Running}}','wso2-identity-server-1'],capture_output=True,text=True,check=True)
        if check.stdout.strip()!='true':raise Stop('OLD_WSO2_NOT_RUNNING')
    ROOT.mkdir(mode=0o700)
    PRIVATE.mkdir(mode=0o700)
    (ROOT/'initdb').mkdir(mode=0o700)
    shutil.copyfile(HERE/'templates/compose.yaml',ROOT/'compose.yaml')
    shutil.copyfile(HERE/'templates/001-databases.sql',ROOT/'initdb/001-databases.sql')
    (ROOT/'.env').write_text('POSTGRES_PASSWORD='+secrets.token_hex(32)+'\n')
    os.chmod(ROOT/'.env',0o600)
    run(['docker','compose','-p',PROJECT,'config','--quiet'])
    run(['docker','compose','-p',PROJECT,'up','-d','postgres'])
    for _ in range(60):
        probe=subprocess.run(['docker','compose','-p',PROJECT,'exec','-T','postgres',
                              'pg_isready','-U','ciamadmin','-d','postgres'],
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if probe.returncode == 0:break
        time.sleep(2)
    else: raise Stop('NEW_POSTGRES_NOT_READY')
    run(['bash',HERE/'schema/init-schemas.sh'])
    run(['bash',HERE/'server/setup.sh'])
    output({'stage':'FRESH_V10_RUNTIME_REQUESTED','port':9444,'bootstrap':'RUN_BOOTSTRAP_AFTER_HTTPS_READY'})

def main():
    if len(sys.argv)!=2:raise Stop('USAGE: scripts/ciam-v10.sh COMMAND')
    command=sys.argv[1]
    if command=='help':
        output({'commands':['fresh','fresh-bootstrap','bootstrap','status','bff-diagnose','bff-start','bff-clear-stale','test',
                           'authority-preflight','authority-evidence','authorization-plan','authorization-apply','authorization-reconcile',
                           'consent-verify','consent-plan','consent-apply','authority-status','runtime-acceptance','bff-runtime-plan','bff-restart'],
                'writeConfirmation':{'authorization-apply':'WSO2_CIAM_V10_AUTHORITY_CONFIRM=AUTHORIZE_EXISTING_V10_OIDC_AND_ASSIGN_SCIM_USERS'},
                'safety':'Consent apply refuses until feature and API contract verified'})
    elif command=='fresh':prepare()
    elif command=='fresh-bootstrap':
        repo_guard()
        automation.verify_intent(os.environ, fresh=True)
        automation.fresh_destination_preflight(ROOT)
        prepare()
        automation.wait_for_https()
        bootstrap_all()
    elif command=='bootstrap':bootstrap_all()
    elif command=='status':
        root_guard()
        for stage,script in [('tenants',TENANTS),('resources',RESOURCES),('oidc',OIDC)]:
            print('STAGE_'+stage.upper())
            run([sys.executable,script,'status'])
        bff_diagnose()
    elif command in ('authority-preflight','authority-evidence','authorization-plan','authorization-apply',
                     'authorization-reconcile','consent-verify','consent-plan',
                     'consent-apply','authority-status'):
        repo_guard();root_guard()
        run([sys.executable,AUTHORITY,command])
    elif command=='runtime-acceptance':
        root_guard()
        run([sys.executable,HERE/'authority/acceptance.py'])
    elif command in ('bff-runtime-plan','bff-restart'):
        root_guard()
        run([sys.executable,HERE/'bff/restart.py',command])
    elif command=='bff-diagnose':bff_diagnose()
    elif command=='bff-start':
        repo_guard();root_guard()
        if port_open():
            output({'stage':'BFF_ALREADY_LISTENING','port':4400,'sessionProbe':http_check()})
        else:
            state,_=pid_status()
            if state!='ABSENT':
                bff_diagnose()
                raise Stop('BFF_PID_EXISTS_'+state+'_RUN_BFF_CLEAR_STALE_ONLY_IF_DEAD')
            run([sys.executable,OIDC,'start-bff','--repo',REPO])
            wait_bff()
    elif command=='bff-clear-stale':
        root_guard()
        if os.environ.get('WSO2_CIAM_V10_STALE_PID_CONFIRM')!='CLEAR_DEAD_PID_ONLY':
            raise Stop('EXPLICIT_LOCAL_PID_CLEAR_CONFIRMATION_REQUIRED')
        state,_=pid_status()
        if state!='STALE' or port_open():raise Stop('PID_NOT_PROVEN_STALE_REFUSE')
        (PRIVATE/'bff-v10.pid').unlink()
        output({'stage':'DEAD_V10_BFF_PID_REMOVED','remoteWrites':0})
    elif command=='test':
        for d in ('server','tenants','resources','oidc','authority','bff'):
            run([sys.executable,'-m','unittest','discover','-s',HERE/d/'tests','-v'],cwd=REPO)
        run([sys.executable,'-m','unittest','discover','-s',HERE/'automation_tests','-v'],cwd=REPO)
        output({'stage':'CIAM_V10_OFFLINE_TESTS_PASSED'})
    else:raise Stop('UNKNOWN_COMMAND: help fresh fresh-bootstrap bootstrap status bff-diagnose bff-start bff-clear-stale test authority-preflight authority-evidence authorization-plan authorization-apply authorization-reconcile consent-verify consent-plan consent-apply authority-status runtime-acceptance bff-runtime-plan bff-restart')

if __name__=='__main__':
    try:main()
    except (Stop,subprocess.CalledProcessError) as e:
        print('CIAM_V10_REPO_STOP: '+(str(e) if isinstance(e,Stop) else 'CHILD_COMMAND_FAILED'),file=sys.stderr)
        sys.exit(1)
