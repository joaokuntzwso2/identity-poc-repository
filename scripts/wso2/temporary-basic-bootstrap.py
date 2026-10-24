#!/usr/bin/env python3
"""Local-only, reversible WSO2 IS 7.3 Basic-auth bootstrap window.

NEVER recreates/removes a container. Copies original config into a private recovery
marker, temporarily relaxes Basic policy, runs Node bootstrap, always restores and
restarts the SAME container. Interrupted runs require 'recover' first.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

CONTAINER='wso2-identity-server-1'
IS_HOME=str(Path('/', 'home', 'wso2carbon', 'wso2is-7.3.0'))
CONFIG=IS_HOME+'/repository/conf/deployment.toml'
PRIVATE=Path('var/wso2/basic-auth-bootstrap').resolve()
MARKER=PRIVATE/'recovery.json'
ORIGINAL=PRIVATE/'original-deployment.toml'
CA=Path('var/wso2/tls/wso2-local.pem').resolve()
COMPAT='[compatibility_setting.basic_auth.disable_basic_auth]\ndefault_value = false\ntarget_value = false\n'

class Stop(RuntimeError):pass

def docker(*args, timeout=120):
    try:
        r=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=timeout)
    except (FileNotFoundError,subprocess.TimeoutExpired) as e: raise Stop('DOCKER_UNAVAILABLE') from e
    if r.returncode:raise Stop('DOCKER_COMMAND_FAILED_'+args[0])
    return r.stdout

def inspect():
    info=json.loads(docker('inspect',CONTAINER))[0]
    if not info.get('State',{}).get('Running'):
        raise Stop('EXISTING_CONTAINER_MUST_BE_RUNNING')
    if info.get('Mounts'):
        raise Stop('MOUNT_LAYOUT_CHANGED_STOP')
    if not info.get('Config',{}).get('Labels',{}).get('com.docker.compose.project'):
        raise Stop('COMPOSE_LABEL_MISSING')
    ports=[p for v in info.get('NetworkSettings',{}).get('Ports',{}).values() for p in v or []]
    if not ports or any(p.get('HostIp') not in ('127.0.0.1','::1') for p in ports):
        raise Stop('PORTS_NOT_LOOPBACK_ONLY')
    return info

def latest_backup():
    root=Path('var/wso2/backups')
    for dest in sorted(root.glob('*'),reverse=True):
        if (dest/'metadata.json').is_file() and not (dest/'INCOMPLETE').exists() and \
           (dest/'repository/conf/deployment.toml').is_file() and list((dest/'repository').rglob('*.mv.db')):
            data=json.loads((dest/'metadata.json').read_text())
            if data.get('backupMode')=='COLD_COPY_STOPPED_CONTAINER' and data.get('originalContainerRestarted') is True:
                return dest
    raise Stop('COMPLETE_COLD_BACKUP_REQUIRED')

def verify_env():
    if os.environ.get('WSO2_LAB_CONFIRM')!='CREATE_SYNTHETIC_RESOURCES':
        raise Stop('EXPLICIT_LAB_WRITE_CONSENT_REQUIRED')
    if not CA.is_file():raise Stop('PINNED_TLS_CA_MISSING')
    if not Path('var/wso2/lab.env').is_file():raise Stop('LAB_ENV_MISSING')
    if not Path('scripts/wso2/bootstrap-tenant-control-plane.mjs').is_file():
        raise Stop('CONTROL_PLANE_CODE_NOT_INSTALLED')
    if MARKER.exists():raise Stop('INTERRUPTED_BASIC_WINDOW_RUN_RECOVER_FIRST')


def ready():
    context=ssl.create_default_context(cafile=str(CA))
    endpoint='https://localhost:9443/t/brisa.identity.test/oauth2/token/.well-known/openid-configuration'
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        try:
            req=urllib.request.Request(endpoint,headers={'Accept':'application/json'})
            with urllib.request.urlopen(req,context=context,timeout=8) as resp:
                data=json.load(resp)
            if resp.status==200 and data.get('issuer')=='https://localhost:9443/t/brisa.identity.test/oauth2/token':
                return
        except (OSError,ValueError,TimeoutError):pass
        time.sleep(3)
    raise Stop('WSO2_HTTPS_NOT_READY_AFTER_RESTART')


def config_copy_from_container():
    PRIVATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(PRIVATE,0o700)
    with tempfile.TemporaryDirectory(dir=PRIVATE) as temp:
        source=Path(temp)/'deployment.toml'
        docker('cp',f'{CONTAINER}:{CONFIG}',str(source))
        return source.read_bytes()


def write_container_config(data):
    """Stages and atomically replaces config in same running container; original mode/owner retained."""
    with tempfile.TemporaryDirectory(dir=PRIVATE) as temp:
        source=Path(temp)/'deployment.toml'
        source.write_bytes(data);os.chmod(source,0o600)
        staging='/tmp/wso2-lab-basic-bootstrap-'+str(os.getpid())+'.toml'
        docker('cp',str(source),f'{CONTAINER}:{staging}')
        # Use numeric owner/mode rather than GNU-only chmod --reference.
        # Whitelist parsed stat output; never interpolate TOML or shell input.
        values=docker('exec',CONTAINER,'stat','-c','%u:%g %a',CONFIG).strip().split()
        if len(values)!=2 or not re.fullmatch(r'[0-9]+:[0-9]+',values[0]) or not re.fullmatch(r'[0-7]{3,4}',values[1]):
            raise Stop('CONFIG_OWNER_MODE_UNDETERMINED')
        cmd='set -eu; chown '+values[0]+' '+staging+\
            '; chmod '+values[1]+' '+staging+\
            '; mv -f '+staging+' '+CONFIG
        docker('exec','-u','0',CONTAINER,'sh','-c',cmd)


def restart_and_wait():
    # This is the SAME container, never docker compose down/up or force-recreate.
    docker('restart','-t','60',CONTAINER,timeout=110)
    ready()


def prepare_marker(raw):
    if MARKER.exists():raise Stop('RECOVERY_MARKER_EXISTS')
    PRIVATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(PRIVATE,0o700)
    # A completed v1 run intentionally retained ORIGINAL for audit. Never try
    # O_EXCL on that fixed path again, overwrite it, or delete the evidence.
    # Every new bootstrap window gets a fresh private immutable snapshot.
    snapshot='original-deployment-'+secrets.token_hex(12)+'.toml'
    destination=PRIVATE/snapshot
    fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    record={'schemaVersion':2,'container':CONTAINER,'config':CONFIG,
            'originalFile':snapshot,
            'originalSha256':hashlib.sha256(raw).hexdigest(),
            'restorationVerified':False}
    fd=os.open(MARKER,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as f:json.dump(record,f);f.flush();os.fsync(f.fileno())


def recover():
    inspect()
    if not MARKER.is_file():raise Stop('NO_RECOVERY_MARKER')
    record=json.loads(MARKER.read_text())
    version=record.get('schemaVersion')
    if version==1:
        # Backwards-compatible with an interrupted v3/v3.1 config window.
        snapshot=ORIGINAL
    elif version==2:
        name=record.get('originalFile')
        if not isinstance(name,str) or not re.fullmatch(r'original-deployment-[0-9a-f]{24}\.toml',name):
            raise Stop('RECOVERY_SNAPSHOT_FILENAME_INVALID')
        snapshot=PRIVATE/name
    else:
        raise Stop('RECOVERY_MARKER_SCHEMA_UNSUPPORTED')
    if snapshot.is_symlink() or not snapshot.is_file():
        raise Stop('RECOVERY_SNAPSHOT_MISSING_OR_SYMLINK')
    raw=snapshot.read_bytes()
    if record.get('container')!=CONTAINER or record.get('config')!=CONFIG or \
       record.get('originalSha256')!=hashlib.sha256(raw).hexdigest():
        raise Stop('RECOVERY_MARKER_INTEGRITY_FAILURE')
    write_container_config(raw)
    restart_and_wait()
    now=config_copy_from_container()
    if now!=raw:raise Stop('RESTORE_READBACK_MISMATCH')
    MARKER.unlink()
    # Keep the private original for audit; no secrets ever printed.
    print(json.dumps({'basicConfiguration':'ORIGINAL_RESTORED',
                      'sameContainerRestarted':True,'httpsReady':True,
                      'containerRecreated':False,'secretsPrinted':False}))


def management_journal_verified():
    """Local state hint only: actual Bearer authority is proven via `verify` below.
    Invalid state stops; it never triggers a new management-app creation attempt.
    """
    path=Path('var/wso2/tenant-management.private.json')
    if not path.exists():return False
    if path.is_symlink() or not path.is_file():raise Stop('MANAGEMENT_JOURNAL_UNSAFE')
    try:state=json.loads(path.read_text())
    except (OSError,ValueError) as e:raise Stop('MANAGEMENT_JOURNAL_UNREADABLE') from e
    if not isinstance(state,dict) or state.get('schemaVersion')!=1 or not isinstance(state.get('management'),dict):
        raise Stop('MANAGEMENT_JOURNAL_INVALID')
    rootpath=Path('var/wso2/tenant-brand.private.json')
    if rootpath.is_symlink() or not rootpath.is_file():raise Stop('ROOT_TENANT_JOURNAL_UNSAFE_OR_MISSING')
    try:root=json.loads(rootpath.read_text())
    except (OSError,ValueError) as e:raise Stop('ROOT_TENANT_JOURNAL_UNREADABLE') from e
    if not isinstance(root,dict) or not isinstance(root.get('tenants'),dict):
        raise Stop('ROOT_TENANT_JOURNAL_INVALID')
    items=state['management']
    # Both private journals must agree about both tenant domains; no assumption
    # that the environment always uses the default synthetic domain names.
    return all(isinstance(items.get(b),dict) and items[b].get('state')=='verified' and
               isinstance(root['tenants'].get(b),dict) and root['tenants'][b].get('state')=='created' and
               items[b].get('domain')==root['tenants'][b].get('domain')
               for b in ('aurora','brisa'))


def node_mode(mode):
    env=dict(os.environ)
    env['NODE_EXTRA_CA_CERTS']=str(CA)
    args=['node','--env-file=var/wso2/lab.env',
          'scripts/wso2/bootstrap-tenant-control-plane.mjs',mode]
    try:r=subprocess.run(args,env=env,timeout=1200,check=False)
    except (FileNotFoundError,subprocess.TimeoutExpired) as e:raise Stop('NODE_STAGE_FAILED_'+mode) from e
    return r.returncode


def run():
    verify_env();inspect();latest_backup()
    # External brand-sector URLs MUST resolve to stable, distinct HTTPS hosts
    # and serve JSON callback lists before any management or OIDC POST.
    # This preflight uses no credentials and cannot change WSO2 configuration.
    if node_mode('sector-preflight'):
        raise Stop('PAIRWISE_SECTOR_PREFLIGHT_FAILED_NO_CONTAINER_RESTART_OR_API_WRITES')
    # On subsequent runs, never reopen Basic on the server if BOTH tenant
    # management apps are already verified. Prove real Bearer authority first.
    if management_journal_verified():
        if node_mode('verify'):
            raise Stop('TENANT_MANAGEMENT_BEARER_RECHECK_FAILED_NO_WRITES')
        if node_mode('clients'):
            raise Stop('OIDC_CLIENT_STAGE_FAILED_REVIEW_JOURNAL_BEFORE_RETRY')
        print(json.dumps({'management':'BEARER_ONLY','temporaryBasicWindowOpened':False,
                          'containerRestarts':0,'basicConfiguration':'UNCHANGED',
                          'secretsPrinted':False}))
        return
    raw=config_copy_from_container()
    if b'[compatibility_setting.basic_auth.disable_basic_auth]' in raw:
        raise Stop('BASIC_COMPAT_SECTION_ALREADY_EXISTS_REFUSE_OVERRIDE')
    prepare_marker(raw)
    failed=False
    try:
        candidate=raw.rstrip(b'\r\n')+b'\n\n'+COMPAT.encode()
        write_container_config(candidate)
        restart_and_wait()
        env=dict(os.environ)
        env['NODE_EXTRA_CA_CERTS']=str(CA)
        args=['node','--env-file=var/wso2/lab.env',
              'scripts/wso2/bootstrap-tenant-control-plane.mjs','all']
        print('TEMP_BASIC_WINDOW_ACTIVE_LOCALHOST_ONLY: running journaled control-plane bootstrap',flush=True)
        r=subprocess.run(args,env=env,timeout=1200,check=False)
        if r.returncode:failed=True
    finally:
        # Any errors or subprocess failure still attempt SAME-container restoration.
        recover()
    if failed:raise Stop('CONTROL_PLANE_STOPPED_WITHOUT_FULL_ACCEPTANCE')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['check','run','recover'])
    mode=p.parse_args().mode
    try:
        if mode=='check':
            inspect();backup=latest_backup()
            if MARKER.exists():raise Stop('RECOVERY_MARKER_EXISTS_USE_RECOVER')
            if b'[compatibility_setting.basic_auth.disable_basic_auth]' in config_copy_from_container():
                raise Stop('BASIC_COMPAT_SECTION_PRESENT')
            print(json.dumps({'result':'SAFE_CONFIG_WINDOW_ELIGIBLE','coldBackupPresent':True,
                              'willRestartSameContainerTwice':True,'recoverySnapshots':'UNIQUE_PER_RUN','remoteWrites':0,
                              'containerRecreationPermitted':False,'secretsPrinted':False}))
        elif mode=='recover':recover()
        else:run()
    except (Stop,OSError,ValueError,subprocess.TimeoutExpired) as e:
        print('CONTROL_PLANE_CONFIG_ERROR:',str(e) if isinstance(e,Stop) else type(e).__name__,file=sys.stderr)
        return 1
    return 0
if __name__=='__main__':sys.exit(main())
