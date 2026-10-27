#!/usr/bin/env python3
"""Read-only planning, write-ahead-staged configuration and guarded v10-only restart.

Never reaches original WSO2 or PostgreSQL; does not assign introspection privileges.
Requires operator intent for the two distinct mutation stages.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from introspection_policy import ensure_introspection_policy, PolicyRefused

ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home()/'wso2-ciam-v10'))).expanduser()
PRIVATE = ROOT/'private'
CONF = PRIVATE/'deployment.toml'
BACKUP = PRIVATE/'deployment.toml.before-introspection.v10'
JOURNAL = PRIVATE/'introspection-config-v10.journal.json'
CONTAINER = 'wso2-ciam-v10-is-1'
IMAGE = 'wso2/wso2is:7.3.0'
VOLUME = 'wso2-ciam-v10_isconf'
STAGING_NAME = '/tmp/ciam-v10-introspection-config-staged.toml'
STAGE_CONFIRM = 'STAGE_VERIFIED_V10_INTROSPECTION_CONFIG_ONLY'
RESTART_CONFIRM = 'RESTART_ONLY_V10_WSO2_AFTER_INTROSPECTION_STAGE'

class Refuse(Exception): pass

def digest(data): return hashlib.sha256(data).hexdigest()

def docker(*args, timeout=25, capture=True):
    try:
        return subprocess.run(['docker', *args], capture_output=capture, text=True,
                              check=True, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        raise Refuse('DOCKER_OPERATION_FAILED_NO_AUTOMATIC_RETRY') from e

def private_file(path):
    if path.is_symlink() or not path.is_file():
        raise Refuse('PRIVATE_FILE_MISSING_OR_SYMLINK_'+path.name)
    meta = path.stat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or
            stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_size > 262144):
        raise Refuse('PRIVATE_FILE_MODE_OWNER_OR_SIZE_'+path.name)
    return path.read_bytes()

def exclusive(path, data):
    if path.exists() or path.is_symlink(): raise Refuse('PRIVATE_FILE_ALREADY_EXISTS_'+path.name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
    except BaseException:
        # Keep the partial file for operator investigation, no automatic retry.
        raise

def update_journal(report):
    # Only called after an existing, ownable 0600 journal has been verified.
    private_file(JOURNAL)
    with tempfile.NamedTemporaryFile(dir=PRIVATE, prefix='.ciam-v10-journal-', delete=False) as f:
        tmp = Path(f.name)
        os.chmod(tmp, 0o600)
        f.write((json.dumps(report, sort_keys=True)+'\n').encode())
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, JOURNAL)

def active_context():
    if PRIVATE.is_symlink() or not PRIVATE.is_dir() or (PRIVATE.stat().st_mode & 0o022):
        raise Refuse('PRIVATE_RUNTIME_DIRECTORY_UNSAFE')
    info = json.loads(docker('inspect', CONTAINER).stdout)
    if len(info) != 1: raise Refuse('AMBIGUOUS_CONTAINER')
    c = info[0]
    if (c.get('Name') != '/'+CONTAINER or c['Config'].get('Image') != IMAGE or
        c['State'].get('Running') is not True):
        raise Refuse('CONTAINER_IDENTITY_OR_STATE_MISMATCH')
    binds = c.get('HostConfig', {}).get('PortBindings') or {}
    bindings = binds.get('9444/tcp', [])
    if not any(v.get('HostIp') == '127.0.0.1' and v.get('HostPort') == '9444' for v in bindings):
        raise Refuse('V10_ONLY_PORT_9444_BINDING_NOT_VERIFIED')
    mounts = [x for x in c.get('Mounts', []) if x.get('Type') == 'volume' and x.get('Name') == VOLUME]
    if len(mounts) != 1: raise Refuse('ISOLATED_CONFIG_VOLUME_NOT_VERIFIED')
    directory = mounts[0]['Destination']
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+/repository/conf', directory):
        raise Refuse('CONFIG_DIRECTORY_UNEXPECTED')
    marker = docker('exec', CONTAINER, 'cat', directory+'/.ciam-v10-managed').stdout.strip()
    if marker != 'wso2-ciam-v10': raise Refuse('CONFIG_VOLUME_NOT_MANAGED_BY_V10')
    actual = docker('exec', CONTAINER, 'sha256sum', directory+'/deployment.toml').stdout.split()[0]
    data = private_file(CONF)
    if digest(data) != actual: raise Refuse('PRIVATE_AND_ACTIVE_CONFIG_DRIFT')
    return {'containerId': c['Id'], 'directory': directory, 'current': data}

def plan():
    c = active_context()
    try:
        candidate = ensure_introspection_policy(c['current'].decode('utf-8')).encode('utf-8')
    except (ValueError, UnicodeError) as e: raise Refuse('TOML_POLICY_REFUSED_'+str(e)) from e
    return c, candidate

def read_journal():
    return json.loads(private_file(JOURNAL))

def cmd_plan():
    c, next_data = plan()
    print(json.dumps({'stage':'CIAM_V10_INTROSPECTION_CONFIG_PLAN', 'remoteWrites':0,
        'privateMatchesMounted':True, 'containerPinnedTo9444':True,
        'changedConfigurationRequired': c['current'] != next_data,
        'journalAlreadyExists': JOURNAL.exists() or JOURNAL.is_symlink(),
        'introspectionScopeRequirement':'internal_oauth2_introspect',
        'oauthClientScopeAuthorization':'NOT_VERIFIED',
        'runningServerSupportsPolicy':'NOT_VERIFIED_UNTIL_RESTART_AND_PROBE'}, indent=2))

def cmd_stage():
    if os.environ.get('WSO2_CIAM_V10_INTROSPECTION_CONFIG_CONFIRM') != STAGE_CONFIRM:
        raise Refuse('EXPLICIT_CONFIG_STAGE_CONFIRMATION_REQUIRED')
    c, candidate = plan()
    if c['current'] == candidate: raise Refuse('POLICY_ALREADY_IN_FILE_USE_READ_ONLY_PLAN')
    if any(p.exists() or p.is_symlink() for p in (JOURNAL, BACKUP)):
        raise Refuse('PREVIOUS_STAGING_OR_BACKUP_PRESENT_NO_AUTOMATIC_REPEAT')
    preflight = docker('exec', CONTAINER, 'sh', '-c', 'test ! -e '+STAGING_NAME)
    del preflight
    # Host backup is intentionally restricted and never committed or printed.
    exclusive(BACKUP, c['current'])
    item = {'schema':'identity.wso2.ciam.v10.introspection.config.v1',
            'containerId':c['containerId'], 'originalHash':digest(c['current']),
            'targetHash':digest(candidate), 'stage':'PREPARED_UNCERTAIN_DO_NOT_RETRY'}
    exclusive(JOURNAL, (json.dumps(item, sort_keys=True)+'\n').encode())
    # Stop if the process fails at any point; preserve backup and journal.
    with tempfile.NamedTemporaryFile(dir=PRIVATE, prefix='.ciam-v10-config-', delete=False) as f:
        tmp = Path(f.name)
        os.chmod(tmp, 0o600)
        f.write(candidate); f.flush(); os.fsync(f.fileno())
    try:
        # Replace private source atomically, then copy to the verified v10 only.
        os.replace(tmp, CONF)
        docker('cp', str(CONF), CONTAINER+':'+STAGING_NAME)
        folder = c['directory']
        script = ('set -eu; '
                  'test -f '+STAGING_NAME+'; '
                  'cp '+STAGING_NAME+' '+folder+'/.ciam-v10-introspection-tmp; '
                  'chown 802:802 '+folder+'/.ciam-v10-introspection-tmp; '
                  'chmod 600 '+folder+'/.ciam-v10-introspection-tmp; '
                  'mv -f '+folder+'/.ciam-v10-introspection-tmp '+folder+'/deployment.toml; '
                  'rm -f '+STAGING_NAME)
        docker('exec','-u','0:0',CONTAINER,'sh','-c',script)
        updated = docker('exec',CONTAINER,'sha256sum',folder+'/deployment.toml').stdout.split()[0]
        if updated != item['targetHash'] or digest(private_file(CONF)) != updated:
            raise Refuse('STAGED_CONFIG_READBACK_MISMATCH_MANUAL_REVIEW')
        item['stage']='STAGED_VERIFIED_RESTART_REQUIRED'
        update_journal(item)
    finally:
        if tmp.exists(): tmp.unlink()
    print(json.dumps({'stage':'CIAM_V10_INTROSPECTION_CONFIG_STAGED',
                      'readbackVerified':True, 'wso2Restarted':False,
                      'oauthClientsIntrospectionAuthorized':False,
                      'action':'EXPLICIT_V10_ONLY_RESTART_REQUIRED'}, indent=2))

def cmd_restart():
    if os.environ.get('WSO2_CIAM_V10_INTROSPECTION_RESTART_CONFIRM') != RESTART_CONFIRM:
        raise Refuse('EXPLICIT_V10_ONLY_RESTART_CONFIRMATION_REQUIRED')
    j = read_journal()
    if j.get('stage') != 'STAGED_VERIFIED_RESTART_REQUIRED':
        raise Refuse('CONFIG_NOT_STAGED_OR_RESTART_OUTCOME_UNCERTAIN')
    c = active_context()
    if c['containerId'] != j.get('containerId') or digest(c['current']) != j.get('targetHash'):
        raise Refuse('CONTAINER_ID_OR_CONFIG_HASH_DRIFT_NO_RESTART')
    # Journal before the uncertain Docker restart. Never silently retry it.
    j['stage']='RESTART_REQUESTED_UNCERTAIN_DO_NOT_REPEAT'
    update_journal(j)
    docker('restart', '-t', '30', CONTAINER, timeout=90)
    current = active_context()
    if digest(current['current']) != j['targetHash']:
        raise Refuse('POST_RESTART_CONFIG_DRIFT')
    j['stage']='RESTART_COMMAND_SUCCEEDED_INTROSPECTION_NOT_VERIFIED'
    update_journal(j)
    print(json.dumps({'stage':'CIAM_V10_ONLY_WSO2_RESTARTED',
        'postRestartConfigHashVerified':True, 'liveIntrospection':'NOT_VERIFIED',
        'oauthClientsIntrospectionAuthorized':False,
        'sessionsMayNeedFreshLogin':True}, indent=2))

def cmd_status():
    c = active_context()
    exists=JOURNAL.exists() or JOURNAL.is_symlink()
    j=read_journal() if exists else None
    print(json.dumps({'stage':'CIAM_V10_INTROSPECTION_CONFIG_STATUS',
        'remoteWrites':0,'configPrivateEqualsMounted':True,
        'journalState':j.get('stage') if j else 'ABSENT',
        'containerIdentityUnchanged': c['containerId']==j.get('containerId') if j else None,
        'configEqualsStagedTarget':digest(c['current'])==j.get('targetHash') if j else None,
        'introspectionAccepted':'NOT_VERIFIED'}, indent=2))

if __name__=='__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('plan','stage','restart','status'):
            raise Refuse('USAGE: introspection-{plan,stage,restart,status}')
        {'plan':cmd_plan,'stage':cmd_stage,'restart':cmd_restart,'status':cmd_status}[sys.argv[1]]()
    except (Refuse, PolicyRefused) as e:
        print('CIAM_V10_INTROSPECTION_REFUSED: '+str(e), file=sys.stderr)
        sys.exit(1)
