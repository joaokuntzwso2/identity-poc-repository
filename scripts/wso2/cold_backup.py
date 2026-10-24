#!/usr/bin/env python3
"""Fail-closed cold backup of an existing loopback-only, unmounted WSO2 IS container.

This is a prerequisite to migration of configuration/DB storage, NOT a migration
or a credential-recovery tool. It never removes, recreates, or commits a container.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys

CONTAINER = 'wso2-identity-server-1'
IS_HOME = str(Path('/', 'home', 'wso2carbon', 'wso2is-7.3.0'))
REPO = IS_HOME + '/repository'
TOML = REPO + '/conf/deployment.toml'

class SafetyError(RuntimeError):
    pass


def docker(*args, capture=True, timeout=120):
    try:
        r = subprocess.run(['docker', *args], check=True, text=True,
                           capture_output=capture, timeout=timeout)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise SafetyError('DOCKER_OPERATION_FAILED_' + str(args[0])) from e
    return r.stdout if capture else ''


def database_urls(toml):
    result = {}
    current = None
    for line in toml.splitlines():
        m = re.match(r'^\s*\[([^]]+)\]\s*(?:#.*)?$', line)
        if m:
            current = m.group(1)
        if current in {'database.identity_db', 'database.shared_db'}:
            url = re.match(r'''^\s*url\s*=\s*["']([^"']+)["']''', line)
            if url:
                result[current] = url.group(1)
    return result


def validate_h2_backing(config):
    urls = database_urls(config)
    if set(urls) != {'database.identity_db', 'database.shared_db'}:
        raise SafetyError('H2_DATABASE_URLS_NOT_BOTH_EXPLICIT')
    for section, uri in urls.items():
        if not uri.startswith('jdbc:h2:'):
            raise SafetyError('UNEXPECTED_DATABASE_BACKEND_' + section)
        raw_path = uri[len('jdbc:h2:'):].split(';', 1)[0]
        if raw_path.startswith('file:'):
            raw_path = raw_path[len('file:'):]
        if raw_path.startswith('./repository/'):
            path = IS_HOME + '/' + raw_path[2:]
        else:
            path = raw_path
        if not path.startswith(REPO + '/') or '..' in Path(path).parts:
            raise SafetyError('H2_DATABASE_OUTSIDE_COPIED_REPOSITORY_' + section)
    return True


def inspect_existing():
    info = json.loads(docker('inspect', CONTAINER))[0]
    if not info.get('State', {}).get('Running'):
        raise SafetyError('EXISTING_CONTAINER_NOT_RUNNING')
    if info.get('Mounts'):
        raise SafetyError('CONTAINER_LAYOUT_CHANGED_MOUNTS_PRESENT')
    if not info.get('Config', {}).get('Labels', {}).get('com.docker.compose.project'):
        raise SafetyError('CONTAINER_NOT_COMPOSE_MANAGED')
    ports = [p for values in info.get('NetworkSettings', {}).get('Ports', {}).values()
             for p in (values or [])]
    if not ports or any(p.get('HostIp') not in ('127.0.0.1', '::1') for p in ports):
        raise SafetyError('PORT_EXPOSED_OR_UNKNOWN')
    config = docker('exec', CONTAINER, 'cat', TOML)
    validate_h2_backing(config)
    files = docker('exec', CONTAINER, 'sh', '-c',
                   "find '" + REPO + "' -type f -name '*.mv.db' -print")
    if not files.strip():
        raise SafetyError('NO_FILE_BACKED_H2_DATABASE_FILES_FOUND')
    disk_kb_raw = docker('exec', CONTAINER, 'du', '-sk', REPO).split()[0]
    disk_kb = int(disk_kb_raw)
    return disk_kb, len(files.splitlines())


def do_backup(root):
    disk_kb, db_files = inspect_existing()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    if shutil.disk_usage(root).free < disk_kb * 1024 * 2 + 100 * 1024 * 1024:
        raise SafetyError('INSUFFICIENT_HOST_DISK_FOR_COLD_BACKUP')
    lock = root / '.cold-backup.lock'
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as e:
        raise SafetyError('PREVIOUS_BACKUP_LOCK_PRESENT_MANUAL_REVIEW') from e
    os.close(fd)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dest = root / (timestamp + '-' + secrets.token_hex(4))
    stopped = False
    try:
        dest.mkdir(mode=0o700)
        (dest / 'INCOMPLETE').write_text('Cold backup not yet finished. Do not use for restore.\n')
        # The copy MUST be made after a clean server stop to avoid torn H2 files.
        docker('stop', '-t', '60', CONTAINER, capture=False, timeout=100)
        stopped = True
        docker('cp', f'{CONTAINER}:{REPO}', str(dest / 'repository'), capture=False, timeout=1800)
        copied = dest / 'repository'
        if not (copied / 'conf' / 'deployment.toml').is_file():
            raise SafetyError('BACKUP_MISSING_DEPLOYMENT_TOML')
        if not list(copied.rglob('*.mv.db')):
            raise SafetyError('BACKUP_MISSING_H2_DATA')
        # Also capture the local, untracked bootstrap journal in the private backup.
        local_wso2 = Path('var/wso2')
        private_dest = dest / 'host-wso2'
        private_dest.mkdir(mode=0o700)
        for pattern in ('*.private.json', 'lab.env'):
            for file in local_wso2.glob(pattern):
                if file.is_file() and not file.is_symlink():
                    shutil.copy2(file, private_dest / file.name)
                    os.chmod(private_dest / file.name, 0o600)
    finally:
        if stopped:
            # This starts the SAME container. No compose up, deletion or recreation.
            try:
                docker('start', CONTAINER, capture=False, timeout=120)
                running = json.loads(docker('inspect', CONTAINER))[0].get('State', {}).get('Running')
                if not running:
                    raise SafetyError('ORIGINAL_CONTAINER_DID_NOT_RESTART')
            except SafetyError:
                print('CRITICAL: original container stopped; docker start was unsuccessful.', file=sys.stderr)
                raise
        try:
            lock.unlink()
        except FileNotFoundError:
            pass
    (dest / 'metadata.json').write_text(json.dumps({
        'container': CONTAINER,
        'repositoryPath': REPO,
        'h2FileCountBeforeBackup': db_files,
        'backupMode': 'COLD_COPY_STOPPED_CONTAINER',
        'restoreTested': False,
        'originalContainerRestarted': True,
    }, indent=2) + '\n')
    os.chmod(dest / 'metadata.json', 0o600)
    (dest / 'INCOMPLETE').unlink()
    print(json.dumps({
        'result': 'COLD_BACKUP_COPIED',
        'backupDirectory': str(dest),
        'originalContainerRestarted': True,
        'restoreTested': False,
        'composeRecreationPermitted': False,
        'managementApplicationsCreated': 0,
        'secretsPrinted': False,
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['check', 'backup'])
    args = parser.parse_args()
    try:
        disk_kb, h2files = inspect_existing()
        if args.mode == 'check':
            print(json.dumps({
                'result': 'COLD_BACKUP_ELIGIBLE',
                'h2DatabaseFilesFound': h2files,
                'repositorySizeMiB': (disk_kb + 1023) // 1024,
                'composeRecreationPermitted': False,
                'stops': 0,
                'writes': 0,
                'secretsPrinted': False,
            }, indent=2))
        else:
            do_backup(Path('var/wso2/backups').resolve())
    except (SafetyError, ValueError, OSError) as e:
        # Error messages are deliberately machine-coded and never include config content.
        print('WSO2_COLD_BACKUP_ERROR:', str(e), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
