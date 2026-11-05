"""Journal-aware, WSO2-only Graal function bundle upgrade.

This is invoked by bootstrap.py upgrade-graal. It intentionally never calls
DB setup, native governance apply, or application sequence update.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import zipfile

RECEIPT = 'private/magalu-risk/graal-upgrade.json'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_call(argv, *, timeout=150, env=None):
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           check=False, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError('command unavailable or timed out: ' + argv[0]) from exc
    if r.returncode:
        # Output may contain secrets; do not forward either stream.
        raise RuntimeError('command failed: ' + argv[0] + ' rc=' + str(r.returncode))
    return r.stdout


def docker_inspect(container):
    return json.loads(safe_call(['docker', 'inspect', container], timeout=12))[0]


def write_receipt(b, path, record):
    b.atomic_write(path, json.dumps(record, indent=2, sort_keys=True) + '\n', mode=0o600)


def preflight(b, approval):
    p = b.home()
    plan_file = p / 'private/magalu-risk-plan.json'
    journal_file = p / 'private/magalu-risk-apply.json'
    receipt_file = p / RECEIPT
    for file in (plan_file, journal_file):
        b.require(file.is_file() and not file.is_symlink(), 'approval/journal missing or symlinked')
    b.require(not receipt_file.exists(), 'existing bundle upgrade receipt; inspect before retry')
    plan_bytes, journal_bytes = plan_file.read_bytes(), journal_file.read_bytes()
    plan, j = json.loads(plan_bytes), json.loads(journal_bytes)
    b.require(plan.get('digest') == approval == j.get('plan_sha256'), 'original approval mismatch')
    b.require(digest(json.dumps(plan['plan'], sort_keys=True,
                                 separators=(',', ':')).encode()) == approval,
              'original plan content digest mismatch')
    b.require(j.get('phase') == 'app-sequences-patched-unverified-live', 'unexpected journal phase')
    rt = b.runtime(p)
    b.require(j['image_id'] == rt['image_id'], 'WSO2 image changed')
    jar = b.EXT / 'target/magalu-wso2-risk-osgi.jar'
    b.require(jar.is_file() and not jar.is_symlink(), 'original JAR absent or symlinked')
    b.require(digest(jar.read_bytes()) == j['jar_sha256'], 'original JAR differs from journal')
    info = docker_inspect(rt['is_id'])
    b.require(info['State']['Running'] and info['Image'] == j['image_id'], 'WSO2 not running approved image')
    dest = rt['carbon_home'] + '/repository/components/dropins/magalu-wso2-risk-osgi.jar'
    b.require(any(pathlib.Path(x.get('Source', '')).resolve() == jar.resolve()
                  and x.get('Destination') == dest and not x.get('RW', True)
                  for x in info.get('Mounts', [])), 'running bundle bind-mount drift')
    live = b.apps()  # This also verifies exact UUID, display name, OAuth client id.
    entries = {(a['tenant'], a['name']): a for a in plan['plan']['app_changes']}
    b.require(len(entries) == 4 and set(entries) == set(live), 'application identity set drift')
    for key, app in live.items():
        b.require(b.fingerprint(app['authenticationSequence']) == entries[key]['after'],
                  'patched authentication sequence drift: ' + key[1])
        b.require('magaluRiskCheck' in app['authenticationSequence'].get('script', ''),
                  'risk gate missing: ' + key[1])
    for tenant in b.BRANDS:
        actual = {k: v['value'] for k, v in b.governance.discovered(tenant, b.request).items()}
        b.require(actual == b.governance.DESIRED[tenant], 'native governance drift: ' + tenant)
    from management_oauth import preflight_write_scopes
    from trusted_tls import trusted_context
    ctx = trusted_context(p, b.runtime)
    for tenant in b.BRANDS:
        preflight_write_scopes(p, tenant, ctx)
    component = (b.EXT / 'src/main/java/com/magalu/wso2/risk/Wso2RiskComponent.java').read_text()
    build = (b.EXT / 'build-extension.sh').read_text()
    b.require('ProxyExecutable' in component and 'checkGraal' in component
              and '(Wso2RiskFunction) this::check' not in component,
              'Java source missing ProxyExecutable fix')
    b.require('org.graalvm.polyglot.proxy' in build, 'build manifest missing Graal import')
    return p, rt, j, journal_bytes, plan, jar, receipt_file


def build_candidate(b, rt, temp):
    """Build from exact running GA JARs, without overwriting mounted JAR."""
    tmp = pathlib.Path(temp)
    src = tmp / 'extension'
    src.mkdir()
    shutil.copytree(b.EXT / 'src', src / 'src')
    shutil.copy2(b.EXT / 'build-extension.sh', src / 'build-extension.sh')
    ga = tmp / 'ga'
    ga_components = ga / 'repository/components'
    ga_components.mkdir(parents=True)
    from_dir = rt['carbon_home'] + '/repository/components/'
    for folder in ('plugins', 'lib'):
        safe_call(['docker', 'cp', rt['is_id'] + ':' + from_dir + folder,
                   str(ga_components / folder)], timeout=150)
    sdk = safe_call(['docker', 'exec', rt['is_id'], 'sh', '-ec',
                     'set -- "$1"/repository/components/dropins/graal-sdk-*.jar; '
                     '[ "$#" -eq 1 ] && [ -f "$1" ] && '
                     '{ printf "%s" "$1"; exit 0; }; exit 2',
                     'graal-sdk-discovery', rt['carbon_home']], timeout=12).strip()
    if not sdk.startswith(rt['carbon_home'] + '/repository/components/dropins/graal-sdk-') or '\n' in sdk:
        raise RuntimeError('ambiguous or missing GA Graal SDK')
    dropins = ga_components / 'dropins'
    dropins.mkdir()
    safe_call(['docker', 'cp', rt['is_id'] + ':' + sdk,
               str(dropins / pathlib.PurePosixPath(sdk).name)], timeout=60)
    env = os.environ.copy()
    env['WSO2_HOME'] = str(ga)
    env['WSO2_GA_IMAGE_DIGEST'] = rt['image_id']
    safe_call(['bash', str(src / 'build-extension.sh')], env=env, timeout=240)
    candidate = src / 'target/magalu-wso2-risk-osgi.jar'
    if not candidate.is_file():
        raise RuntimeError('GA build did not produce candidate JAR')
    with zipfile.ZipFile(candidate) as z:
        names = set(z.namelist())
        if 'com/magalu/wso2/risk/Wso2RiskComponent.class' not in names:
            raise RuntimeError('candidate missing component class')
        manifest = z.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
        # Java's jar tool folds long headers at byte boundaries.
        # Join continuation lines before validating the logical Import-Package value.
        unfolded = manifest.replace('\r\n ', '').replace('\n ', '')
        import_headers = [line[len('Import-Package: '):] for line in unfolded.splitlines()
                          if line.startswith('Import-Package: ')]
        if len(import_headers) != 1 or 'org.graalvm.polyglot.proxy' not in import_headers[0].split(','):
            raise RuntimeError('candidate manifest lacks Graal proxy import')
    return candidate


def overwrite_same_inode(path, data):
    """Preserve bind-mounted host inode; only invoked while WSO2 is stopped."""
    previous = path.stat()
    with path.open('r+b') as f:
        f.seek(0)
        f.write(data)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())
    if path.stat().st_ino != previous.st_ino or digest(path.read_bytes()) != digest(data):
        raise RuntimeError('mounted JAR inode/digest verification failed')


def current_activation(container):
    info = docker_inspect(container)
    started = info['State']['StartedAt']
    if not info['State']['Running']:
        return False, started
    r = subprocess.run(['docker', 'logs', '--since', started, '--tail', '1000', container],
                       capture_output=True, text=True, timeout=12, check=False)
    return r.returncode == 0 and 'MAGALU_RISK_ACTIVE' in (r.stdout + r.stderr), started


def upgrade_bundle(b, approval):
    p, rt, j, journal_bytes, plan, jar, receipt_file = preflight(b, approval)
    print('MAGALU_UPGRADE_PREFLIGHT_PASS', flush=True)
    with tempfile.TemporaryDirectory(prefix='magalu-graal-ga-build-') as temp:
        candidate = build_candidate(b, rt, temp)
        new_bytes = candidate.read_bytes()
        new_sha = digest(new_bytes)
        b.require(new_sha != j['jar_sha256'], 'new bundle identical to old bundle')
        print('MAGALU_GRAAL_CANDIDATE_GA_COMPILED', flush=True)
        # Keep an immutable backup and upgrade candidate before stopping WSO2.
        backupdir = p / 'private/magalu-risk/graal-upgrade-backup'
        b.require(not backupdir.exists() and not backupdir.is_symlink(),
                  'upgrade backup path exists; manual inspection required')
        backupdir.mkdir(mode=0o700, parents=True)
        original_backup = backupdir / 'original-bundle.jar'
        candidate_backup = backupdir / 'candidate-bundle.jar'
        b.atomic_write(original_backup, jar.read_bytes(), mode=0o600)
        b.atomic_write(candidate_backup, new_bytes, mode=0o600)
        b.require(digest(original_backup.read_bytes()) == j['jar_sha256'],
                  'original backup checksum mismatch')
        receipt = {
            'format': 1,
            'phase': 'prepared',
            'base_plan_sha256': approval,
            'base_jar_sha256': j['jar_sha256'],
            'new_jar_sha256': new_sha,
            'image_id': j['image_id'],
            'new_java_sha256': digest((b.EXT / 'src/main/java/com/magalu/wso2/risk/Wso2RiskComponent.java').read_bytes()),
            'new_build_sha256': digest((b.EXT / 'build-extension.sh').read_bytes()),
            'wso2_container_id': rt['is_id'],
            'created_epoch': int(time.time()),
        }
        write_receipt(b, receipt_file, receipt)
        print('MAGALU_UPGRADE_BACKUP_AND_RECEIPT_STAGED', flush=True)
        # WSO2 only: do not touch Compose, PostgreSQL, retention, apps, or governance.
        safe_call(['docker', 'stop', '--time', '40', rt['is_id']], timeout=65)
        receipt['phase'] = 'wso2-stopped'
        write_receipt(b, receipt_file, receipt)
        overwrite_same_inode(jar, new_bytes)
        receipt['phase'] = 'jar-replaced'
        write_receipt(b, receipt_file, receipt)
        safe_call(['docker', 'start', rt['is_id']], timeout=45)
        receipt['phase'] = 'wso2-started'
        write_receipt(b, receipt_file, receipt)
        print('MAGALU_WSO2_ONLY_RESTART_COMPLETE', flush=True)
        ready = False
        for _ in range(36):
            active, started = current_activation(rt['is_id'])
            if active:
                try:
                    b.request('aurora.identity.test', '/api/server/v1/identity-governance')
                    b.request('brisa.identity.test', '/api/server/v1/identity-governance')
                    ready = True
                    receipt['wso2_started_at'] = started
                    break
                except Exception:
                    pass
            time.sleep(2)
        b.require(ready, 'post-upgrade activation/management readiness unverified; receipt retained')
        live = b.apps()
        expected = {(e['tenant'], e['name']): e for e in plan['plan']['app_changes']}
        b.require(len(live) == 4 and all(b.fingerprint(app['authenticationSequence']) == expected[key]['after']
                                         for key, app in live.items()), 'application sequence readback drift after restart')
        for tenant in b.BRANDS:
            values = {k: v['value'] for k, v in b.governance.discovered(tenant, b.request).items()}
            b.require(values == b.governance.DESIRED[tenant], 'native governance drift after restart')
        b.require((p / 'private/magalu-risk-apply.json').read_bytes() == journal_bytes,
                  'original apply journal mutated')
        b.require(digest(jar.read_bytes()) == new_sha, 'repaired JAR hash drift')
        receipt['phase'] = 'verified-config'
        write_receipt(b, receipt_file, receipt)
        print(json.dumps({
            'status': 'GRAAL_BUNDLE_CONFIG_VERIFIED',
            'journal': 'ORIGINAL_UNCHANGED',
            'risk_database': 'UNTOUCHED',
            'native_governance': 'MATCHED',
            'authentication_sequences': 'FOUR_READBACK_MATCHED',
            'osgi_active_since_restart': True,
            'live_login': 'NOT_EXECUTED',
            'token_issuance': 'NOT_TESTED',
            'new_jar_sha256': new_sha,
        }, indent=2))
