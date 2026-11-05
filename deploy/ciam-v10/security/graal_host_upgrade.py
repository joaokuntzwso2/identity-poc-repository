"""Second, journal-aware Magalu Graal host-callable bundle upgrade.

Must be invoked as bootstrap.py upgrade-host --approve <original-plan-digest>.
Only the existing bind-mounted WSO2 risk JAR and the WSO2 container are changed.
Never re-run after a receipt is created. All other journal/database/app state is read-only.
"""
import hashlib
import json
import pathlib
import tempfile
import time
import zipfile

import graal_upgrade as previous

RECEIPT_REL = 'private/magalu-risk/graal-host-upgrade.json'
BACKUP_REL = 'private/magalu-risk/graal-host-upgrade-backup'
FIRST_REL = 'private/magalu-risk/graal-upgrade.json'
FIRST_BACKUP_REL = 'private/magalu-risk/graal-upgrade-backup'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require_file(b, file, label):
    b.require(file.is_file() and not file.is_symlink(), label + ' absent, symlink, or unreadable')
    return file.read_bytes()


def verify_applications(b, plan):
    live = b.apps()  # Also checks original OAuth client IDs and UUIDs.
    entries = {(x['tenant'], x['name']): x for x in plan['plan']['app_changes']}
    b.require(len(live) == len(entries) == 4 and set(live) == set(entries),
              'four-app identity set drift')
    for key, app in live.items():
        sequence = app['authenticationSequence']
        b.require(b.fingerprint(sequence) == entries[key]['after'],
                  'authentication sequence drift: ' + key[1])
        b.require('magaluRiskCheck' in (sequence.get('script') or ''),
                  'risk gate missing: ' + key[1])
    for tenant in b.BRANDS:
        actual = {k: v['value'] for k, v in b.governance.discovered(tenant, b.request).items()}
        b.require(actual == b.governance.DESIRED[tenant],
                  'native lock policy drift: ' + tenant)


def verify_mount(b, rt, j, jar):
    info = previous.docker_inspect(rt['is_id'])
    b.require(info['State']['Running'] and info['Image'] == j['image_id'],
              'expected WSO2 container/image not running')
    dest = rt['carbon_home'] + '/repository/components/dropins/magalu-wso2-risk-osgi.jar'
    b.require(any(pathlib.Path(m.get('Source', '')).resolve() == jar.resolve()
                  and m.get('Destination') == dest and not m.get('RW', True)
                  for m in info.get('Mounts', [])),
              'risk JAR read-only bind mount drift')
    b.require(len(info.get('NetworkSettings', {}).get('Ports', {}).get('9444/tcp') or []) == 1,
              'WSO2 published endpoint drift')
    return info


def preflight(b, approval):
    p = b.home()
    plan_path = p / 'private/magalu-risk-plan.json'
    journal_path = p / 'private/magalu-risk-apply.json'
    first_path = p / FIRST_REL
    second_path = p / RECEIPT_REL
    backup_dir = p / BACKUP_REL
    old_backup_dir = p / FIRST_BACKUP_REL
    for fp in (plan_path, journal_path, first_path):
        require_file(b, fp, fp.name)
    b.require(not second_path.exists() and not second_path.is_symlink(),
              'second-upgrade receipt exists; inspect and recover, never repeat')
    b.require(not backup_dir.exists() and not backup_dir.is_symlink(),
              'second-upgrade backup exists; inspect, never repeat')
    plan_bytes = require_file(b, plan_path, 'original plan')
    journal_bytes = require_file(b, journal_path, 'original journal')
    first_bytes = require_file(b, first_path, 'first upgrade receipt')
    plan, journal, first = map(json.loads, (plan_bytes, journal_bytes, first_bytes))
    b.require(journal.get('phase') == 'app-sequences-patched-unverified-live',
              'unexpected apply journal phase')
    b.require(plan.get('digest') == journal.get('plan_sha256') == approval,
              'original approval and journal digest mismatch')
    b.require(digest(json.dumps(plan['plan'], sort_keys=True,
                                separators=(',', ':')).encode()) == approval,
              'approved plan content digest mismatch')
    b.require(first.get('phase') == 'verified-config'
              and first.get('base_plan_sha256') == approval
              and first.get('base_jar_sha256') == journal.get('jar_sha256')
              and first.get('image_id') == journal.get('image_id'),
              'first upgrade receipt incomplete/inconsistent')
    b.require(isinstance(first.get('new_jar_sha256'), str)
              and len(first['new_jar_sha256']) == 64,
              'first upgraded bundle SHA missing')
    b.require(old_backup_dir.is_dir() and not old_backup_dir.is_symlink(),
              'original upgrade backup directory unavailable')
    old_original = require_file(b, old_backup_dir / 'original-bundle.jar', 'first original backup')
    old_candidate = require_file(b, old_backup_dir / 'candidate-bundle.jar', 'first candidate backup')
    b.require(digest(old_original) == journal['jar_sha256']
              and digest(old_candidate) == first['new_jar_sha256'],
              'first backup chain mismatch')
    rt = b.runtime(p)
    b.require(rt['image_id'] == journal['image_id'], 'GA image changed')
    jar = b.EXT / 'target/magalu-wso2-risk-osgi.jar'
    current_bytes = require_file(b, jar, 'mounted JAR')
    b.require(digest(current_bytes) == first['new_jar_sha256'],
              'running bundle does not match first receipt')
    verify_mount(b, rt, journal, jar)
    active, _ = previous.current_activation(rt['is_id'])
    b.require(active, 'OSGi activation since current WSO2 start not found')
    verify_applications(b, plan)
    java_file = b.EXT / 'src/main/java/com/magalu/wso2/risk/Wso2RiskComponent.java'
    java = require_file(b, java_file, 'host-callable Java source').decode('utf-8')
    b.require('MAGALU_HOST_CALLABLE_V2' in java
              and 'new HostRiskFunction(this)' in java
              and '@HostAccess.Export' in java
              and '(ProxyExecutable) this::checkGraal' not in java,
              'host-callable Java registration missing or regressed')
    build = require_file(b, b.EXT / 'build-extension.sh', 'shared GA build')
    b.require(b'org.graalvm.polyglot' in build,
              'shared GA build lacks Polyglot import')
    return {'home': p, 'rt': rt, 'plan': plan, 'plan_bytes': plan_bytes,
            'journal': journal, 'journal_bytes': journal_bytes,
            'first': first, 'first_bytes': first_bytes, 'first_path': first_path,
            'jar': jar, 'current_bytes': current_bytes, 'receipt': second_path,
            'backup': backup_dir, 'java_file': java_file,
            'java_sha': digest(java.encode()), 'build_sha': digest(build)}


def verify_candidate(b, candidate):
    data = candidate.read_bytes()
    with zipfile.ZipFile(candidate) as z:
        entries = set(z.namelist())
        name = 'com/magalu/wso2/risk/Wso2RiskComponent$HostRiskFunction.class'
        b.require(name in entries and
                  'com/magalu/wso2/risk/Wso2RiskComponent.class' in entries,
                  'candidate JAR does not contain host function')
        b.require(b'HostAccess$Export' in z.read(name),
                  'host function missing compiled @HostAccess.Export')
        manifest = z.read('META-INF/MANIFEST.MF').decode('utf-8', 'replace')
        unfolded = manifest.replace('\r\n ', '').replace('\n ', '')
        headers = [x[16:] for x in unfolded.splitlines() if x.startswith('Import-Package: ')]
        b.require(len(headers) == 1 and 'org.graalvm.polyglot' in headers[0],
                  'Graal package missing in candidate manifest')
    return data


def write_receipt(b, file, value):
    previous.write_receipt(b, file, value)


def upgrade_host_bundle(b, approval):
    state = preflight(b, approval)
    print('MAGALU_HOST_UPGRADE_PREFLIGHT_PASS', flush=True)
    rt, jar, j = state['rt'], state['jar'], state['journal']
    with tempfile.TemporaryDirectory(prefix='magalu-host-upgrade-ga-') as td:
        candidate = previous.build_candidate(b, rt, td)
        new_bytes = verify_candidate(b, candidate)
        new_sha = digest(new_bytes)
        b.require(new_sha != state['first']['new_jar_sha256'],
                  'new bundle identical to first-upgrade JAR')
        # Verify no drift during isolated GA build, before any WSO2 write.
        b.require(digest(jar.read_bytes()) == state['first']['new_jar_sha256'],
                  'mounted bundle changed during build')
        b.require(digest(state['java_file'].read_bytes()) == state['java_sha']
                  and digest((b.EXT / 'build-extension.sh').read_bytes()) == state['build_sha'],
                  'Java/build source changed during candidate compilation')
        b.require(state['first_path'].read_bytes() == state['first_bytes']
                  and (state['home'] / 'private/magalu-risk-apply.json').read_bytes()
                  == state['journal_bytes'],
                  'receipt or journal changed during build')
        verify_mount(b, rt, j, jar)
        verify_applications(b, state['plan'])
        print('MAGALU_HOST_GA_CANDIDATE_COMPILED', flush=True)
        backup = state['backup']
        backup.mkdir(parents=True, mode=0o700, exist_ok=False)
        files = {
            'previous-bundle.jar': state['current_bytes'],
            'candidate-bundle.jar': new_bytes,
            'first-receipt.json': state['first_bytes'],
        }
        for filename, data in files.items():
            b.atomic_write(backup / filename, data, mode=0o600)
            b.require((backup / filename).read_bytes() == data,
                      'staged backup validation failed: ' + filename)
        receipt = {
            'format': 1,
            'phase': 'prepared',
            'base_plan_sha256': approval,
            'base_jar_sha256': state['first']['new_jar_sha256'],
            'first_receipt_sha256': digest(state['first_bytes']),
            'new_jar_sha256': new_sha,
            'image_id': j['image_id'],
            'new_java_sha256': state['java_sha'],
            'new_build_sha256': state['build_sha'],
            'upgrade_module_sha256': digest(pathlib.Path(__file__).read_bytes()),
            'wso2_container_id': rt['is_id'],
            'created_epoch': int(time.time()),
        }
        write_receipt(b, state['receipt'], receipt)
        print('MAGALU_HOST_BACKUP_AND_RECEIPT_STAGED', flush=True)
        # No DB, Compose, governance, or application writes. WSO2 only.
        previous.safe_call(['docker', 'stop', '--time', '40', rt['is_id']], timeout=65)
        receipt['phase'] = 'wso2-stopped'
        write_receipt(b, state['receipt'], receipt)
        previous.overwrite_same_inode(jar, new_bytes)
        receipt['phase'] = 'jar-replaced'
        write_receipt(b, state['receipt'], receipt)
        previous.safe_call(['docker', 'start', rt['is_id']], timeout=45)
        receipt['phase'] = 'wso2-started'
        write_receipt(b, state['receipt'], receipt)
        print('MAGALU_HOST_WSO2_RESTART_COMPLETE', flush=True)
        ready = False
        for _ in range(36):
            active, started = previous.current_activation(rt['is_id'])
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
        b.require(ready, 'new bundle activation and management readiness failed; receipt retained')
        verify_mount(b, rt, j, jar)
        verify_applications(b, state['plan'])
        b.require(digest(jar.read_bytes()) == new_sha, 'installed JAR SHA drift')
        b.require(digest(state['java_file'].read_bytes()) == state['java_sha']
                  and digest((b.EXT / 'build-extension.sh').read_bytes()) == state['build_sha'],
                  'source changed during upgrade')
        b.require((state['home'] / 'private/magalu-risk-apply.json').read_bytes()
                  == state['journal_bytes'], 'original journal changed during upgrade')
        b.require((state['home'] / 'private/magalu-risk-plan.json').read_bytes()
                  == state['plan_bytes'], 'approved plan changed during upgrade')
        b.require(state['first_path'].read_bytes() == state['first_bytes'],
                  'first upgrade receipt changed during upgrade')
        receipt['phase'] = 'verified-config'
        write_receipt(b, state['receipt'], receipt)
        print(json.dumps({
            'status': 'GRAAL_HOST_CONFIG_VERIFIED',
            'receipt_chain': 'ORIGINAL_TO_FIRST_TO_SECOND',
            'journal': 'ORIGINAL_UNCHANGED',
            'authentication_sequences': 'FOUR_READBACK_MATCHED',
            'native_governance': 'MATCHED',
            'osgi_active_since_restart': True,
            'new_jar_sha256': new_sha,
            'live_login': 'NOT_EXECUTED',
            'token_issuance': 'NOT_TESTED',
        }, indent=2), flush=True)
