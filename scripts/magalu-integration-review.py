#!/usr/bin/env python3
"""One-pass GA readiness review, no WSO2 writes or console configuration.

Creates a mode-0600, operator-only ZIP containing ONLY the existing adaptive
JavaScript scripts required for human/security review; never exports application
credentials or token data. All management calls are GET except OAuth token POST.
The optional --no-build saves time but does not prove GA API compatibility.
"""
import argparse
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import sys
import zipfile
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SYSDIR = ROOT / 'deploy/ciam-v10/security'
sys.path.insert(0, str(SYSDIR))

SUSPICIOUS = re.compile(r'(?i)(client[_-]?secret|password\s*[:=]|private[_-]?key|api[_-]?key|-----BEGIN [^-]+PRIVATE KEY-----|access[_-]?token\s*[:=])')


def digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def valid_review_scripts(apps):
    """Require exactly four verified apps and identical per-tenant scripts."""
    expected = {('aurora.identity.test', 'aurora-web'),
                ('aurora.identity.test', 'aurora-app'),
                ('brisa.identity.test', 'brisa-web'),
                ('brisa.identity.test', 'brisa-app')}
    if set(apps) != expected:
        raise ValueError('FOUR_JOURNAL_BOUND_APPLICATIONS_REQUIRED')
    scripts = {}
    for (tenant, alias), app in apps.items():
        seq = app.get('authenticationSequence')
        value = seq.get('script') if isinstance(seq, dict) else None
        if not isinstance(value, str) or not 30 < len(value) < 65536:
            raise ValueError('SCRIPT_MISSING_OR_TOO_LARGE_' + alias)
        if SUSPICIOUS.search(value):
            raise ValueError('SCRIPT_REQUIRES_MANUAL_SECRET_REVIEW_' + alias)
        scripts[alias] = value
    for brand in ('aurora', 'brisa'):
        if scripts[brand+'-web'] != scripts[brand+'-app']:
            raise ValueError('TENANT_CHANNEL_SCRIPTS_DIFFER_' + brand)
    return scripts


def write_review_zip(dest, scripts, local_p010):
    """Export only three JS source files and SHA metadata, not WSO2 app JSON."""
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        for brand in ('aurora', 'brisa'):
            script = scripts[brand+'-web']
            archive.writestr('live-' + brand + '.js', script)
        if local_p010 is not None and not SUSPICIOUS.search(local_p010):
            archive.writestr('repo-original-aurora-p010.js', local_p010)
        archive.writestr('SHA256.json', json.dumps({k: digest(v) for k,v in scripts.items()}, indent=2))
    fd = os.open(dest, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(out.getvalue())
            f.flush(); os.fsync(f.fileno())
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return dest


def compile_from_ga(b, rt, private_home):
    """Read container JARs, compile locally, preserve safe compiler diagnostics.

    This runs no process in the running WSO2 container; docker cp is read-only.
    Compiler logs are 0600 and never printed verbatim into ordinary chat logs.
    """
    ext = ROOT / 'extensions/magalu-wso2-risk'
    build = ext / 'build-extension.sh'
    (ext / 'target').mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='magalu-ga-review-', dir=str(ext / 'target')) as folder:
        source = Path(folder)
        base = rt['carbon_home'] + '/repository/components'
        dest = source / 'repository/components'
        dest.mkdir(parents=True)
        for part in ('plugins', 'lib'):
            b.run(['docker', 'cp', rt['is_id'] + ':' + base + '/' + part, str(dest / part)])
        env = os.environ.copy()
        env['WSO2_HOME'] = str(source)
        env['WSO2_GA_IMAGE_DIGEST'] = rt['image_id']
        result = subprocess.run(['bash', str(build)], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                check=False, timeout=180)
    logfile = private_home / 'private' / ('magalu-risk-ga-compile-' + str(time.time_ns()) + '.log')
    fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write('GA image ID: ' + rt['image_id'] + '\n')
        f.write('Build return code: ' + str(result.returncode) + '\n')
        f.write(result.stdout[-40000:])
    if result.returncode != 0:
        marker = re.search(r'(Required GA class absent: [A-Za-z0-9_.$/]+|GA PostgreSQL JDBC JAR not present)', result.stdout)
        if marker:
            reason = marker.group(1)
        elif re.search(r'\berror:', result.stdout):
            reason = 'JAVAC_GA_API_COMPILATION_ERROR'
        else:
            reason = 'GA_BUILD_RC_' + str(result.returncode)
        return {'status': 'FAILED', 'reason': reason, 'private_log': str(logfile)}
    jar = ext / 'target/magalu-wso2-risk-osgi.jar'
    return {'status': 'PASS_LOCAL_BINARY_COMPILE',
            'sha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
            'private_log': str(logfile)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true', help='Skip local-only compile (not deployment-ready)')
    args = parser.parse_args()
    os.chdir(ROOT)
    b = importlib.import_module('bootstrap')
    report = {'evidence': 'LIVE_MANAGEMENT_READBACK_AND_LOCAL_GA_BUILD',
              'remote_wso2_writes': False, 'apps': {}, 'governance': {}, 'scopes': {},
              'ga_extension_compile': 'NOT_EXECUTED', 'osgi_activation': 'NOT_TESTED',
              'live_authentication_enforcement': 'NOT_TESTED', 'blockers': []}
    try:
        home = b.home()
        rt = b.runtime(home)
        b.runtime = lambda _path: rt  # cache exact-image/port inventory during read-only checks
        report['runtime_image_id'] = rt['image_id']
        found = b.apps()
        p010 = ROOT / 'deploy/ciam-v10/p010/aurora-acr-totp-adaptive.js'
        old = p010.read_text() if p010.exists() else None
        try:
            scripts = valid_review_scripts(found)
            path = home / 'private' / 'magalu-risk-live-script-review.zip'
            if path.exists():
                report['script_review_archive'] = str(path)
                report['archive_state'] = 'EXISTS_NOT_OVERWRITTEN_REVIEW_BEFORE_USE'
            else:
                write_review_zip(path, scripts, old)
                report['script_review_archive'] = str(path)
                report['archive_mode'] = '0600'
            for alias, script in sorted(scripts.items()):
                report['apps'][alias] = {
                    'sha256': digest(script),
                    'same_as_original_aurora_p010': old is not None and old == script,
                    'step2_call_present': bool(re.search(r'\bexecuteStep\s*\(\s*2\s*[,)]', script)),
                    'requested_acr_marker': 'requestedAcr' in script,
                    'selected_acr_marker': 'selectedAcr' in script,
                    'needs_exact_semantic_review': True}
            report['blockers'].append('LIVE_ADAPTIVE_JS_REQUIRES_SEMANTIC_REVIEW_BEFORE_PATCH')
        except (ValueError, OSError) as e:
            # Continue other independent checks to avoid serial failure loops.
            report['blockers'].append('SCRIPT_REVIEW_' + (str(e) if isinstance(e, ValueError) else type(e).__name__))
        for tenant in b.BRANDS:
            try:
                before = b.governance.discovered(tenant, b.request)
                report['governance'][tenant] = {
                    'status': 'READBACK_OK',
                    'keys_found': sorted(before),
                    'needs_update': sorted(k for k,v in before.items() if v['value'] != b.governance.DESIRED[tenant][k])}
            except b.governance.GovernanceMismatch as e:
                report['governance'][tenant] = {'status': 'BLOCKED', 'reason_code': str(e)}
                report['blockers'].append('GOVERNANCE_' + tenant)
            except Exception as e:
                report['governance'][tenant] = {'status': 'BLOCKED', 'reason_code': type(e).__name__}
                report['blockers'].append('GOVERNANCE_' + tenant)
        from trusted_tls import trusted_context
        from management_oauth import preflight_write_scopes
        ctx = trusted_context(home, b.runtime)
        for tenant in b.BRANDS:
            try:
                preflight_write_scopes(home, tenant, ctx)
                report['scopes'][tenant] = 'TENANT_OAUTH_WRITE_TOKEN_CONFIRMED'
            except Exception as e:
                report['scopes'][tenant] = type(e).__name__
                report['blockers'].append('MANAGEMENT_SCOPE_' + tenant)
        if not args.no_build:
            try:
                result = compile_from_ga(b, rt, home)
                report['ga_extension_compile'] = result['status']
                report['ga_compile_private_log'] = result['private_log']
                if result['status'] == 'PASS_LOCAL_BINARY_COMPILE':
                    report['compiled_jar_sha256'] = result['sha256']
                else:
                    report['ga_compile_reason'] = result['reason']
                    report['blockers'].append('GA_OSGI_BINARY_COMPILATION')
            except Exception as e:
                report['ga_extension_compile'] = 'FAILED_' + type(e).__name__
                report['blockers'].append('GA_OSGI_BINARY_COMPILATION')
        else:
            report['ga_extension_compile'] = 'SKIPPED_BY_OPERATOR'
            report['blockers'].append('GA_OSGI_BINARY_COMPILATION_NOT_TESTED')
    except Exception as e:
        report['blockers'].append('PRECHECK_' + (str(e) if isinstance(e, ValueError) else type(e).__name__))
    report['blockers'] = sorted(set(report['blockers']))
    print(json.dumps(report, indent=2))
    return 0  # reporting never means the deployment is approved

if __name__ == '__main__':
    sys.exit(main())
