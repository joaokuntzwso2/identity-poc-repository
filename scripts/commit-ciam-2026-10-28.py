#!/usr/bin/env python3
"""Commit the known, reviewed CIAM v10/v3/v4 files from the local repository.

This script never accesses WSO2, never stages whole directories, never pushes,
and refuses to mingle with an existing Git index.  It amends README and
.gitignore additively, runs local checks, then makes a single local Git commit.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
README_START = '<!-- CIAM_V10_IMPLEMENTATION_2026_10_28_START -->'
README_END = '<!-- CIAM_V10_IMPLEMENTATION_2026_10_28_END -->'
GITIGNORE_START = '# CIAM_V10_PRIVATE_RUNTIME_2026_10_28_START'
GITIGNORE_END = '# CIAM_V10_PRIVATE_RUNTIME_2026_10_28_END'

README_SECTION = '''<!-- CIAM_V10_IMPLEMENTATION_2026_10_28_START -->
## Live CIAM implementation — WSO2 Identity Server 7.3

This repository includes a live, **zero-synthetic-identity** Aurora/Brisa customer
portal, WSO2-provisioned OIDC applications and tenant-local users, an
application-scoped business API, and a persistent service-request demonstration.
Authentication and authorization are provided by **WSO2**; the BFF owns only
session protection and application business records.

- **[Implementation map and component relationships](docs/CIAM_V10_IMPLEMENTATION_MAP.md)** — tenants → OIDC applications → API resources/scopes → app roles → tokens → BFF endpoints → business records; bootstrap lifecycle, security boundaries, configuration, and still-deferred capabilities.
- **[2026-10-28 acceptance evidence](docs/CIAM_V10_ACCEPTANCE_2026-10-28.md)** — what real WSO2 sessions verified and what remains untested.
- **[Phase 4 implementation runbook](README-IMPLEMENTATION.md)** — bootstrap plan/apply/verify instructions. Follow its guarded readback rules; never run fresh tenant provisioning against the existing lab.

**Verified so far:** Ana's Aurora Web login and owned case create/read (201/200),
Marcos's cross-user brand review (200), denied seller creation (403), and denied
approval without fresh WSO2 TOTP (403). **Not yet verified:** positive TOTP
approval, B2B delegation, privacy preferences, released profile names/email,
or business-token audiences for the other three OIDC clients. See the evidence
file for precise scope and API results.
<!-- CIAM_V10_IMPLEMENTATION_2026_10_28_END -->'''

RUNBOOK_START = '<!-- CIAM_V4_2026_10_28_STATUS_START -->'
RUNBOOK_END = '<!-- CIAM_V4_2026_10_28_STATUS_END -->'
RUNBOOK_SECTION = '''<!-- CIAM_V4_2026_10_28_STATUS_START -->
## Current verified runtime status (2026-10-28)

**Start with the [component relationship map](docs/CIAM_V10_IMPLEMENTATION_MAP.md)** and
[dated acceptance evidence](docs/CIAM_V10_ACCEPTANCE_2026-10-28.md). The
instructions below include **original deployment steps and future feature sketches**;
not every step was executed, and the earlier manual Console descriptions are
**not** the deployment procedure used for this lab. Changes to WSO2 settings are
made with guarded bootstrap/API scripts, private backup, journal, and remote
readback. Do not manually edit Console settings as a substitute for a bootstrap.

As of this date, the v4 business API and role assignments read back successfully,
Aurora Web's profile and business audiences were confirmed after a guarded OIDC
PUT, the BFF restarted, and **real users** proved these endpoints: Ana created
and read an owned request (201/200); Marcos reviewed it (200), was denied a
customer-only create (403) and was denied approval without fresh TOTP (403).
Positive MFA approval, delegated organizations, privacy preferences and other
OIDC clients' business-token audiences remain unverified. The audience recovery
source in `scripts/recovery/` is a **one-time historical recovery**, not a
bootstrap for new labs. Do not re-run fresh tenant bootstrapping on this lab.
<!-- CIAM_V4_2026_10_28_STATUS_END -->'''

GITIGNORE_SECTION = '''# CIAM_V10_PRIVATE_RUNTIME_2026_10_28_START
# Never commit local WSO2 secrets, private bootstrap journals, token diagnostics,
# mutable business data, PID files, or installer backups.
private/
*.private.json
*.backup-*
*.bak
*.bak.*
*.jsonl
*.pid
*.log
.env
.env.*
!.env.example
__pycache__/
*.pyc
.DS_Store
# CIAM_V10_PRIVATE_RUNTIME_2026_10_28_END'''

# Explicit paths only. Never stage an unknown script or whole repository.
CANDIDATES = (
    '.gitignore', 'README.md', 'README-IMPLEMENTATION.md',
    'docs/CIAM_V10_IMPLEMENTATION_MAP.md',
    'docs/CIAM_V10_ACCEPTANCE_2026-10-28.md',
    'scripts/commit-ciam-2026-10-28.py',
    'scripts/recovery/README.md',
    'scripts/recovery/ciam-v4-audience-bootstrap-v4_4.py',
    'tests/test_audience_bootstrap_v4_4.py',
    'deploy/ciam-v10/cli.py',
    'deploy/ciam-v10/resources/bootstrap.py',
    'deploy/ciam-v10/oidc/bootstrap.py',
    'scripts/ciam-v10.sh',
    'services/identity-bff/src/oidc.js',
    'deploy/ciam-v10/identities/bootstrap.py',
    'deploy/ciam-v10/identities/seed.json',
    'deploy/ciam-v10/phase4/desired.json',
    'deploy/ciam-v10/phase4/business-bootstrap.py',
    'deploy/ciam-v10/phase4/b2b-bootstrap.py',
    'deploy/ciam-v10/phase4/consent-preflight.py',
    'deploy/ciam-v10/phase4/consent-deployment.toml.txt',
    'scripts/install-identity-stage.py',
    'scripts/install-live-brand-v3.py',
    'scripts/live-v3-acceptance.sh',
    'scripts/install-business-v4.py',
    'scripts/zero-mock-gate.py',
    'scripts/live-denial-gate.sh',
    'scripts/zero-mock-v3-payload/apps/experience-center/src/main.tsx',
    'scripts/zero-mock-v3-payload/scripts/zero-mock-gate.py',
    'scripts/zero-mock-v3-payload/services/identity-bff/src/server.js',
    'services/identity-bff/src/server.js',
    'services/identity-bff/src/wso2-authority.js',
    'services/identity-bff/src/live-brand-v3.html',
    'services/identity-bff/src/live-brand-v3.css',
    'services/identity-bff/src/live-brand-v3.js',
    'services/identity-bff/src/live-userinfo.js',
    'services/identity-bff/src/live-cases-v4.js',
    'services/identity-bff/src/live-cases-v4-ui.js',
    'services/identity-bff/src/live-cases-v4-fragment.html',
    'tests/live-userinfo.test.mjs',
    'tests/live-cases-v4.test.mjs',
    'apps/experience-center/src/main.tsx',
    'apps/experience-center/src/data/personas.json',
)

REQUIRED = (
    'deploy/ciam-v10/phase4/desired.json',
    'deploy/ciam-v10/phase4/business-bootstrap.py',
    'services/identity-bff/src/live-cases-v4.js',
    'services/identity-bff/src/server.js',
    'services/identity-bff/src/wso2-authority.js',
    'scripts/zero-mock-gate.py',
    'tests/live-cases-v4.test.mjs',
    'tests/live-userinfo.test.mjs',
    'docs/CIAM_V10_IMPLEMENTATION_MAP.md',
    'docs/CIAM_V10_ACCEPTANCE_2026-10-28.md',
)

class Refuse(Exception):
    pass


def run(cmd, *, check=True, capture=False):
    output = subprocess.run(
        cmd, cwd=ROOT, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False
    )
    if check and output.returncode:
        # Diagnostic: show the failing command, but do not print potentially
        # sensitive stdout/stderr or serialized Git file content.
        raise Refuse('CHECK_FAILED: ' + ' '.join(cmd) + ' (exit ' + str(output.returncode) + ')')
    return output


def git(*args, check=True, capture=False):
    return run(['git', *args], check=check, capture=capture)


def assert_repo():
    root = git('rev-parse', '--show-toplevel', capture=True).stdout.strip()
    if Path(root).resolve() != ROOT:
        raise Refuse('RUN_FROM_REPOSITORY_ROOT_ONLY')
    if git('symbolic-ref', '-q', '--short', 'HEAD', check=False, capture=True).returncode:
        raise Refuse('DETACHED_HEAD_REFUSED')
    for marker in ('MERGE_HEAD', 'REBASE_HEAD'):
        if git('rev-parse', '--verify', '-q', marker, check=False, capture=True).returncode == 0:
            raise Refuse('IN_PROGRESS_GIT_OPERATION_' + marker)
    if git('diff', '--cached', '--quiet', check=False).returncode != 0:
        raise Refuse('PREEXISTING_STAGED_CHANGES_REFUSED: review index first')
    for path in REQUIRED:
        if not (ROOT / path).is_file():
            raise Refuse('MISSING_REQUIRED_SOURCE: ' + path)
    if (ROOT / 'apps/experience-center/src/data/personas.json').exists():
        raise Refuse('LIVE_DEMO_FIXTURE_PERSONAS_STILL_PRESENT')


def update_bounded(path: Path, start: str, end: str, section: str):
    if path.exists():
        data = path.read_text(encoding='utf-8')
    else:
        data = ''
    if data.count(start) != data.count(end) or data.count(start) > 1:
        raise Refuse('README_OR_IGNORE_MARKER_CORRUPT: ' + str(path.name))
    if data.count(start) == 1:
        a, b = data.index(start), data.index(end) + len(end)
        updated = data[:a] + section + data[b:]
    else:
        updated = data.rstrip() + ('\n\n' if data.strip() else '') + section + '\n'
    if updated != data:
        path.write_text(updated, encoding='utf-8')
        print('UPDATED:', path.relative_to(ROOT))
    else:
        print('UNCHANGED:', path.relative_to(ROOT))


def lint():
    checks = [
        ['python3', '-m', 'py_compile',
         'deploy/ciam-v10/phase4/business-bootstrap.py',
         'deploy/ciam-v10/phase4/b2b-bootstrap.py',
         'deploy/ciam-v10/phase4/consent-preflight.py',
         'scripts/recovery/ciam-v4-audience-bootstrap-v4_4.py'],
        ['node', '--check', 'services/identity-bff/src/server.js'],
        ['node', '--check', 'services/identity-bff/src/wso2-authority.js'],
        ['node', '--check', 'services/identity-bff/src/live-cases-v4.js'],
        ['node', '--check', 'services/identity-bff/src/live-cases-v4-ui.js'],
        ['node', '--test', 'tests/live-userinfo.test.mjs', 'tests/live-cases-v4.test.mjs'],
        ['python3', '-m', 'unittest', 'discover', '-s', 'tests',
         '-p', 'test_audience_bootstrap_v4_4.py', '-q'],
        ['python3', 'scripts/zero-mock-gate.py', '.'],
    ]
    for command in checks:
        print('VERIFY:', ' '.join(command), flush=True)
        run(command)


def tracked(path):
    return git('ls-files', '--error-unmatch', '--', path, check=False,
               capture=True).returncode == 0


def stage_allowlist():
    paths = [p for p in CANDIDATES if (ROOT / p).exists() or tracked(p)]
    if not paths:
        raise Refuse('NO_ALLOWLIST_FILES')
    git('add', '-A', '--', *paths)
    # Legacy v4 scope anchor intentionally contains trailing whitespace;
    # changing it would break byte-exact recovery checks. Preserve the source
    # but continue to flag every other Git whitespace class.
    git('-c', 'core.whitespace=-blank-at-eol', 'diff', '--cached', '--check')
    raw = git('diff', '--cached', '--name-only', '-z', capture=True).stdout
    staged = [x for x in raw.split('\0') if x]
    if not staged:
        raise Refuse('NO_CHANGES_TO_COMMIT')
    unexpected = sorted(set(staged) - set(paths))
    if unexpected:
        raise Refuse('UNEXPECTED_STAGED_PATHS_' + ','.join(unexpected))
    prohibited = re.compile(
        r'(^|/)(private|node_modules|__pycache__|\.git)(/|$)|'
        r'(^|/)\.env(?:\.|$)|'
        r'\.private\.json$|\.jsonl$|\.bak(?:\.|$)|\.(?:pem|key|p12|pfx)$|'
        r'\.DS_Store$|\.pid$|\.log$', re.I
    )
    for path in staged:
        if prohibited.search(path):
            raise Refuse('PRIVATE_OR_BACKUP_PATH_STAGED: ' + path)
    # Content scan of staged blobs only; do not dump source or credentials.
    checks = [
        re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
        re.compile(rb'\bAKIA[0-9A-Z]{16}\b'),
        re.compile(rb'\beyJ[A-Za-z0-9_-]{45,}\.eyJ[A-Za-z0-9_-]{45,}\.'),
    ]
    for path in staged:
        blob = git('show', ':' + path, capture=True, check=False)
        if blob.returncode:
            # Deleted tracked fixture has no staged blob.
            continue
        data = blob.stdout.encode('utf-8', 'surrogatepass')
        if any(rx.search(data) for rx in checks):
            raise Refuse('POSSIBLE_SECRET_IN_STAGED_SOURCE: ' + path)
    return staged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'commit'),
                        help='prepare = stage and show diff; commit = stage and commit locally')
    args = parser.parse_args()
    assert_repo()
    update_bounded(ROOT / 'README.md', README_START, README_END, README_SECTION)
    if (ROOT / 'README-IMPLEMENTATION.md').exists():
        update_bounded(ROOT / 'README-IMPLEMENTATION.md',
                       RUNBOOK_START, RUNBOOK_END, RUNBOOK_SECTION)
    update_bounded(ROOT / '.gitignore', GITIGNORE_START, GITIGNORE_END, GITIGNORE_SECTION)
    lint()
    staged = stage_allowlist()
    print('\nREVIEWED STAGED PATHS ({}):'.format(len(staged)))
    for p in staged:
        print(' ', p)
    print('\nSTAGED SUMMARY:')
    git('diff', '--cached', '--stat')
    if args.action == 'prepare':
        print('\nPREPARED_ONLY: No commit created. Review with git diff --cached.')
        return
    if not git('config', 'user.name', check=False, capture=True).stdout.strip() or not git(
        'config', 'user.email', check=False, capture=True).stdout.strip():
        raise Refuse('GIT_USER_IDENTITY_NOT_CONFIGURED')
    git('commit', '-m',
        'feat(ciam): document and commit verified IS 7.3 live flows',
        '-m',
        'Record Aurora/Brisa bootstrap, real business API scopes, audience recovery,\n'
        'Ana case persistence and Marcos authorization/MFA denial evidence.\n'
        'Keep private journals and runtime data out of Git.')
    sha = git('rev-parse', '--short', 'HEAD', capture=True).stdout.strip()
    print('\nLOCAL_COMMIT_CREATED:', sha)
    print('PUSH_NOT_ATTEMPTED')
    print('REMAINING_UNCOMMITTED_CHANGES:')
    git('status', '--short')


if __name__ == '__main__':
    try:
        main()
    except Refuse as exc:
        print('REFUSED:', exc, file=sys.stderr)
        sys.exit(2)
