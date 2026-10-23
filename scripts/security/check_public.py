#!/usr/bin/env python3
"""Fail-closed check of Git index or a committed tree for a public repository.

Customer-specific literal patterns live OUTSIDE the repository. Do not add them here.
This is a safeguard, not a substitute for human security review.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATTERNS = ROOT.parent / '.identity-private-patterns.txt'
MAX_BLOB_SIZE = 3_000_000

# General sensitive filenames. These are blocked even if git add -f bypasses .gitignore.
PRIVATE_PATH = re.compile(
    r'(^|/)(?:\.env(?:\.|$)|[^/]*(?:rfp|blueprint|traceability|requirements[-_ ]?matrix|'
    r'customer[-_ ]?data|confidential|private[-_ ]?notes|proposal|credentials|secrets|'
    r'operator[-_ ]?runbook|repository[-_ ]?audit)[^/]*)(?:$|/)',
    re.IGNORECASE,
)
PRIVATE_EXT = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.tar',
    '.tgz', '.gz', '.7z', '.rar', '.sqlite', '.db', '.pem', '.p12', '.pfx',
    '.jks', '.keystore', '.key', '.crt', '.cer', '.p8', '.mobileprovision',
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.heic', '.ico', '.svg', '.avif',
    '.mp4', '.mov', '.webm', '.pdf', '.woff', '.woff2', '.ttf', '.otf',
}
DENY_CONTENT = [
    ("restricted confidentiality label", re.compile(r'(?im)^(?:classifica(?:ção|cao)\s*:\s*)?(?:confidencial|confidential)\s*[-—:]\s*(?:uso restrito|internal use|restricted|confidential)\b')),
    ("private key", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----')),
    ("GitHub token", re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{20,}')),
    ("AWS access key", re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ("Slack token", re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{15,}')),
    ("private home path", re.compile(r'/(?:Users|home)/[A-Za-z0-9_.-]+/')),
    ("Brazilian CPF-shaped personal identifier", re.compile(r'(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)')),
]


def git(*args: str, input_bytes: bytes | None = None) -> bytes:
    p = subprocess.run(['git', *args], cwd=ROOT, input=input_bytes,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError(f"git {' '.join(args[:3])}: {p.stderr.decode('utf-8', 'replace').strip()}")
    return p.stdout


def private_patterns(path: Path) -> list[str]:
    if not path.is_file():
        raise RuntimeError(f"Required private pattern file missing: {path}. Run the external preparation script.")
    lines = path.read_text(encoding='utf-8').splitlines()
    patterns = [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith('#')]
    if not patterns:
        raise RuntimeError(f'Private pattern file contains no patterns: {path}')
    return patterns


def from_index():
    for entry in git('ls-files', '-z', '--stage').split(b'\0'):
        if not entry:
            continue
        meta, name = entry.split(b'\t', 1)
        mode, sha, stage = meta.split(b' ')
        if stage != b'0':
            raise RuntimeError('Unmerged Git index; resolve conflicts before committing')
        yield (name.decode('utf-8', 'surrogateescape'), mode.decode(), sha.decode())


def from_tree(revision: str):
    for entry in git('ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
        if not entry:
            continue
        meta, name = entry.split(b'\t', 1)
        mode, kind, sha = meta.split(b' ')
        yield (name.decode('utf-8', 'surrogateescape'), mode.decode(), sha.decode())


def main():
    ap = argparse.ArgumentParser()
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument('--staged', action='store_true')
    source.add_argument('--tree', metavar='GIT_REVISION')
    ap.add_argument('--patterns', type=Path, default=Path(os.environ.get('PUBLIC_PRIVATE_PATTERNS_FILE', str(DEFAULT_PATTERNS))))
    args = ap.parse_args()
    try:
        patterns = private_patterns(args.patterns)
        files = list(from_index() if args.staged else from_tree(args.tree))
    except Exception as ex:
        print(f'PUBLICATION_BLOCKED: {ex}', file=sys.stderr)
        return 2

    if not files:
        print('PUBLICATION_BLOCKED: no files staged or committed', file=sys.stderr)
        return 2

    issues: list[str] = []
    for name, mode, sha in files:
        rel = name.replace('\\', '/')
        lower = rel.casefold()
        if mode not in ('100644', '100755'):
            issues.append(f'{rel}: symlink/submodule/non-regular file not approved')
            continue
        if '\n' in name or '\r' in name:
            issues.append(f'{rel!r}: filename includes newlines')
            continue
        if ((PRIVATE_PATH.search(rel) and Path(rel).name not in ('.env.example', '.env.sample', '.env.template'))
                or Path(rel).suffix.lower() in PRIVATE_EXT):
            issues.append(f'{rel}: private/opaque path or extension is not allowed')
            continue
        if any(p.casefold() in lower for p in patterns):
            issues.append(f'{rel}: private pattern in filename')
            continue
        if args.staged:
            ignore = subprocess.run(['git', 'check-ignore', '--no-index', '-q', '--', name], cwd=ROOT)
            if ignore.returncode == 0:
                issues.append(f'{rel}: ignored file forcibly staged (git add -f)')
                continue
        try:
            content = git('cat-file', 'blob', sha)
        except Exception as ex:
            issues.append(f'{rel}: unable to read blob ({ex})')
            continue
        if len(content) > MAX_BLOB_SIZE:
            issues.append(f'{rel}: file too large; requires separate review')
            continue
        if b'\x00' in content:
            issues.append(f'{rel}: binary content requires separate review')
            continue
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            issues.append(f'{rel}: non-UTF-8 content requires separate review')
            continue
        folded = text.casefold()
        if any(p.casefold() in folded for p in patterns):
            issues.append(f'{rel}: customer/private term found in content')
            continue
        for label, regex in DENY_CONTENT:
            if regex.search(text):
                issues.append(f'{rel}: {label}')
                break
    if issues:
        print(f'PUBLICATION_BLOCKED: {len(issues)} issue(s); no commit or push should proceed.', file=sys.stderr)
        for issue in issues[:80]:
            print(f'  - {issue}', file=sys.stderr)
        if len(issues) > 80:
            print(f'  ... and {len(issues) - 80} more', file=sys.stderr)
        return 1
    print(f'PUBLICATION_PASS: scanned {len(files)} Git blobs and paths against private rules.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
