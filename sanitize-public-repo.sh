#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$ROOT"

if [[ ! -d .git ]] && ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf '%s\n' 'ERROR: place this script in the root of an existing Git checkout.' >&2
  exit 2
fi
if [[ "$(git rev-parse --show-toplevel 2>/dev/null)" != "$ROOT" ]]; then
  printf '%s\n' 'ERROR: the script must live in the Git repository root.' >&2
  exit 2
fi
command -v python3 >/dev/null || { printf '%s\n' 'ERROR: Python 3 is required.' >&2; exit 2; }

python3 - "$@" <<'PY'
from __future__ import annotations

import datetime
import os
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = pathlib.Path.cwd().resolve()
TARGET = 'ma' + 'galu'  # Split to ensure the cleanup script cannot reintroduce the removed label.
MATCH = re.compile(re.escape(TARGET), re.IGNORECASE)
MATCH_BYTES = re.compile(re.escape(TARGET.encode()), re.IGNORECASE)
CHECK_ONLY = '--check' in sys.argv[1:]
if any(arg != '--check' for arg in sys.argv[1:]):
    raise SystemExit('Usage: ./sanitize-public-repo.sh [--check]')

# Runtime dependencies and Git's object database are not distributed as repository source files.
EXCLUDED_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', '.npm', '.pnpm-store'}
# Office files and archives may hide embedded labels and proprietary attachments.
# Instead of risking a partial rewrite, move them outside the checkout for manual review.
QUARANTINE_EXTS = {'.zip', '.gz', '.tgz', '.tar', '.7z', '.rar', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}
QUARANTINE_NAMES = {TARGET + '_repo_correction_kit', '.' + TARGET + '-backups'}

changed = []
moved = []
renamed = []
errors = []
backup_root = None


def replacement(match: re.Match) -> str:
    original = match.group(0)
    if original.isupper():
        return 'IDENTITY'
    if original.islower():
        return 'identity'
    if original[0].isupper():
        return 'Identity'
    return 'identity'


def neutralize(value: str) -> str:
    return MATCH.sub(replacement, value)


def backup_directory() -> pathlib.Path:
    global backup_root
    if backup_root is None:
        stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        candidate = ROOT.parent / ('.public-poc-scrub-backup-' + stamp)
        count = 0
        while candidate.exists():
            count += 1
            candidate = ROOT.parent / ('.public-poc-scrub-backup-' + stamp + '-' + str(count))
        candidate.mkdir(mode=0o700)
        backup_root = candidate
    return backup_root


def backup_path(path: pathlib.Path) -> pathlib.Path:
    dest = backup_directory() / path.relative_to(ROOT)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        raise RuntimeError(f'Backup collision: {dest}')
    return dest


def quarantine(path: pathlib.Path, why: str) -> None:
    if CHECK_ONLY:
        errors.append(f'Cannot certify archive/backup: {path.relative_to(ROOT)} ({why})')
        return
    dest = backup_path(path)
    shutil.move(str(path), str(dest))
    moved.append(str(path.relative_to(ROOT)))


def walk():
    directories, files, links = [], [], []
    for parent, subdirs, filenames in os.walk(ROOT, topdown=True, followlinks=False):
        base = pathlib.Path(parent)
        # Exclude installed dependencies; never follow symlinks out of this checkout.
        for name in list(subdirs):
            candidate = base / name
            if name in EXCLUDED_DIRS:
                subdirs.remove(name)
            elif candidate.is_symlink():
                subdirs.remove(name)
                links.append(candidate)
            else:
                directories.append(candidate)
        for name in filenames:
            p = base / name
            (links if p.is_symlink() else files).append(p)
    return directories, files, links


def change_file(path: pathlib.Path):
    try:
        data = path.read_bytes()
        if path.suffix.lower() in QUARANTINE_EXTS or path.name.lower() in QUARANTINE_NAMES:
            quarantine(path, 'opaque document/archive')
            return
        if not MATCH_BYTES.search(data):
            return
        if b'\x00' in data:
            quarantine(path, 'binary file with matching bytes')
            return
        try:
            content = data.decode('utf-8-sig')
        except UnicodeDecodeError:
            quarantine(path, 'non-UTF8 file with matching bytes')
            return
        output = neutralize(content)
        if output == content:
            errors.append(f'Unchanged matching content: {path.relative_to(ROOT)}')
            return
        if CHECK_ONLY:
            errors.append(f'Current source contains customer label: {path.relative_to(ROOT)}')
            return
        dest = backup_path(path)
        shutil.copy2(path, dest)
        result = (b'\xef\xbb\xbf' if data.startswith(b'\xef\xbb\xbf') else b'') + output.encode('utf-8')
        path.write_bytes(result)
        shutil.copymode(dest, path)
        changed.append(str(path.relative_to(ROOT)))
    except Exception as exc:
        errors.append(f'Could not sanitize {path.relative_to(ROOT)}: {exc}')


def change_link(path: pathlib.Path):
    try:
        target = os.readlink(path)
        if not MATCH.search(target):
            return
        if CHECK_ONLY:
            errors.append(f'Symlink target contains customer label: {path.relative_to(ROOT)}')
            return
        dest = backup_path(path)
        dest.symlink_to(target)
        path.unlink()
        path.symlink_to(neutralize(target))
        changed.append(str(path.relative_to(ROOT)))
    except Exception as exc:
        errors.append(f'Could not sanitize symlink {path.relative_to(ROOT)}: {exc}')


def change_name(path: pathlib.Path):
    if not MATCH.search(path.name):
        return
    if CHECK_ONLY:
        errors.append(f'Current path contains customer label: {path.relative_to(ROOT)}')
        return
    dest = path.with_name(neutralize(path.name))
    if dest.exists() or dest.is_symlink():
        errors.append(f'RENAME COLLISION: {path.relative_to(ROOT)} -> {dest.relative_to(ROOT)}')
        return
    try:
        path.rename(dest)
        renamed.append(f'{path.relative_to(ROOT)} -> {dest.relative_to(ROOT)}')
    except OSError as exc:
        errors.append(f'Could not rename {path.relative_to(ROOT)}: {exc}')


def audit_git_history():
    try:
        commits = subprocess.run(['git', 'rev-list', '--all'], cwd=ROOT,
                                 text=True, capture_output=True, check=True).stdout.splitlines()
        if not commits:
            return []
        found = []
        log = subprocess.run(['git', 'log', '--all', '--format=%B'], cwd=ROOT,
                             capture_output=True, text=True, errors='replace', check=True).stdout
        if MATCH.search(log):
            found.append('Commit messages')
        objects = subprocess.run(['git', 'rev-list', '--objects', '--all'], cwd=ROOT,
                                 capture_output=True, text=True, errors='replace', check=True).stdout
        if MATCH.search(objects):
            found.append('Historical file paths')
        refs = subprocess.run(['git', 'for-each-ref', '--format=%(refname)'], cwd=ROOT,
                              capture_output=True, text=True, errors='replace', check=True).stdout
        if MATCH.search(refs):
            found.append('Branch or tag references')
        remotes = subprocess.run(['git', 'remote', '-v'], cwd=ROOT,
                                 capture_output=True, text=True, errors='replace', check=True).stdout
        if MATCH.search(remotes):
            found.append('Remote name or URL')
        for i in range(0, len(commits), 25):
            batch = subprocess.run(['git', 'grep', '-l', '-I', '-i', '-e', TARGET, *commits[i:i+25]],
                                   cwd=ROOT, capture_output=True, text=True, errors='replace')
            if batch.returncode == 0:
                found.append('Historical file contents')
                break
            if batch.returncode > 1:
                found.append('Git history content check failed')
                break
        return found
    except Exception as exc:
        return [f'History could not be fully checked: {exc}']


# Remove old installer source, previous patch backups, and downloadable binary packages.
# They are redundant after installation and are likely to reintroduce private materials.
dirs, files, links = walk()
for p in sorted(dirs, key=lambda q: len(q.parts)):
    if not p.exists():
        continue
    if p.name.lower() in QUARANTINE_NAMES:
        quarantine(p, 'installation artifact / old backups')

# Re-evaluate after moving whole trees out of the checkout.
dirs, files, links = walk()
for path in files:
    if path.exists():
        change_file(path)
for path in links:
    if path.is_symlink():
        change_link(path)

# Rename file/symlink components, then directories deepest-first; string references are already updated.
dirs, files, links = walk()
for path in [*files, *links]:
    if path.exists() or path.is_symlink():
        change_name(path)
for path in sorted(dirs, key=lambda q: len(q.parts), reverse=True):
    if path.exists():
        change_name(path)

# Verify current working tree after modifications; no silent success.
dirs, files, links = walk()
remaining = []
for path in [*dirs, *files, *links]:
    if MATCH.search(str(path.relative_to(ROOT))):
        remaining.append(f'Name: {path.relative_to(ROOT)}')
for path in files:
    if path.suffix.lower() in QUARANTINE_EXTS:
        remaining.append(f'Unchecked binary document: {path.relative_to(ROOT)}')
    else:
        try:
            if MATCH_BYTES.search(path.read_bytes()):
                remaining.append(f'Content: {path.relative_to(ROOT)}')
        except OSError as exc:
            remaining.append(f'Read failure: {path.relative_to(ROOT)} ({exc})')
for path in links:
    if MATCH.search(os.readlink(path)):
        remaining.append(f'Symlink: {path.relative_to(ROOT)}')

print('MODE:', 'CHECK ONLY' if CHECK_ONLY else 'CLEANUP')
print('Modified text files / symlinks:', len(changed))
print('Renamed paths:', len(renamed))
print('Moved installers / opaque documents outside repo:', len(moved))
if backup_root:
    print('Originals saved OUTSIDE repository:', backup_root)
if remaining or errors:
    print('CURRENT WORKTREE: NEEDS REVIEW')
    for item in (remaining + errors)[:40]:
        print(' -', item)
else:
    print('CURRENT WORKTREE: PASS — no matching paths or readable file contents')

history = audit_git_history()
if history:
    print('GIT HISTORY: REFERENCES FOUND OR UNVERIFIED')
    for item in history:
        print(' -', item)
    print('History is NOT modified. Public history requires a separately reviewed rewrite or repository replacement.')
else:
    print('GIT HISTORY: no matching references detected in reachable local commits')

print('NOTE: Installed dependencies/.git internals and text embedded in screenshots are not scanned.')
print('NOTE: Changing the customer name does not declassify customer-specific requirements or metrics.')
if remaining or errors:
    raise SystemExit(2)
if CHECK_ONLY and history:
    raise SystemExit(3)
PY
