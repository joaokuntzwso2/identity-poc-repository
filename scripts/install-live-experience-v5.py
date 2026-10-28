#!/usr/bin/env python3
"""Additive v5 UI reintegration. No remote writes, no git stage, no reset.

Usage: python3 scripts/install-live-experience-v5.py --check|--apply|--verify
Run from the repository root after extracting the source package.
"""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'services/identity-bff/src'
SERVER = SRC / 'server.js'
FILES = ('live-experience-v5.html', 'live-experience-v5.js',
         'live-experience-v5.css', 'live-retail-v5.css')

ANCHOR = "  '/portal/brisa': 'live-brand-v3.html',"
INSERT = """  // CIAM_V5_LIVE_LAB: original Experience Center presentation, zero synthetic identity.
  '/lab': 'live-experience-v5.html',
  '/experience': 'live-experience-v5.html',
  '/portal/aurora/web': 'live-experience-v5.html',
  '/portal/aurora/mobile': 'live-experience-v5.html',
  '/portal/brisa/web': 'live-experience-v5.html',
  '/portal/brisa/mobile': 'live-experience-v5.html',
  '/live-experience-v5.js': 'live-experience-v5.js',
  '/live-experience-v5.css': 'live-experience-v5.css',
  '/live-retail-v5.css': 'live-retail-v5.css',"""
DEST_OLD = """function destination(key, asked) {
  if (asked === '/identity-live-v2') return asked;
  const brand = clients[key].brand;
  return asked === `/portal/${brand}` ? asked : '/';
}"""
DEST_NEW = """function destination(key, asked) {
  // CIAM_V5_RETURNTO: explicit local allowlist; never accept external or cross-brand URLs.
  if (asked === '/identity-live-v2' || asked === '/lab' || asked === '/experience') return asked;
  const brand = clients[key].brand;
  if (asked === `/portal/${brand}`) return asked;
  if (asked === `/portal/${brand}/web` && key === `${brand}-web`) return asked;
  if (asked === `/portal/${brand}/mobile` && key === `${brand}-app`) return asked;
  return '/lab';
}"""
ROOT_OLD = "  '/': 'live-wso2.html',"
ROOT_NEW = "  '/': 'live-experience-v5.html',"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def refuse(why):
    raise SystemExit('REFUSED: ' + why)


def expect_files():
    for name in FILES:
        p = SRC / name
        if not p.is_file() or p.stat().st_size < 200:
            refuse('MISSING_OR_EMPTY_V5_SOURCE_' + name)
    if not SERVER.is_file():
        refuse('BFF_SERVER_MISSING')


def make_new(original):
    if 'CIAM_V5_LIVE_LAB' in original or 'CIAM_V5_RETURNTO' in original:
        refuse('ALREADY_PATCHED_USE_VERIFY')
    for old in (ANCHOR, DEST_OLD, ROOT_OLD):
        if original.count(old) != 1:
            refuse('SOURCE_ANCHOR_MISMATCH_' + old[:32].replace('\n', '_'))
    updated = original.replace(ANCHOR, ANCHOR + '\n' + INSERT)
    updated = updated.replace(DEST_OLD, DEST_NEW).replace(ROOT_OLD, ROOT_NEW)
    return updated


def node_checks():
    for name in ('server.js', 'live-experience-v5.js', 'live-cases-v4.js'):
        subprocess.run(['node', '--check', str(SRC / name)], check=True)


def status(mode):
    return {
        'stage': 'CIAM_V5_LIVE_EXPERIENCE', 'mode': mode,
        'mainExperience': '/', 'lab': '/lab',
        'clientRoutes': [f'/portal/{b}/{c}' for b in ('aurora', 'brisa') for c in ('web','mobile')],
        'identitySource': 'WSO2_LIVE_BFF_ONLY',
        'remoteWrites': 0,
        'identityFixturesAdded': 0,
        'positiveBrowserEvidence': 'NOT_TESTED'
    }


def main():
    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--apply', action='store_true')
    group.add_argument('--verify', action='store_true')
    args = ap.parse_args()
    expect_files()
    original = SERVER.read_text()
    if args.verify:
        if 'CIAM_V5_RETURNTO' not in original or 'CIAM_V5_LIVE_LAB' not in original:
            refuse('NOT_INSTALLED')
        for path in ('/lab','/experience','/portal/aurora/web','/portal/aurora/mobile',
                     '/portal/brisa/web','/portal/brisa/mobile'):
            if f"'{path}': 'live-experience-v5.html'" not in original:
                refuse('MISSING_ROUTE_' + path)
        node_checks()
        print(json.dumps(status('VERIFY') | {'localSource': 'VERIFIED'}, indent=2))
        return
    updated = make_new(original)
    if args.check:
        node_checks()
        print(json.dumps(status('CHECK') | {'canInstall': True, 'serverSha256': sha(SERVER)}, indent=2))
        return
    backup = SRC / 'server.js.pre-live-experience-v5.bak'
    if backup.exists():
        refuse('BACKUP_ALREADY_EXISTS_STOP')
    # Back up before patch. Atomic replace after changes pass the JS syntax check.
    tmp = SRC / '.server-ciam-v5-pending.js'
    if tmp.exists():
        refuse('TEMPORARY_PATCH_FILE_EXISTS_STOP')
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file:
        file.write(original)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file:
        file.write(updated)
    try:
        subprocess.run(['node', '--check', str(tmp)], check=True)
        os.replace(tmp, SERVER)
        node_checks()
    finally:
        if tmp.exists():
            tmp.unlink()
    readme = ROOT / 'README.md'
    if readme.is_file():
        text = readme.read_text()
        if '<!-- CIAM_V5_LIVE_EXPERIENCE -->' not in text:
            with readme.open('a') as out:
                out.write('\n\n<!-- CIAM_V5_LIVE_EXPERIENCE -->\n'
                  '## Experience Center – WSO2 live (v5)\n\n'
                  'Open `http://127.0.0.1:4400/lab` for the original-style guided lab and '
                  'the four Aurora/Brisa Web/Mobile experiences. Identity and permissions '
                  'are fetched through the live WSO2 BFF, not synthetic persona fixtures. '
                  'See [v5 architecture](docs/CIAM_V5_EXPERIENCE_AND_WSO2_RELATIONSHIPS.md) '
                  'and [v5 instructions](README-LIVE-EXPERIENCE-V5.md). '
                  'Mobile is an OIDC browser preview, not a native app.\n')
    print(json.dumps(status('APPLY') | {'localSource':'INSTALLED',
          'backup':str(backup.relative_to(ROOT)), 'serverSha256':sha(SERVER)}, indent=2))

if __name__ == '__main__':
    main()
