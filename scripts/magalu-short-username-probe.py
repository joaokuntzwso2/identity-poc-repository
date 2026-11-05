#!/usr/bin/env python3
"""Check tenant-local Basic names once; patch v10 Magalu bootstrap only after both GET 200.

This program never reads or prints the administrator passwords outside the
existing private v10 journal loader. It never writes to a running server.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

TENANTS = ('aurora.identity.test', 'brisa.identity.test')


def short_name(username: str, tenant: str) -> str | None:
    """Strip ONLY an exact matching WSO2 tenant suffix, not arbitrary email domains."""
    suffix = '@' + tenant
    if not username.lower().endswith(suffix.lower()):
        return None
    local = username[:-len(suffix)]
    if not local or '@' in local or ':' in local or any(c in local for c in '\r\n'):
        return None
    return local


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def probe(tenant: str, username: str, password: str, ctx) -> int:
    path = f'/t/{tenant}/api/server/v1/applications?limit=30&offset=0'
    token = base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii')
    conn = http.client.HTTPSConnection('localhost', 9444, context=ctx, timeout=6)
    try:
        conn.request('GET', path, headers={
            'Authorization': 'Basic ' + token,
            'Accept': 'application/json',
        })
        result = conn.getresponse()
        body = result.read(8192)
        if result.status == 200:
            # HTTP 200 alone is insufficient: a proxy or login page might
            # respond with HTML instead of the expected management JSON.
            try:
                payload = json.loads(body)
            except (ValueError, UnicodeError):
                raise RuntimeError('unexpected non-JSON management response') from None
            if not isinstance(payload, dict) or not isinstance(payload.get('applications'), list):
                raise RuntimeError('unexpected application-list response contract')
        return result.status
    finally:
        conn.close()


def safe_patch(path: Path) -> str:
    """Only replace known, installed auto-credentials code. No server changes."""
    old = "    return base64.b64encode((username+':'+password).encode()).decode()"
    replacement = (
        "    # Verified by read-only tenant app-management GET: normalize only the exact tenant suffix.\n"
        "    suffix = '@' + tenant\n"
        "    if username.lower().endswith(suffix.lower()):\n"
        "        username = username[:-len(suffix)]\n"
        "    return base64.b64encode((username+':'+password).encode()).decode()"
    )
    text = path.read_text(encoding='utf-8')
    if replacement in text:
        return 'already_patched'
    if text.count(old) != 1 or 'resolve_tenant_owner(home(), tenant)' not in text:
        raise RuntimeError('bootstrap source differs from expected auto-credential loader; no changes')
    update = text.replace(old, replacement)
    compile(update, str(path), 'exec')
    backup = path.with_name('bootstrap.py.before-short-username')
    if backup.exists():
        raise RuntimeError('backup already exists; refusing to overwrite')
    shutil.copy2(path, backup)
    fd, tmpname = tempfile.mkstemp(prefix='.bootstrap-short-', suffix='.py', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            out.write(update)
        os.chmod(tmpname, path.stat().st_mode & 0o777)
        os.replace(tmpname, path)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)
    return 'patched'


def main() -> int:
    root = repo_root()
    src = root / 'deploy/ciam-v10/security'
    if not (root / 'scripts/ciam-v10.sh').exists() or not (src / 'bootstrap.py').exists():
        print('STOP: run this from the verified poc-implementation repository', file=sys.stderr)
        return 2
    sys.path.insert(0, str(src))
    import bootstrap as b
    from credential_store import resolve_tenant_owner
    from trusted_tls import trusted_context

    # Existing bootstrap runtime checks pin the correct v10 Compose instance.
    try:
        b.runtime(b.home())
        ctx = trusted_context(b.home(), b.runtime)
    except Exception as exc:
        print('STOP: existing v10 runtime/TLS validation failed:', type(exc).__name__, file=sys.stderr)
        return 2
    results = []
    for tenant in TENANTS:
        try:
            user, password = resolve_tenant_owner(b.home(), tenant)
            local = short_name(user, tenant)
            if local is None:
                print(f'{tenant}: SKIPPED (stored username is not tenant-qualified)')
                return 2
            status = probe(tenant, local, password, ctx)
            print(f'{tenant}: unqualified username GET HTTP {status}')
            results.append(status)
        except Exception as exc:
            print(f'{tenant}: STOP ({type(exc).__name__})')
            return 2

    if results != [200, 200]:
        print('STOP: at least one tenant did not authorize the short name. Bootstrap unchanged.')
        return 1

    try:
        status = safe_patch(src / 'bootstrap.py')
    except Exception as exc:
        print(f'STOP: safe source patch refused ({type(exc).__name__})')
        return 2
    print(f'Local bootstrap {status}; backed up original file, no WSO2 writes.')
    print('Now run: ./scripts/ciam-magalu-bootstrap.sh plan')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
