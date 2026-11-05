#!/usr/bin/env python3
"""Idempotent, source-guarded local fix for Magalu WSO2 management OAuth.

No live WSO2 requests or mutations; only edits the known Magalu overlay files.
It will not modify the existing v10 owner credential store or M2M app grants.
"""
import ast
import os
from pathlib import Path
import shutil
import sys

REPO = Path(__file__).resolve().parents[1]
BOOT = REPO / 'deploy/ciam-v10/security/bootstrap.py'
WRAPPER = REPO / 'scripts/ciam-magalu-bootstrap.sh'
DISPATCH = REPO / 'scripts/ciam-v10-security.sh'

NEW_REQUEST = '''def request(tenant, path, method='GET', body=None):
    # Use the v10 tenant M2M client, not 401-rejected tenant-owner Basic auth.
    # All scopes are explicitly requested and validated before use.
    if tenant not in BRANDS:
        raise GuardError('unsupported tenant')
    from management_oauth import OAuthBlocked, management_request
    from trusted_tls import trusted_context, TlsBootstrapError
    try:
        ctx = trusted_context(home(), runtime)
        return management_request(home(), tenant, path, method, body, context=ctx)
    except (OAuthBlocked, TlsBootstrapError) as ex:
        raise GuardError('management OAuth blocked: ' + tenant + ' ' + method + ' ' +
                         path.split('?')[0] + ' (' + str(ex) + ')') from None
'''

NEW_CHECK = '''def do_auth_check():
    # Fully non-mutating remote management check; OAuth tokens stay in memory.
    # No username/password variants, invalid login retries, or privilege grants.
    p = home()
    rt = runtime(p)
    result = {'evidence': 'LIVE_MANAGEMENT_READ_ONLY', 'image_id': rt['image_id'], 'tenants': {}}
    for tenant in BRANDS:
        item = {}
        for key, path in (
            ('application_view', '/api/server/v1/applications?limit=1'),
            ('governance_view', '/api/server/v1/identity-governance/'),
        ):
            try:
                request(tenant, path)
                item[key] = 'HTTP_200'
            except GuardError as exc:
                text = str(exc)
                import re
                match = re.search(r'\(([A-Z0-9_]+)\)\s*$', text)
                code = match.group(1) if match else 'BLOCKED'
                item[key] = code
        result['tenants'][tenant] = item
    result['ready_for_plan'] = all(
        entry['application_view'] == 'HTTP_200' and entry['governance_view'] == 'HTTP_200'
        for entry in result['tenants'].values())
    print(json.dumps(result, indent=2))
    if not result['ready_for_plan']:
        raise GuardError('at least one tenant M2M client lacks management read permission')
'''


def replace_function(text, name, replacement):
    tree = ast.parse(text)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise RuntimeError(f'expected exactly one {name}() function')
    node = nodes[0]
    lines = text.splitlines(keepends=True)
    old = ''.join(lines[node.lineno - 1:node.end_lineno])
    if name == 'request':
        if "'Authorization':'Basic '+admin(tenant)" not in old:
            if 'management_request(home(), tenant' in old:
                return text
            raise RuntimeError('unexpected request() version; refuse unreviewed edit')
    return ''.join(lines[:node.lineno - 1]) + replacement.rstrip() + '\n' + ''.join(lines[node.end_lineno:])


def patch_source(text):
    if "'auth-check'" in text and 'management_request(home(), tenant' in text:
        return text
    if 'def do_auth_check():' in text or 'management_request(home(), tenant' in text:
        raise RuntimeError('partially installed OAuth patch; refuse unsafe repeat')
    if 'from credential_store import CredentialError, resolve_tenant_owner' not in text:
        raise RuntimeError('auto-credentials prerequisite not installed; source unexpected')
    text = replace_function(text, 'request', NEW_REQUEST)
    anchor = 'def do_inventory():\n'
    if text.count(anchor) != 1:
        raise RuntimeError('inventory insertion anchor missing')
    text = text.replace(anchor, NEW_CHECK + '\n\n' + anchor, 1)
    original = "    files += [HERE/'application_sequences.py', HERE/'governance.py', HERE/'bootstrap.py', HERE/'credential_store.py', HERE/'trusted_tls.py', EXT/'build-extension.sh']"
    amended = original.replace("HERE/'trusted_tls.py',", "HERE/'trusted_tls.py', HERE/'management_oauth.py',")
    if text.count(original) != 1:
        raise RuntimeError('source fingerprint anchor not found')
    text = text.replace(original, amended, 1)
    build = '    jar_sha=build_from_running_ga(rt)'
    if text.count(build) != 1:
        raise RuntimeError('apply preflight anchor missing')
    guard = '''    # Fail before any runtime write if existing tenant M2M clients cannot
    # obtain and prove the exact application/governance write scopes.
    from management_oauth import OAuthBlocked, preflight_write_scopes
    from trusted_tls import trusted_context
    ctx = trusted_context(p, runtime)
    try:
        for tenant in BRANDS:
            preflight_write_scopes(p, tenant, ctx)
    except OAuthBlocked as ex:
        raise GuardError('M2M_WRITE_CAPABILITY_BLOCKED (' + str(ex) + ')') from None
'''
    text = text.replace(build, guard + build, 1)
    oldchoices = "choices=['inventory','plan','apply','verify','rollback']"
    if text.count(oldchoices) != 1:
        raise RuntimeError('CLI command choices anchor missing')
    text = text.replace(oldchoices, "choices=['inventory','plan','apply','verify','rollback','auth-check']", 1)
    oldbranch = "        if a.command=='inventory': do_inventory()"
    if text.count(oldbranch) != 1:
        raise RuntimeError('CLI dispatcher anchor missing')
    text = text.replace(oldbranch, "        if a.command=='auth-check': do_auth_check()\n" + oldbranch, 1)
    compile(text, 'bootstrap.py', 'exec')
    return text


def patch_wrapper(text):
    old = '  inventory|plan|verify)'
    new = '  inventory|plan|verify|auth-check)'
    if old in text and new not in text:
        return text.replace(old, new, 1)
    if new in text:
        return text
    raise RuntimeError('unfamiliar Magalu bootstrap wrapper')


def patch_dispatch(text):
    old = '  security-inventory) action=inventory ;;'
    new = old + '\n  security-auth-check) action=auth-check ;;'
    if new in text:
        return text
    if text.count(old) != 1:
        raise RuntimeError('unfamiliar security dispatcher')
    return text.replace(old, new, 1)


def main():
    helper = REPO / 'deploy/ciam-v10/security/management_oauth.py'
    if not helper.is_file():
        raise RuntimeError('management_oauth.py missing; extract patch files first')
    changes = [(BOOT, patch_source), (WRAPPER, patch_wrapper), (DISPATCH, patch_dispatch)]
    prepared = []
    for dest, transform in changes:
        before = dest.read_text()
        after = transform(before)
        if before != after:
            backup = dest.with_name(dest.name + '.before-m2m-oauth')
            if backup.exists():
                raise RuntimeError(f'existing backup prevents repeat: {backup.name}')
            prepared.append((dest, backup, after))
    for dest, backup, content in prepared:
        shutil.copy2(dest, backup)
        tmp = dest.with_name(dest.name + '.oauth-tmp')
        try:
            tmp.write_text(content)
            os.chmod(tmp, dest.stat().st_mode & 0o777)
            os.replace(tmp, dest)
        finally:
            tmp.unlink(missing_ok=True)
        print(f'PATCHED {dest.relative_to(REPO)}')
    print('OAuth client wired. No WSO2 API writes, restart, or credential changes.')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('PATCH_BLOCKED:', str(e), file=sys.stderr)
        sys.exit(2)
