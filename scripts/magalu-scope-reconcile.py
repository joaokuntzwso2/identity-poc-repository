#!/usr/bin/env python3
"""Bounded, journaled API authorization reconciliation for existing CIAM v10.

Only uses existing tenant-bound owner records, existing tenant M2M applications,
and WSO2's documented application-management REST endpoints. No credential
creation, password reset, DB edits, or Console actions. All mutations require a
fresh SHA256-approved plan and a verified tenant-owner Basic authority.

Usage: magalu-scope-reconcile.py plan | apply --approve SHA256 | verify

This is not a substitute for a working tenant-admin account: if the persisted
owner password is no longer valid, stop. Never attempt credential variations.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib import parse, request, error

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / 'deploy' / 'ciam-v10' / 'security'
sys.path.insert(0, str(SECURITY))
sys.path.insert(0, str(ROOT / 'scripts'))

import bootstrap as b
from credential_store import resolve_tenant_owner, CredentialError
from trusted_tls import trusted_context, TlsBootstrapError
import management_oauth as oauth
import importlib.util

AUDIT_PATH = ROOT / 'scripts' / 'magalu-scope-audit.py'
TENANTS = ('aurora.identity.test', 'brisa.identity.test')
TARGET = frozenset({
    'internal_application_mgt_view',
    'internal_application_mgt_update',
    'internal_application_script_update',
    'internal_governance_view',
    'internal_governance_update',
})
MAX_BYTES = 2_000_000
MAX_CATALOG = 500
MAX_PAGES = 10
RECORD = 'magalu-scope-reconcile-plan.json'
JOURNAL = 'magalu-scope-reconcile-apply.json'


class Blocked(RuntimeError):
    pass


def canon_user(raw: str, tenant: str) -> str:
    """Convert a tenant-bound journal name to WSO2's canonical login name.

    No cross-tenant name, arbitrary suffix, or guessed admin fallback.
    """
    if tenant not in TENANTS or not isinstance(raw, str) or not raw or ':' in raw or '\n' in raw:
        raise Blocked('OWNER_NAME_INVALID')
    if '@' not in raw:
        return raw + '@' + tenant
    if raw.lower().endswith('@' + tenant) and raw.count('@') == 1:
        return raw
    raise Blocked('OWNER_TENANT_SUFFIX_MISMATCH')


def safe_id(text: str) -> str:
    if not isinstance(text, str) or not re.fullmatch(r'[A-Za-z0-9._~+=-]{1,256}', text):
        raise Blocked('INVALID_SERVER_RESOURCE_ID')
    return text


def hashed(data) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def write_private(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise Blocked('UNSAFE_PRIVATE_JOURNAL_SYMLINK')
    if path.exists():
        raise Blocked('PRIVATE_JOURNAL_ALREADY_EXISTS')
    name = path.with_name(path.name + '.pending-' + str(os.getpid()))
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        os.chmod(path, 0o600)
    finally:
        name.unlink(missing_ok=True)


def read_private(path: Path) -> dict:
    if path.is_symlink():
        raise Blocked('UNSAFE_PRIVATE_JOURNAL_SYMLINK')
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_size > MAX_BYTES:
        raise Blocked('UNSAFE_PRIVATE_JOURNAL')
    return json.loads(path.read_text())


def owner_header(home: Path, tenant: str) -> str:
    # No fallback to carbon.super or any API client secret.
    try:
        username, secret = resolve_tenant_owner(home, tenant)
    except CredentialError:
        raise Blocked('TENANT_OWNER_JOURNAL_MISSING_OR_AMBIGUOUS') from None
    login = canon_user(username, tenant)
    return 'Basic ' + base64.b64encode((login + ':' + secret).encode()).decode()


class OwnerClient:
    """One canonical principal per tenant; no redirects, retries, proxy, or logs."""
    def __init__(self, home: Path, tenant: str, ctx):
        if tenant not in TENANTS:
            raise Blocked('TENANT_NOT_ALLOWED')
        self.tenant = tenant
        self.auth = owner_header(home, tenant)
        self.opener = request.build_opener(request.ProxyHandler({}),
                                           request.HTTPSHandler(context=ctx),
                                           oauth._NoRedirect())

    def call(self, method: str, path: str, body=None):
        if method not in ('GET', 'PATCH', 'POST'):
            raise Blocked('METHOD_NOT_ALLOWED')
        if not path.startswith('/api/server/v1/') or '..' in path or '\n' in path or '#' in path:
            raise Blocked('PATH_NOT_ALLOWED')
        if method == 'GET' and body is not None:
            raise Blocked('GET_BODY_NOT_ALLOWED')
        if method != 'GET' and not isinstance(body, dict):
            raise Blocked('JSON_BODY_REQUIRED')
        data = json.dumps(body, separators=(',', ':')).encode() if body is not None else None
        url = 'https://localhost:9444/t/' + self.tenant + path
        req = request.Request(url, data=data, method=method,
                              headers={'Authorization': self.auth,
                                       'Accept': 'application/json',
                                       **({'Content-Type': 'application/json'} if data else {})})
        try:
            with self.opener.open(req, timeout=6) as response:
                raw = response.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise Blocked('RESPONSE_TOO_LARGE')
                if method == 'GET' and not raw:
                    raise Blocked('UNEXPECTED_EMPTY_READBACK')
                if not raw:
                    return {}
                try:
                    return json.loads(raw)
                except ValueError:
                    raise Blocked('INVALID_JSON_RESPONSE') from None
        except error.HTTPError as exc:
            # Do not report response body; never retry failed owner logins.
            raise Blocked('HTTP_' + str(exc.code)) from None
        except (error.URLError, TimeoutError, OSError):
            raise Blocked('OWNER_API_NETWORK_OR_TLS_ERROR') from None


def parse_auth_rows(body):
    if isinstance(body, list):
        rows = body
    elif isinstance(body, dict) and isinstance(body.get('authorizedAPIs'), list):
        rows = body['authorizedAPIs']
    else:
        raise Blocked('AUTHORIZATION_LIST_FORMAT_CHANGED')
    if len(rows) > 250:
        raise Blocked('EXCESSIVE_AUTHORIZATION_LIST')
    found = {}
    for row in rows:
        if not isinstance(row, dict):
            raise Blocked('AUTHORIZATION_ROW_INVALID')
        resource = safe_id(row.get('id'))
        if resource in found:
            raise Blocked('DUPLICATE_AUTHORIZATION_RESOURCE')
        scopes = row.get('authorizedScopes')
        if not isinstance(scopes, list):
            raise Blocked('AUTHORIZED_SCOPES_FORMAT_CHANGED')
        parsed = set()
        for s in scopes:
            if not isinstance(s, dict) or not isinstance(s.get('name'), str):
                raise Blocked('AUTHORIZED_SCOPE_INVALID')
            parsed.add(s['name'])
        found[resource] = parsed
    return found


def _catalog_next(href: str, tenant: str | None):
    """Parse, but NEVER follow, a WSO2 pagination link.

    Requests are reconstructed against OwnerClient's pinned https://localhost:9444
    origin and selected tenant. Accept the GA server's absolute loopback links,
    including its internal 9443 port, only after explicit origin/path validation.
    """
    if not isinstance(href, str) or not href or len(href) > 2048 or any(ord(c) < 32 for c in href):
        raise Blocked('CATALOG_LINK_INVALID')
    try:
        url = parse.urlsplit(href)
        if url.fragment or url.username is not None or url.password is not None:
            raise Blocked('CATALOG_LINK_UNSAFE')
        if url.scheme or url.netloc:
            if (url.scheme != 'https' or url.hostname not in ('localhost', '127.0.0.1')
                    or url.port not in (9443, 9444) or not url.netloc):
                raise Blocked('CATALOG_LINK_UNSAFE')
        allowed_paths = ['/api/server/v1/api-resources']
        if tenant is not None:
            if tenant not in TENANTS:
                raise Blocked('TENANT_NOT_ALLOWED')
            allowed_paths.append('/t/' + tenant + '/api/server/v1/api-resources')
        # No path normalization, percent-decoding or path traversal permitted.
        # A query-only relative reference ("?after=...") is also valid.
        if url.path not in allowed_paths and (url.path != '' or bool(url.scheme or url.netloc)):
            raise Blocked('CATALOG_LINK_UNSAFE')
        query = parse.parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
        if not query or set(query) - {'after', 'offset', 'limit'}:
            raise Blocked('CATALOG_QUERY_UNSAFE')
        if any(len(values) != 1 for values in query.values()):
            raise Blocked('CATALOG_QUERY_AMBIGUOUS')
        if 'limit' in query:
            limit = query['limit'][0]
            if not limit.isdecimal() or not (1 <= int(limit) <= 100):
                raise Blocked('CATALOG_QUERY_LIMIT_INVALID')
        if ('after' in query) == ('offset' in query):
            raise Blocked('CATALOG_PAGINATION_UNRECOGNIZED')
        if 'after' in query:
            cursor = query['after'][0]
            if not cursor or len(cursor) > 128 or not re.fullmatch(r'[A-Za-z0-9._~+/=-]+', cursor):
                raise Blocked('CATALOG_CURSOR_INVALID')
            return cursor
        offset = query['offset'][0]
        if not offset.isdecimal() or int(offset) < 1 or int(offset) > MAX_CATALOG:
            raise Blocked('CATALOG_OFFSET_INVALID')
        return ('offset', int(offset))
    except (ValueError, UnicodeError):
        raise Blocked('CATALOG_LINK_UNSAFE') from None


def parse_catalog_page(doc, tenant=None):
    # Observed GA response uses apiResources; published examples sometimes use APIResources.
    if not isinstance(doc, dict):
        raise Blocked('CATALOG_FORMAT_CHANGED')
    keys = [key for key in ('apiResources', 'APIResources') if key in doc]
    if len(keys) != 1 or not isinstance(doc[keys[0]], list):
        raise Blocked('CATALOG_FORMAT_CHANGED')
    items = doc[keys[0]]
    if len(items) > 100:
        raise Blocked('CATALOG_PAGE_TOO_LARGE')
    total = doc.get('totalResults')
    if total is not None and (type(total) is not int or total < 0 or total > MAX_CATALOG):
        raise Blocked('CATALOG_TOTAL_INVALID')
    links = doc.get('links', [])
    if not isinstance(links, list) or len(links) > 20:
        raise Blocked('CATALOG_LINKS_INVALID')
    next_cursor = None
    for link in links:
        if not isinstance(link, dict) or not isinstance(link.get('rel'), str):
            raise Blocked('CATALOG_LINK_INVALID')
        # Only next/after links are consumed. Some older WSO2 examples label
        # after-bearing links 'before'; retain support for that observed test form.
        rel = link['rel'].lower()
        if rel in ('next', 'after', 'before'):
            candidate = _catalog_next(link.get('href'), tenant)
            if rel == 'before' and isinstance(candidate, tuple):
                # Never traverse backwards through offset pagination.
                continue
            if next_cursor is not None:
                raise Blocked('CATALOG_DUPLICATE_NEXT_LINK')
            next_cursor = candidate
    return items, total, next_cursor


def catalog(client: OwnerClient):
    records = {}
    seen = set()
    cursor = None
    total = None
    for page in range(MAX_PAGES):
        path = '/api/server/v1/api-resources?limit=100'
        if cursor is not None:
            if isinstance(cursor, tuple) and cursor[0] == 'offset':
                path += '&offset=' + str(cursor[1])
            elif isinstance(cursor, str):
                path += '&after=' + parse.quote(cursor, safe='')
            else:
                raise Blocked('CATALOG_CURSOR_INVALID')
        items, reported, after = parse_catalog_page(client.call('GET', path), getattr(client, 'tenant', None))
        if reported is not None:
            if total is not None and reported != total:
                raise Blocked('CATALOG_CHANGED_DURING_READ')
            total = reported
        for item in items:
            if not isinstance(item, dict):
                raise Blocked('CATALOG_RESOURCE_INVALID')
            rid = safe_id(item.get('id'))
            if rid in records:
                raise Blocked('CATALOG_DUPLICATE_RESOURCE')
            records[rid] = item
            if len(records) > MAX_CATALOG:
                raise Blocked('CATALOG_TOO_LARGE')
        if total is not None and len(records) >= total:
            return records
        if not after:
            if total is not None and len(records) != total:
                raise Blocked('CATALOG_INCOMPLETE_WITHOUT_CURSOR')
            return records
        if after in seen:
            raise Blocked('CATALOG_REPEATED_CURSOR')
        seen.add(after)
        cursor = after
    raise Blocked('CATALOG_PAGINATION_LIMIT')


def locate_scopes(client: OwnerClient, resources):
    found = {}
    for rid, row in resources.items():
        # Management, system, or tenant platform API only. Never authorize a
        # similarly named custom BUSINESS API or unknown resource classification.
        if row.get('type') not in ('MANAGEMENT', 'SYSTEM', 'TENANT'):
            continue
        # API resource object may or may not contain full scope names. Fetch
        # exact GET detail, not names or IDs inferred from display text.
        detail = client.call('GET', '/api/server/v1/api-resources/' + parse.quote(rid, safe=''))
        if not isinstance(detail, dict) or detail.get('id') != rid:
            raise Blocked('CATALOG_RESOURCE_READBACK_MISMATCH')
        if detail.get('type') != row.get('type'):
            raise Blocked('CATALOG_RESOURCE_TYPE_CHANGED')
        scoped = detail.get('scopes')
        if not isinstance(scoped, list):
            raise Blocked('CATALOG_RESOURCE_SCOPES_CHANGED')
        for ent in scoped:
            if not isinstance(ent, dict):
                raise Blocked('CATALOG_SCOPE_INVALID')
            n = ent.get('name')
            if n in TARGET:
                if n in found:
                    raise Blocked('TARGET_SCOPE_AMBIGUOUS_IN_CATALOG')
                found[n] = rid
    if set(found) != TARGET:
        raise Blocked('REQUIRED_SCOPES_MISSING_FROM_GA_CATALOG')
    return found


def plan_tenant(client: OwnerClient, manager: str, scope_ids):
    path = '/api/server/v1/applications/' + parse.quote(safe_id(manager), safe='') + '/authorized-apis'
    current = parse_auth_rows(client.call('GET', path))
    grouped = {}
    for name, rid in scope_ids.items():
        grouped.setdefault(rid, set()).add(name)
    operations = []
    for rid, needed in sorted(grouped.items()):
        missing = needed - current.get(rid, set())
        if missing:
            operations.append({'api_resource_id': rid,
                               'method': 'PATCH' if rid in current else 'POST',
                               'added_scopes': sorted(missing)})
    return {'manager_app_id': manager,
            'before_authorizations_sha256': hashed({rid: sorted(scopes) for rid, scopes in current.items()}),
            'operations': operations}


def fetch_snapshot(home: Path, rt: dict, ctx):
    if not AUDIT_PATH.exists():
        raise Blocked('SCOPE_AUDIT_V2_NOT_INSTALLED')
    spec = importlib.util.spec_from_file_location('magalu_scope_audit', AUDIT_PATH)
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    out = {'format': 1, 'runtime_image_id': rt['image_id'], 'tenants': {}}
    for tenant in TENANTS:
        client = OwnerClient(home, tenant, ctx)
        # First request tests exactly one canonical owner identity; no retries.
        client.call('GET', '/api/server/v1/applications?limit=1')
        m2m_cid, _ = oauth._management(home, tenant)
        manager = audit._find_manager(home, ctx, tenant, m2m_cid)
        resources = catalog(client)
        scope_ids = locate_scopes(client, resources)
        out['tenants'][tenant] = plan_tenant(client, manager, scope_ids)
    return out


def verified_readback(client, manager, expected):
    path = '/api/server/v1/applications/' + parse.quote(safe_id(manager), safe='') + '/authorized-apis'
    rows = parse_auth_rows(client.call('GET', path))
    for op in expected:
        if not set(op['added_scopes']).issubset(rows.get(op['api_resource_id'], set())):
            raise Blocked('GRANT_WRITE_READBACK_MISSING')


def patch_one(client, manager, op):
    app_path = '/api/server/v1/applications/' + parse.quote(safe_id(manager), safe='') + '/authorized-apis'
    rid = safe_id(op['api_resource_id'])
    scopes = op['added_scopes']
    if not isinstance(scopes, list) or not scopes or not set(scopes).issubset(TARGET):
        raise Blocked('INVALID_SCOPE_PATCH_PLAN')
    if op['method'] == 'PATCH':
        client.call('PATCH', app_path + '/' + parse.quote(rid, safe=''),
                    {'addedScopes': scopes, 'removedScopes': []})
    elif op['method'] == 'POST':
        client.call('POST', app_path, {'id': rid, 'policyIdentifier': 'RBAC', 'scopes': scopes})
    else:
        raise Blocked('INVALID_PATCH_METHOD')
    verified_readback(client, manager, [op])


def do_plan():
    home = b.home(); rt = b.runtime(home)
    ctx = trusted_context(home, b.runtime)
    payload = fetch_snapshot(home, rt, ctx)
    digest = hashed(payload)
    path = home / 'private' / RECORD
    data = {'digest': digest, 'snapshot': payload}
    if path.exists():
        if read_private(path) != data:
            raise Blocked('EXISTING_GRANT_PLAN_DIFFERS_DELETE_ONLY_AFTER_REVIEW')
    else:
        write_private(path, data)
    redacted = {t: {'added_scope_names': sorted({s for op in entry['operations'] for s in op['added_scopes']}),
                    'operations': len(entry['operations'])} for t, entry in payload['tenants'].items()}
    print(json.dumps({'evidence': 'LIVE_READBACK_ONLY_NO_WRITES', 'approval_sha256': digest,
                      'tenants': redacted}, indent=2, sort_keys=True))


def do_apply(approve: str):
    home = b.home(); rt = b.runtime(home)
    ctx = trusted_context(home, b.runtime)
    plan_path = home / 'private' / RECORD
    journal_path = home / 'private' / JOURNAL
    if journal_path.exists():
        raise Blocked('PREVIOUS_GRANT_APPLY_EXISTS_REFUSE_AUTOMATIC_RETRY')
    plan = read_private(plan_path)
    if not re.fullmatch(r'[a-f0-9]{64}', approve or ''):
        raise Blocked('APPROVAL_HASH_REQUIRED')
    if not hmac.compare_digest(plan.get('digest', ''), approve):
        raise Blocked('APPROVAL_HASH_MISMATCH')
    fresh = fetch_snapshot(home, rt, ctx)
    if not hmac.compare_digest(hashed(fresh), approve):
        raise Blocked('LIVE_AUTHORIZATION_DRIFT_STOP')
    # Journal BEFORE first network write. Failure is never automatically retried.
    write_private(journal_path, {'plan_digest': approve,
                                 'phase': 'WRITE_IN_PROGRESS', 'created_epoch': int(time.time()),
                                 'operations_per_tenant': {t: len(v['operations']) for t, v in fresh['tenants'].items()}})
    for tenant in TENANTS:
        client = OwnerClient(home, tenant, ctx)
        entry = fresh['tenants'][tenant]
        for op in entry['operations']:
            patch_one(client, entry['manager_app_id'], op)
    print(json.dumps({'evidence': 'LIVE_AUTHORIZATION_WRITTEN_AND_READBACK',
                      'tenants': list(TENANTS),
                      'next': 'Run magalu-scope-audit.py, then Magalu auth-check and plan'}, indent=2))


def do_verify():
    import importlib.util
    if not AUDIT_PATH.exists():
        raise Blocked('SCOPE_AUDIT_V2_NOT_INSTALLED')
    spec = importlib.util.spec_from_file_location('scope_verify', AUDIT_PATH)
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    home = b.home(); b.runtime(home)
    ctx = trusted_context(home, b.runtime)
    for tenant in TENANTS:
        result = audit.audit_tenant(home, ctx, tenant)
        if not result.get('all_required_granted'):
            raise Blocked('OAUTH_MANAGEMENT_SCOPES_STILL_MISSING_' + tenant)
    print(json.dumps({'evidence': 'LIVE_WSO2_MANAGEMENT_SCOPE_READBACK',
                      'tenants': list(TENANTS), 'all_required_granted': True}, indent=2))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('command', choices=['plan', 'apply', 'verify'])
    p.add_argument('--approve')
    args = p.parse_args()
    try:
        if args.command == 'plan': do_plan()
        elif args.command == 'apply': do_apply(args.approve)
        else: do_verify()
    except (Blocked, b.GuardError, oauth.OAuthBlocked, TlsBootstrapError) as exc:
        # Fixed diagnostic codes only: no response bodies, user info or secrets.
        text = str(exc)
        if text.startswith('HTTP_'):
            text = 'TENANT_OWNER_AUTH_OR_AUTHORIZATION_' + text
        elif not re.fullmatch(r'[A-Z0-9_]+(?:_[a-z.]+)?', text):
            text = type(exc).__name__
        print('SCOPE_RECONCILE_BLOCKED:', text, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
