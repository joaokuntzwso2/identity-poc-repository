#!/usr/bin/env python3
"""Read-only WSO2 pagination-link shape diagnostic. No links, credentials, or tokens printed."""
import importlib.util
import json
from pathlib import Path
from urllib import parse

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / 'scripts' / 'magalu-scope-reconcile.py'
spec = importlib.util.spec_from_file_location('magalu_scope_reconcile_link_probe', P)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def shape(href, tenant):
    if not isinstance(href, str):
        return {'value_type': type(href).__name__}
    url = parse.urlsplit(href)
    expected_paths = ('/api/server/v1/api-resources',
                      '/t/' + tenant + '/api/server/v1/api-resources')
    host = url.hostname
    try:
        port = url.port
    except ValueError:
        port = -1
    keys = sorted(parse.parse_qs(url.query, keep_blank_values=True).keys())
    return {'absolute': bool(url.scheme or url.netloc),
            'scheme': 'https' if url.scheme == 'https' else ('relative' if not url.scheme else 'other'),
            'host_category': 'loopback' if host in ('localhost', '127.0.0.1') else ('none' if host is None else 'other'),
            'port_category': str(port) if port in (9443, 9444) else ('absent' if port is None else 'other'),
            'path_category': 'allowed' if url.path in expected_paths else ('query-only' if not url.path else 'other'),
            'query_keys': keys[:10],
            'fragment_present': bool(url.fragment)}


def main():
    home = m.b.home()
    m.b.runtime(home)
    ctx = m.trusted_context(home, m.b.runtime)
    out = {'evidence': 'LIVE_READ_ONLY_LINK_SHAPES_NO_LINK_VALUES', 'tenants': {}}
    for tenant in m.TENANTS:
        client = m.OwnerClient(home, tenant, ctx)
        doc = client.call('GET', '/api/server/v1/api-resources?limit=100')
        links = doc.get('links', []) if isinstance(doc, dict) else []
        if not isinstance(links, list) or len(links) > 20:
            raise m.Blocked('CATALOG_LINKS_INVALID')
        out['tenants'][tenant] = [
            {'rel': (link.get('rel') if link.get('rel') in ('next','after','before','previous','self') else 'other'),
             **shape(link.get('href'), tenant)} for link in links if isinstance(link, dict)
        ]
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (m.Blocked, m.b.GuardError, m.TlsBootstrapError) as exc:
        print('CATALOG_SHAPE_BLOCKED:', type(exc).__name__)
        raise SystemExit(2)
