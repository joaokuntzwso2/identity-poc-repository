#!/usr/bin/env python3
"""Read-only local diagnostic: compare BFF OIDC clients with WSO2 PostgreSQL registrations.

Run from the identity-poc-repository root. No credentials, tokens, or secrets are logged.
This script makes only HTTPS GET requests, reads BFF config, and runs read-only SELECTs
on the local Docker PostgreSQL container. It NEVER updates WSO2 or source files.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

EXPECTED = ('aurora-web', 'aurora-app', 'brisa-web', 'brisa-app')
DATABASE_CONTAINER = os.environ.get('WSO2_AUDIT_DB_CONTAINER', 'wso2-ciam-v10-postgres-1')
SERVER_BASE = 'https://localhost:9444'
PUBLIC_ORIGIN = 'http://127.0.0.1:4400'
CERT = Path.home() / '.config/ciam/wso2-local.pem'


def run(args, *, env=None, timeout=20):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f'command unavailable or timed out: {args[0]} ({type(exc).__name__})') from exc
    if result.returncode != 0:
        # Avoid echoing command content, credentials, access tokens or private paths.
        first = (result.stderr.strip() or result.stdout.strip()).splitlines()
        detail = first[-1] if first else 'no diagnostic detail'
        if len(detail) > 150:
            detail = detail[:150] + '...'
        raise RuntimeError(f'{args[0]} returned {result.returncode}: {detail}')
    return result.stdout


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]


def load_configured_clients():
    js = '''import {clients} from './services/identity-bff/src/config.js';
const keys=['aurora-web','aurora-app','brisa-web','brisa-app'];
console.log(JSON.stringify(Object.fromEntries(keys.map(k=>[k,{clientId:clients[k]?.clientId,issuer:clients[k]?.issuer,redirectUri:clients[k]?.redirectUri}]))));'''
    env = os.environ.copy()
    env.update(IDENTITY_MODE='live-wso2', ALLOW_INSECURE_LOCAL='true', PUBLIC_ORIGIN=PUBLIC_ORIGIN, WSO2_BFF_PRIVATE_MANIFEST='var/wso2/identity-bff-v10.private.json')
    data = json.loads(run(['node', '--input-type=module', '-e', js], env=env, timeout=15))
    for key in EXPECTED:
        entry = data.get(key)
        if not isinstance(entry, dict) or not all(isinstance(entry.get(x), str) and entry[x] for x in ('clientId', 'issuer', 'redirectUri')):
            raise RuntimeError(f'incomplete local client settings: {key}')
    return data


def discover(tenant, expected_issuer, ctx):
    url = f'{SERVER_BASE}/t/{tenant}/oauth2/oidcdiscovery/.well-known/openid-configuration'
    with urllib.request.urlopen(url, context=ctx, timeout=8) as response:
        data = json.load(response)
    issuer = data.get('issuer')
    return issuer == expected_issuer, issuer


# Executes entirely inside PostgreSQL container, with transaction-level READ ONLY.
# Neither the SQL nor credentials are printed. No external Python libraries needed.
SQL_SHELL = '''set -eu
export PGPASSWORD="${POSTGRES_PASSWORD:-}"
export PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=5000'
db="$1"; sql="$2"
exec psql -X -v ON_ERROR_STOP=1 -qAt -F '|' -U "${POSTGRES_USER:-postgres}" -d "$db" -c "$sql"'''


def select_sql(database, statement):
    if not statement.lstrip().upper().startswith('SELECT '):
        raise RuntimeError('Non-SELECT SQL blocked')
    # psql connection enforces default_transaction_read_only=on.
    raw = run(['docker', 'exec', DATABASE_CONTAINER, 'sh', '-c', SQL_SHELL, 'sh', database, statement], timeout=20)
    return [line.split('|') for line in raw.splitlines() if line.strip()]


def quote_identifier(s):
    return '"' + s.replace('"', '""') + '"'


def list_tables(db):
    return select_sql(db, "SELECT table_schema, table_name FROM information_schema.tables WHERE lower(table_name) IN ('idn_oauth_consumer_apps','um_tenant') AND table_type='BASE TABLE' ORDER BY table_schema,table_name")


def table_columns(db, schema, table):
    q = lambda s: "'" + s.replace("'", "''") + "'"
    return [x[0].lower() for x in select_sql(db, f"SELECT column_name FROM information_schema.columns WHERE table_schema={q(schema)} AND table_name={q(table)}")]


def select_table(db, schema, table, cols):
    lookup = {s.lower(): s for s in cols}
    actual = [lookup[key] for key in ('consumer_key','tenant_id','app_name') if key in lookup]
    if 'consumer_key' not in lookup:
        return []
    # Return only allowed fields, NEVER consumer_secret.
    projection = ', '.join(quote_identifier(s) for s in actual)
    sql = f'SELECT {projection} FROM {quote_identifier(schema)}.{quote_identifier(table)} LIMIT 20000'
    rows = select_sql(db, sql)
    result = []
    for row in rows:
        mapped = dict(zip([x.lower() for x in actual], row))
        if mapped.get('consumer_key'):
            result.append(mapped)
    return result


def tenants_in_table(db, schema, table, cols):
    names = {x.lower(): x for x in cols}
    key = 'um_id' if 'um_id' in names else None
    domain = 'um_domain_name' if 'um_domain_name' in names else None
    if not key or not domain:
        return {}
    sql = f'SELECT {quote_identifier(names[key])}, {quote_identifier(names[domain])} FROM {quote_identifier(schema)}.{quote_identifier(table)} LIMIT 5000'
    return {row[0]: row[1] for row in select_sql(db, sql) if len(row) == 2}


def audit_db():
    if not shutil.which('docker'):
        raise RuntimeError('Docker CLI unavailable')
    # docker inspect does not read or reveal DB passwords.
    status = run(['docker', 'inspect', '--format', '{{.State.Running}}', DATABASE_CONTAINER], timeout=8).strip()
    if status != 'true':
        raise RuntimeError('PostgreSQL container is not running')
    dbs = [row[0] for row in select_sql('postgres', 'SELECT datname FROM pg_database WHERE datallowconn=true AND datistemplate=false ORDER BY datname')]
    records, mappings, locations = [], {}, []
    for db in dbs:
        try:
            tables = list_tables(db)
        except RuntimeError as exc:
            print(f'  {db}: cannot inspect ({exc})')
            continue
        for schema, table in tables:
            cols = table_columns(db, schema, table)
            if table.lower() == 'um_tenant':
                mappings.update(tenants_in_table(db, schema, table, cols))
            elif table.lower() == 'idn_oauth_consumer_apps':
                rows = select_table(db, schema, table, cols)
                for row in rows:
                    row['database'] = db
                    records.append(row)
                locations.append(f'{db}.{schema}.{table} ({len(rows)} registrations)')
    return records, mappings, locations


def main():
    print('WSO2 7.x four-client registration audit — READ ONLY')
    print(f'BFF public origin: {PUBLIC_ORIGIN}')
    print('Secrets, tokens and full client IDs: not printed')
    if not Path('services/identity-bff/src/config.js').exists():
        print('ERROR: Run from your identity-poc-repository root')
        return 2
    try:
        configured = load_configured_clients()
    except Exception as exc:
        print(f'ERROR loading BFF client configuration: {exc}')
        return 2
    print('\nEffective BFF client IDs (SHA-256 prefix only):')
    for key in EXPECTED:
        c = configured[key]
        print(f'  {key:11s} id_sha256={digest(c["clientId"])} issuer={c["issuer"]}')
    print('\nOIDC discovery (verified HTTPS, no insecure TLS fallback):')
    discovery_ok = True
    if not CERT.is_file():
        discovery_ok = False
        print(f'  ERROR: CA file not found: {CERT}')
    else:
        try:
            context = ssl.create_default_context(cafile=str(CERT))
            for tenant in ('aurora.identity.test', 'brisa.identity.test'):
                key = 'aurora-web' if tenant.startswith('aurora') else 'brisa-web'
                try:
                    match, advertised = discover(tenant, configured[key]['issuer'], context)
                    print(f'  {tenant}: {"PASS issuer matches" if match else "FAIL issuer mismatch"}')
                    if not match:
                        discovery_ok = False
                        print(f'    advertised: {advertised}')
                except Exception as exc:
                    discovery_ok = False
                    print(f'  {tenant}: ERROR {type(exc).__name__}: {str(exc)[:160]}')
        except Exception as exc:
            discovery_ok = False
            print(f'  CA setup failed: {type(exc).__name__}: {str(exc)[:160]}')
    print('\nLocal WSO2 registration database (SELECT only):')
    try:
        records, tenant_map, locations = audit_db()
    except Exception as exc:
        print(f'  ERROR: {exc}')
        print('  No registrations verified. No modifications made.')
        return 3
    if not locations:
        print('  ERROR: No IDN_OAUTH_CONSUMER_APPS table found in accessible databases.')
        return 3
    for location in locations:
        print(f'  source: {location}')
    missing = []
    mismatches = []
    found = []
    for key in EXPECTED:
        c = configured[key]
        hits = [r for r in records if r['consumer_key'] == c['clientId']]
        if not hits:
            missing.append(key)
            print(f'  {key:11s} MISSING: configured client ID not present in inspected WSO2 DB')
            continue
        found.append(key)
        for h in hits:
            tid = h.get('tenant_id', '?')
            domain = tenant_map.get(tid, 'tenant domain not available')
            app = h.get('app_name', 'application name unavailable')
            print(f'  {key:11s} PRESENT: application={app!r} tenant_id={tid} tenant={domain}')
            expected_tenant = 'aurora.identity.test' if key.startswith('aurora') else 'brisa.identity.test'
            if domain != expected_tenant:
                mismatches.append(key)
                print(f'    ERROR: expected tenant {expected_tenant}; tenant cannot be attested')
    print('\nSummary:')
    if missing:
        print('  Configured client IDs missing: ' + ', '.join(missing))
        print('  The BFF private manifest may contain stale IDs, or the applications may not have been provisioned in this WSO2 instance.')
        print('  Do not guess IDs or modify WSO2 grants; reconcile registrations from the original provisioning source.')
    else:
        print('  Four configured client IDs found. If login still fails, investigate tenant association and runtime app loading.')
    print('  No code, database, manifest, registration or permission changes were made.')
    if mismatches: print('  Tenant binding mismatch: ' + ', '.join(sorted(set(mismatches))))
    if not discovery_ok: print('  OIDC discovery not verified under trusted TLS')
    return 1 if missing or mismatches or not discovery_ok else 0

if __name__ == '__main__':
    sys.exit(main())
