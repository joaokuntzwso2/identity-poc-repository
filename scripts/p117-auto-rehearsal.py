#!/usr/bin/env python3
"""P1.17 migration rehearsal: discover registered issuers, audit DB/snapshot, optional guarded import.

Does not read client secrets into output, change WSO2, run activation, or create a DB.
Avoids executing repository config or downloading anything. Fail closed when source is ambiguous.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import shutil
from urllib.parse import urlsplit, unquote

BRANDS = ('aurora', 'brisa')
EXPECTED_DB = ('127.0.0.1', 55434, 'ciam_migration_rehearsal_test', 'p117_migration_owner')
EXPECTED_FINGERPRINT = '33389b5d122b6e0dee086f0571c6681007cdf0743a83b5aaf84d9482c5709579'
EXPECTED_SCHEMA_SHA = 'da5c4dd3e5893fc5ee058b9f9b2db2c44a9993123ff2e0289ca6aba6ccafab3c'
MAX_FILES = 1000
EXPLICIT_PATH_VARS = (
 'CIAM_CLIENTS_MANIFEST', 'CIAM_CLIENTS_MANIFEST_PATH', 'CIAM_CLIENTS_CONFIG_FILE',
 'CIAM_CLIENT_MANIFEST_PATH', 'CIAM_CLIENT_REGISTRATIONS_FILE', 'CIAM_REGISTRATIONS_FILE',
 'CIAM_REGISTRATIONS_MANIFEST', 'WSO2_CLIENTS_FILE', 'WSO2_CLIENTS_MANIFEST',
 'OIDC_CLIENTS_CONFIG', 'OIDC_CLIENTS_FILE', 'CIAM_LIVE_CLIENTS_FILE',
)
OMIT_DIRS = {'.git', 'node_modules', 'test', 'tests', '__tests__', 'fixtures', 'dist', 'build', 'coverage', '.next', 'vendor', 'docs'}

class RehearsalError(Exception): pass

def run(args, cwd, env=None):
    p = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if p.returncode:
        # Avoid echoing private manifests, credentials, URLs, or arbitrary SQL diagnostics.
        msg = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else 'command failed'
        msg = re.sub(r'postgres(?:ql)?://\S+', '[redacted-url]', msg)
        raise RehearsalError(f'{args[0]} {args[1] if len(args)>1 else ""} failed: {msg[:300]}')
    return p.stdout.strip()

def issuer_url(value):
    if not isinstance(value, str) or not 15 < len(value) <= 1024: return None
    try:
        u=urlsplit(value)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment:
            return None
        if not u.path.endswith('/oauth2/token'): return None
        return value
    except ValueError:
        return None

def brand_from_key(key):
    key = str(key).lower().replace('_','-')
    for brand in BRANDS:
        if re.fullmatch(rf'{brand}(?:-(?:web|mobile|app|ios|android))?', key):
            return brand
    return None

def find_issuers_in_tree(tree):
    """Only issuer entries explicitly attached to a recognized client/brand are accepted."""
    found = []
    def visit(obj, context=None):
        if isinstance(obj, list):
            for item in obj: visit(item, context)
        elif isinstance(obj, dict):
            # Keys like 'aurora-web', or objects with brand and a registered client ID.
            name = obj.get('key') or obj.get('name') or obj.get('clientKey') or obj.get('client_key')
            brand = brand_from_key(name) if isinstance(name,str) else None
            brand = brand or brand_from_key(obj.get('brand', '')) or context
            raw = obj.get('issuer') or obj.get('issuerUrl') or obj.get('oidcIssuer') or obj.get('oidc_issuer')
            issuer = issuer_url(raw)
            # A brand-labelled top-level config block is admissible, but not a stray unrelated issuer.
            if brand and issuer:
                found.append((brand, issuer))
            for key, child in obj.items():
                keyed_brand = brand_from_key(key)
                # propagate brand only within an explicitly keyed registration
                visit(child, keyed_brand or (brand if key in ('oidc','oauth','oauth2','config','registration') else None))
    visit(tree)
    return found

def candidate_files(repo:Path, env):
    paths = set()
    for key in EXPLICIT_PATH_VARS:
        if env.get(key):
            p=Path(env[key]).expanduser()
            paths.add(p if p.is_absolute() else repo/p)
    # Also consider named config manifests at the repository root.
    for path in repo.glob('*.json'):
        low=path.name.lower()
        if any(x in low for x in ('client','registration','manifest','wso2','ciam','oidc','identity')):
            paths.add(path)
    # Only parse JSON configuration candidates, never arbitrary executable scripts or test fixtures.
    for dirname in ('var', 'private', '.private', '.secrets', 'secrets', '.config', 'config', 'deploy', 'bootstrap', 'scripts', 'services/identity-bff'):
        directory=repo/dirname
        if not directory.is_dir(): continue
        for root, dirs, filenames in os.walk(directory, followlinks=False):
            dirs[:]=[d for d in dirs if d not in OMIT_DIRS and not d.startswith('tmp')]
            for name in filenames:
                low = name.lower()
                if not low.endswith('.json'): continue
                if not any(x in low for x in ('client','registration','manifest','wso2','ciam','oidc','identity','application')):
                    continue
                paths.add(Path(root)/name)
                if len(paths)>MAX_FILES: raise RehearsalError('Too many client configuration candidates; refusing ambiguous discovery')
    return sorted(paths)

BFF_MANIFESTS = (
    'var/wso2/identity-bff-v10.private.json',
    'var/wso2/identity-bff-wso2.private.json',
)

def _load_bff_issuer_pair(path:Path, repo:Path):
    if path.is_symlink() or not path.is_file():
        raise RehearsalError('BFF manifest missing or symlink: '+path.name)
    if path.stat().st_size > 1024 * 1024:
        raise RehearsalError('BFF manifest too large: '+path.name)
    try:
        document=json.loads(path.read_text('utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        raise RehearsalError('BFF manifest unreadable/invalid JSON: '+path.name) from e
    matches=find_issuers_in_tree(document)
    by_brand={b:set() for b in BRANDS}
    for brand, value in matches:
        by_brand[brand].add(value)
    for brand in BRANDS:
        if len(by_brand[brand]) != 1:
            raise RehearsalError(f'{brand}: BFF manifest {path.name} contains '
                f'{len(by_brand[brand])} issuer candidates; refusing ambiguity')
    return {b:next(iter(by_brand[b])) for b in BRANDS}

def discover_issuers(repo:Path, env):
    """Bind only to the BFF registration manifest, never a linked-status report.

    If the runtime explicitly pins WSO2_BFF_PRIVATE_MANIFEST, use that file.
    Without an override, BOTH known BFF private manifests must be present and
    agree on each brand, protecting against stale or drifting registrations.
    """
    launcher=repo/'scripts/ciam-live-start.mjs'
    if (not launcher.is_file() or launcher.is_symlink() or
        'WSO2_BFF_PRIVATE_MANIFEST' not in launcher.read_text('utf-8')):
        raise RehearsalError('BFF launcher manifest contract not found; no issuer guessed')
    explicit=env.get('WSO2_BFF_PRIVATE_MANIFEST','').strip()
    if explicit:
        p=Path(explicit).expanduser()
        chosen=[p if p.is_absolute() else repo/p]
    else:
        chosen=[repo/name for name in BFF_MANIFESTS]
    pairs=[]
    sources={b:set() for b in BRANDS}
    for path in chosen:
        pair=_load_bff_issuer_pair(path,repo)
        pairs.append(pair)
        try: display=str(path.relative_to(repo))
        except ValueError: display='[external runtime BFF manifest]'
        for brand in BRANDS: sources[brand].add(display)
    if any(pair!=pairs[0] for pair in pairs[1:]):
        raise RehearsalError('BFF registration manifests disagree; refusing issuer choice')
    resolved=pairs[0]
    if resolved['aurora']==resolved['brisa']:
        raise RehearsalError('Aurora and Brisa issuer collision in BFF manifest')
    for brand in BRANDS:
        preconfigured=env.get(f'CIAM_{brand.upper()}_ISSUER','')
        if preconfigured and preconfigured!=resolved[brand]:
            raise RehearsalError(f'{brand}: pre-set issuer conflicts with BFF manifest')
    return resolved,sources

def validate_target(url):
    if not url: raise RehearsalError('Missing CIAM_BUSINESS_MIGRATOR_DATABASE_URL; never auto-create a DB URL')
    try:
        u=urlsplit(url)
        parts=(u.hostname,u.port or 5432,unquote(u.path.lstrip('/')),unquote(u.username or ''))
        if u.scheme not in ('postgres','postgresql') or parts!=EXPECTED_DB or u.query or u.fragment:
            raise RehearsalError('Database URL does not match exact disposable rehearsal target 127.0.0.1:55434')
    except ValueError as ex:
        raise RehearsalError('Malformed database URL') from ex

def prepare_snapshot(repo:Path,env):
    """Use existing snapshot or create a private, non-destructive local copy automatically."""
    source=repo/'var/ciam-business-data'
    supplied=env.get('CIAM_BUSINESS_SNAPSHOT_DIR')
    if supplied:
        snapshot=Path(supplied).resolve()
    else:
        snapshot=Path(tempfile.mkdtemp(prefix='p117-auto-import-'))
        os.chmod(snapshot,0o700)
        try:
            for brand in BRANDS:
                a=source/f'requests-{brand}.jsonl'
                if not a.is_file() or a.is_symlink():
                    raise RehearsalError(f'{brand}: missing/unsafe business ledger')
                b=snapshot/a.name
                with a.open('rb') as input_stream, b.open('xb') as output_stream:
                    shutil.copyfileobj(input_stream,output_stream)
                    output_stream.flush();os.fsync(output_stream.fileno())
                b.chmod(0o600)
        except Exception:
            shutil.rmtree(snapshot)
            raise
        print(f'Private JSONL snapshot prepared: {snapshot}',flush=True)
    if snapshot==source or source in snapshot.parents:
        raise RehearsalError('Snapshot must be isolated from live source')
    compare_snapshot(source,snapshot)
    return snapshot

def compare_snapshot(source,snapshot):
    for brand in BRANDS:
        a=source/f'requests-{brand}.jsonl'; b=snapshot/f'requests-{brand}.jsonl'
        if not a.is_file() or not b.is_file() or a.is_symlink() or b.is_symlink():
            raise RehearsalError(f'{brand}: source/snapshot missing or symlink')
        if hashlib.sha256(a.read_bytes()).digest()!=hashlib.sha256(b.read_bytes()).digest():
            raise RehearsalError(f'{brand}: source changed since snapshot; migration STOP')

def inspect_database(repo,env):
    js='''import pg from "pg";
const c = new pg.Client({connectionString:process.env.CIAM_BUSINESS_MIGRATOR_DATABASE_URL});
try {
 await c.connect();
 const id=(await c.query('SELECT current_database() AS db, current_user AS role')).rows[0];
 const m=(await c.query('SELECT checksum FROM business.schema_migrations WHERE version=1')).rows;
 const r=(await c.query(`SELECT
   (SELECT COUNT(*)::int FROM business.brands) AS brands,
   (SELECT COUNT(*)::int FROM business.service_requests) AS cases,
   (SELECT COUNT(*)::int FROM business.case_events) AS events,
   (SELECT COUNT(*)::int FROM business.seller_decisions) AS decisions,
   (SELECT COUNT(*)::int FROM business.jsonl_imports) AS imports`)).rows[0];
 console.log(JSON.stringify({id,m,r}));
} finally { await c.end().catch(()=>{}); }
'''
    try: output=run(['node','--input-type=module','-e',js], repo, env)
    except RehearsalError as ex: raise RehearsalError('Database schema/identity inspection failed; no import attempted') from ex
    data=json.loads(output)
    if data['id']!={'db':EXPECTED_DB[2], 'role':EXPECTED_DB[3]}: raise RehearsalError('Connected database identity mismatch')
    if len(data['m'])!=1 or data['m'][0]['checksum']!=EXPECTED_SCHEMA_SHA:
        raise RehearsalError('Schema checksum differs from approved v1')
    if any(data['r'][key]!=0 for key in ('brands','cases','events','decisions','imports')):
        raise RehearsalError(f'Business target not empty: counts={data["r"]}; import refused')
    return data['r']

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo',type=Path,default=Path.cwd())
    ap.add_argument('--apply',action='store_true',help='explicit approval for test-only historical import and verification')
    args=ap.parse_args()
    repo=args.repo.resolve(); env=os.environ.copy()
    if not (repo/'scripts/business-db.mjs').is_file(): raise RehearsalError('Wrong repository root')
    if env.get('CIAM_CASES_BACKEND','jsonl')!='jsonl': raise RehearsalError('BFF backend must remain JSONL')
    if (repo/'var/ciam-business-data/business-postgres-cutover.json').exists(): raise RehearsalError('Cutover already activated')
    snapshot=prepare_snapshot(repo,env)
    inv_env={**env,'CIAM_BUSINESS_DATA_DIR':str(snapshot)}
    summary=json.loads(run(['node','scripts/business-db.mjs','inventory'],repo,inv_env))
    if summary.get('fingerprint')!=EXPECTED_FINGERPRINT or summary.get('schemaSha256')!=EXPECTED_SCHEMA_SHA:
        raise RehearsalError('Inventory fingerprint or schema checksum changed; no import')
    expected={'aurora':(3,6,3),'brisa':(0,0,0)}
    for rec in summary['brands']:
        if expected.get(rec['brand'])!=(rec['cases'],rec['events'],rec['approved']):
            raise RehearsalError('Historical totals changed; no import')
    issuers,sources=discover_issuers(repo,env)
    validate_target(env.get('CIAM_BUSINESS_MIGRATOR_DATABASE_URL'))
    inspect_database(repo,env)
    print(json.dumps({'status':'PREFLIGHT_OK','target':EXPECTED_DB[2],
        'fingerprint':summary['fingerprint'],
        'issuers':{brand:{'issuer_sha256_prefix':hashlib.sha256(issuer.encode('utf-8')).hexdigest()[:16],
                           'configuration_sources':sorted(sources[brand])}
                    for brand,issuer in issuers.items()},
        'business_data_writes':'APPROVED' if args.apply else 'NONE'},indent=2))
    if not args.apply:
        print('READ_ONLY: no import performed. Re-run with --apply to authorize rehearsal-only DB writes.')
        return
    env2={**inv_env, 'NODE_ENV':'test','CIAM_OPERATOR_APPROVED_WRITES':'YES',
          **{f'CIAM_{b.upper()}_ISSUER':v for b,v in issuers.items()}}
    print('Starting controlled historical import into dedicated rehearsal database...',flush=True)
    print(run(['node','scripts/business-db.mjs','apply-ledger',f'--approve={EXPECTED_FINGERPRINT}'],repo,env2))
    print(run(['node','scripts/business-db.mjs','verify'],repo,env2))
    print('VERIFIED_IMPORT_COMPLETE; NO CUTOVER ACTIVATED')

if __name__=='__main__':
    try: main()
    except RehearsalError as e:
        print('P117_REHEARSAL_STOP: '+str(e),file=sys.stderr)
        sys.exit(2)
