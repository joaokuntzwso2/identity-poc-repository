#!/usr/bin/env python3
"""Render isolated WSO2 7.3 TOML from the extracted stock configuration."""
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tomllib
import importlib.util

SECTIONS = ('server','super_admin','database.identity_db','database.shared_db','datasource.AgentIdentity')


def only_owner_private(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError(f'PRIVATE_PATH_UNSAFE_{p.name}')
    s = p.stat()
    if stat.S_IMODE(s.st_mode) != 0o600 or s.st_uid != os.getuid():
        raise ValueError(f'PRIVATE_MODE_UNSAFE_{p.name}')


def env_password(path):
    only_owner_private(path)
    raw = Path(path).read_text()
    matches = re.findall(r'^POSTGRES_PASSWORD=([0-9a-f]{64})$', raw, re.M)
    if len(matches) != 1:
        raise ValueError('POSTGRES_PASSWORD_NOT_STRICT_HEX64')
    return matches[0]


def render(stock, pg_password, admin_password):
    src = tomllib.loads(stock)
    if any(not isinstance(src.get(top), dict) for top in ('server', 'super_admin', 'database', 'datasource')) or \
       any(k not in src['database'] for k in ('identity_db', 'shared_db')) or 'AgentIdentity' not in src['datasource']:
        raise ValueError('STOCK_TOML_MISSING_EXPECTED_SECTION')
    if src['database']['identity_db'].get('type') != 'h2' or src['database']['shared_db'].get('type') != 'h2':
        raise ValueError('STOCK_DB_NOT_H2')
    if src['datasource']['AgentIdentity'].get('driver') != 'org.h2.Driver':
        raise ValueError('STOCK_AGENT_DB_NOT_H2')
    q = json.dumps
    sections = {
        'server': '[server]\nhostname = "localhost"\nnode_ip = "127.0.0.1"\nbase_path = "https://localhost:9444"\noffset = 1\n',
        'super_admin': '[super_admin]\nusername = "admin"\npassword = '+q(admin_password)+'\ncreate_admin_account = true\n',
        'database.identity_db': '[database.identity_db]\ntype = "postgre"\nhostname = "postgres"\nname = "ciam_identity"\nusername = "ciamadmin"\npassword = '+q(pg_password)+'\nport = "5432"\n',
        'database.shared_db': '[database.shared_db]\ntype = "postgre"\nhostname = "postgres"\nname = "ciam_shared"\nusername = "ciamadmin"\npassword = '+q(pg_password)+'\nport = "5432"\n',
        'datasource.AgentIdentity': '[datasource.AgentIdentity]\nid = "AgentIdentity"\nurl = "jdbc:postgresql://postgres:5432/ciam_agent"\nusername = "ciamadmin"\npassword = '+q(pg_password)+'\ndriver = "org.postgresql.Driver"\n',
    }
    out = stock
    for key in SECTIONS:
        pattern = r'(?ms)^\[' + re.escape(key) + r'\][^\n]*\n.*?(?=^\[|\Z)'
        out, cnt = re.subn(pattern, lambda _: sections[key] + '\n', out)
        if cnt != 1:
            raise ValueError(f'STOCK_SECTION_NONUNIQUE_{key}')
    policy_file = Path(__file__).with_name('introspection_policy.py')
    policy_spec = importlib.util.spec_from_file_location('ciam_v10_introspection_policy', policy_file)
    policy = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy)
    out = policy.ensure_introspection_policy(out)
    parsed = tomllib.loads(out)
    assert parsed['server']['offset'] == 1
    assert parsed['database']['identity_db']['name'] == 'ciam_identity'
    assert parsed['database']['shared_db']['name'] == 'ciam_shared'
    assert parsed['datasource']['AgentIdentity']['url'].endswith('/ciam_agent')
    assert parsed['super_admin']['password'] == admin_password
    return out


def create_exclusive(path, content):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if p.exists() or p.is_symlink():
        raise ValueError('OUTPUT_EXISTS_'+p.name)
    with open(p, 'x', encoding='utf-8', opener=lambda f, flags: os.open(f, flags, 0o600)) as h:
        h.write(content)


def main(argv):
    if len(argv) != 5:
        raise SystemExit('usage: render.py stock.toml .env deployment.toml admin.private.json')
    stock_path, env_path, output_path, admin_path = map(Path, argv[1:])
    if output_path.exists() or admin_path.exists():
        raise SystemExit('REFUSING_TO_OVERWRITE_BOOTSTRAP_SECRETS')
    if stock_path.is_symlink() or not stock_path.is_file():
        raise SystemExit('STOCK_TOML_MISSING_OR_SYMLINK')
    pg_password = env_password(env_path)
    admin_password = secrets.token_urlsafe(36)
    output = render(stock_path.read_text(), pg_password, admin_password)
    try:
        create_exclusive(output_path, output)
        create_exclusive(admin_path, json.dumps({'username':'admin', 'password':admin_password, 'console':'https://localhost:9444/console'}, indent=2)+'\n')
    except Exception:
        # Deliberately leave partial private files in place; never silently regenerate secrets.
        raise
    print('ISOLATED_WSO2_CONFIG_GENERATED_PRIVATE')
    print('ADMIN_CREDENTIALS_STORED_IN_PRIVATE_FILE')


if __name__ == '__main__':
    main(sys.argv)
