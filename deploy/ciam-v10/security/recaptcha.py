#!/usr/bin/env python3
"""Idempotent, secret-safe, WSO2 GA 7.3 [recaptcha] TOML renderer.

Never emits secrets. Requires a private (0600) JSON file:
{ "version": "v2" | "v3", "site_key": "...", "secret_key": "...", "threshold": 0.5 }
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat

class Refused(Exception):
    pass

KEYS = ('enabled', 'api_url', 'verify_url', 'site_key', 'secret_key', 'threshold')
SECTION = re.compile(r'^\s*\[([^\]]+)\]\s*(?:#.*)?$', re.M)


def load_credentials(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise Refused('RECAPTCHA_PRIVATE_CREDENTIALS_REQUIRED')
    s = path.stat()
    if stat.S_IMODE(s.st_mode) != 0o600 or s.st_uid != os.getuid() or s.st_size > 8192:
        raise Refused('RECAPTCHA_CREDENTIAL_FILE_OWNER_MODE_OR_SIZE')
    config = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(config, dict) or config.get('version') not in ('v2', 'v3'):
        raise Refused('RECAPTCHA_VERSION_MUST_BE_V2_OR_V3')
    for k in ('site_key', 'secret_key'):
        value = config.get(k)
        if not isinstance(value, str) or not 12 <= len(value) <= 512 or any(ord(x) < 33 or ord(x) > 126 for x in value):
            raise Refused('RECAPTCHA_INVALID_PRIVATE_'+k.upper())
    if not isinstance(config.get('threshold', 0.5), (float, int)) or isinstance(config.get('threshold', 0.5), bool) or not 0 < config.get('threshold', 0.5) < 1:
        raise Refused('RECAPTCHA_THRESHOLD_INVALID')
    return config


def render(stock: str, creds: dict) -> str:
    """Refuse unknown pre-existing reCAPTCHA sections; never override silently."""
    matches = list(SECTION.finditer(stock))
    rec = [m for m in matches if m.group(1).strip() == 'recaptcha']
    if rec:
        start = rec[0].start()
        subsequent = next((m.start() for m in matches if m.start() > start), len(stock))
        body = stock[start:subsequent]
        if len(rec) != 1 or 'MAGALU_WSO2_RECAPTCHA_MANAGED_V1' not in body:
            raise Refused('UNOWNED_RECAPTCHA_SECTION_REFUSED')
        stock = stock[:start] + stock[subsequent:]
    rows = [
        '[recaptcha]',
        '# MAGALU_WSO2_RECAPTCHA_MANAGED_V1',
        'enabled = true',
        'api_url = "https://www.google.com/recaptcha/api.js"',
        'verify_url = "https://www.google.com/recaptcha/api/siteverify"',
        'site_key = ' + json.dumps(creds['site_key']),
        'secret_key = ' + json.dumps(creds['secret_key'])
    ]
    if creds['version'] == 'v3':
        rows.append('threshold = ' + json.dumps(str(creds.get('threshold', 0.5))))
    return stock.rstrip() + '\n\n' + '\n'.join(rows) + '\n'


def verify_rendered(text: str, config: dict) -> bool:
    try:
        # Cryptographic comparison avoids displaying the private keys in report output.
        return render(text, config) == text
    except Refused:
        return False


def digest(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()
