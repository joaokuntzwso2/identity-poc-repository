"""Resolve a trusted WSO2 7.3 localhost TLS identity from existing v10 state.

No insecure SSL contexts, proxy headers, TOFU trust-on-first-use or certificate
blindly downloaded from the network. The last resort extracts *only the public*
certificate from the explicitly selected running v10 container keystore and
still requires TLS peer/hostname verification.
"""
from __future__ import annotations

import os
import pathlib
import re
import socket
import ssl
import stat
import subprocess
import tomllib


class TlsBootstrapError(RuntimeError):
    pass


_CACHE = {}


def _verify_peer(context):
    # This is a TLS handshake only. It does not send any HTTP payload and
    # therefore cannot duplicate non-idempotent management writes.
    with socket.create_connection(('127.0.0.1', 9444), timeout=4) as sock:
        with context.wrap_socket(sock, server_hostname='localhost'):
            pass
    return context


def _safe_cert(path, private):
    if path.is_symlink() or not path.is_file():
        return None
    st = path.stat()
    if st.st_uid != os.getuid() or not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022:
        return None
    if st.st_size > 64_000:
        return None
    content = path.read_text(errors='replace')
    if '-----BEGIN CERTIFICATE-----' not in content or 'PRIVATE KEY' in content:
        return None
    return content


def _keystore_pubcert(home, resolver):
    path = pathlib.Path(home) / 'private/deployment.toml'
    if path.is_symlink() or not path.is_file():
        raise TlsBootstrapError('missing pinned existing v10 deployment.toml')
    try:
        config = tomllib.loads(path.read_text())
    except (ValueError, UnicodeError):
        raise TlsBootstrapError('invalid existing v10 deployment.toml') from None
    keystore = config.get('keystore', {})
    if not isinstance(keystore, dict):
        raise TlsBootstrapError('existing v10 keystore configuration missing')
    # tls key has precedence. primary is considered only if no explicit tls
    # configuration; the final verified localhost handshake decides whether it
    # is the certificate WSO2 actually serves.
    info = keystore.get('tls') or keystore.get('primary')
    if not isinstance(info, dict):
        raise TlsBootstrapError('no pinned public TLS keystore declared in v10 deployment.toml')
    name = info.get('file_name', '')
    alias = info.get('alias') or 'wso2carbon'
    password = info.get('password')
    if (not isinstance(name, str) or not name
            or pathlib.PurePosixPath(name).name != name
            or not isinstance(alias, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', alias)
            or not isinstance(password, str) or not password
            or password.startswith('${')):
        raise TlsBootstrapError('TLS keystore public certificate cannot be safely extracted from existing config')
    rt = resolver(pathlib.Path(home))
    container = rt.get('is_id', '')
    carbon = rt.get('carbon_home', '')
    if not container or not carbon.startswith('/'):
        raise TlsBootstrapError('pinned v10 container not identified')
    store = str(pathlib.PurePosixPath(carbon) / 'repository/resources/security' / name)
    # Deliver keystore password on stdin, never in Docker CLI arguments.
    if '\n' in password or '\r' in password:
        raise TlsBootstrapError('unsupported TLS keystore credential format')
    args = ['docker', 'exec', '-i', container, 'sh', '-ec',
            'IFS= read -r MAGALU_TLS_STOREPASS; export MAGALU_TLS_STOREPASS; '
            'exec keytool -exportcert -rfc -alias "$1" -keystore "$2" '
            '-storepass:env MAGALU_TLS_STOREPASS',
            'keytool-wrapper', alias, store]
    try:
        p = subprocess.run(args, input=password + '\n', capture_output=True,
                           text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise TlsBootstrapError('unable to extract public certificate from pinned WSO2 TLS keystore') from None
    if p.returncode != 0:
        # Never print keytool stderr, keystore paths or environment secrets.
        raise TlsBootstrapError('pinned WSO2 TLS keystore public certificate extraction failed')
    match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', p.stdout, re.DOTALL)
    if not match:
        raise TlsBootstrapError('pinned WSO2 keystore did not export a public certificate')
    return match.group(0)


def trusted_context(v10_home, runtime_resolver):
    """Return hostname-verifying SSLContext; cache only within this process."""
    home = pathlib.Path(v10_home).expanduser().resolve()
    # Do not cache across processes or a changed operator-specified CA path.
    override = os.environ.get('CIAM_V10_CA_CERT', '')
    key = (str(home), override)
    if key in _CACHE:
        return _CACHE[key]
    if override:
        try:
            ctx = _verify_peer(ssl.create_default_context(cafile=override))
        except (OSError, ssl.SSLError, ValueError):
            raise TlsBootstrapError('operator-pinned TLS CA did not verify the v10 peer') from None
        _CACHE[key] = ctx
        return ctx
    # First use operating-system roots; no special trust required for public CA.
    try:
        ctx = _verify_peer(ssl.create_default_context())
        _CACHE[key] = ctx
        return ctx
    except (OSError, ssl.SSLError):
        pass
    private = home / 'private'
    if private.is_dir():
        # Existing operator-owned certificates; do not inspect keystores,
        # arbitrary project secrets or write new CA files.
        dirs = (private, private / 'certs', private / 'tls')
        for directory in dirs:
            if not directory.is_dir() or directory.is_symlink():
                continue
            candidates = sorted(p for p in directory.iterdir()
                                if p.suffix.lower() in ('.pem', '.crt') and p.is_file())
            for candidate in candidates[:32]:
                pem = _safe_cert(candidate, private)
                if pem is None:
                    continue
                try:
                    ctx = _verify_peer(ssl.create_default_context(cadata=pem))
                    _CACHE[key] = ctx
                    return ctx
                except (OSError, ssl.SSLError, ValueError):
                    continue
    # Last resort: load the public cert from the trusted, already-running
    # Docker v10 server config, never from an unauthenticated TLS connection.
    pem = _keystore_pubcert(home, runtime_resolver)
    try:
        ctx = ssl.create_default_context(cadata=pem)
        ctx.verify_flags |= getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0)
        ctx = _verify_peer(ctx)
    except (OSError, ssl.SSLError, ValueError):
        raise TlsBootstrapError('pinned running WSO2 TLS identity does not match localhost:9444') from None
    _CACHE[key] = ctx
    return ctx
