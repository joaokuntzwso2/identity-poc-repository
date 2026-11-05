"""Read existing v10 tenant-owner credentials without leaking or rotating secrets.

Only allowlisted, owner-owned, mode-0600 private v10 JSON journals are inspected.
We never infer tenant credentials from super-tenant admin secrets, OAuth clients,
WSO2 user databases, Docker environment or arbitrary project files.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import stat

TENANTS = frozenset(('aurora.identity.test', 'brisa.identity.test'))
JOURNALS = (
    'bootstrap-tenants-v10.private.json',
    'bootstrap-resources-v10.private.json',
    'admin.private.json',
)
MAX_BYTES = 1_048_576
_DOMAIN_KEYS = ('tenantDomain', 'tenant_domain', 'tenant', 'domain')
_OWNER_KEYS = ('owner', 'tenantOwner', 'tenant_owner', 'tenantAdmin', 'tenant_admin')
_NAME_KEYS = ('username', 'userName', 'user_name', 'login', 'name')
_PASS_KEYS = ('password', 'ownerPassword', 'owner_password')
_FLAT_NAME = ('ownerUsername', 'owner_username', 'ownerUserName',
              'tenantAdminUsername', 'tenant_admin_username')
_FLAT_PASS = ('ownerPassword', 'owner_password', 'tenantAdminPassword',
              'tenant_admin_password')


class CredentialError(RuntimeError):
    """Contains no secret, credential text or the account username."""


def _one(node, keys):
    options = [node.get(key) for key in keys
               if isinstance(node.get(key), str) and node[key].strip()]
    if len(set(options)) > 1:
        raise CredentialError('conflicting owner credential fields; refusing ambiguity')
    return options[0] if options else None


def _non_duplicate_pairs(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            raise CredentialError('duplicate JSON key in private v10 journal')
        value[k] = v
    return value


def _secure_load(path: pathlib.Path):
    # O_NOFOLLOW prevents symlink substitution. fstat checks the opened file,
    # not only the potentially raced path.
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CredentialError(f'cannot safely open private v10 journal {path.name}') from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            raise CredentialError(f'unsafe ownership/type of {path.name}')
        if st.st_mode & 0o077:
            raise CredentialError(f'{path.name} must have mode 0600, refusing secret read')
        if st.st_size > MAX_BYTES:
            raise CredentialError(f'private v10 journal too large: {path.name}')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            data = f.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise CredentialError(f'private v10 journal too large: {path.name}')
        try:
            return json.loads(data, object_pairs_hook=_non_duplicate_pairs)
        except (ValueError, UnicodeError) as exc:
            raise CredentialError(f'invalid private v10 JSON journal: {path.name}') from None
    finally:
        os.close(fd)


def _pairs(node, tenant):
    """Yield credentials only when explicitly under a domain-bound owner record."""
    results = []

    def walk(obj, bound, depth):
        if depth > 12 or len(results) > 32:
            raise CredentialError('private journal structure ambiguous/too deep')
        if isinstance(obj, list):
            for child in obj:
                walk(child, bound, depth + 1)
            return
        if not isinstance(obj, dict):
            return
        domains = {obj[k] for k in _DOMAIN_KEYS if isinstance(obj.get(k), str)}
        if domains:
            # All explicitly declared domain fields must agree; never inherit a
            # different tenant's record or silently cross tenant boundaries.
            if len(domains) != 1:
                raise CredentialError('conflicting tenant domains in private v10 journal')
            bound = tenant in domains

        if bound:
            u = _one(obj, _FLAT_NAME)
            p = _one(obj, _FLAT_PASS)
            if u and p:
                results.append((u, p))
            for key in _OWNER_KEYS:
                owner = obj.get(key)
                if isinstance(owner, dict):
                    ou = _one(owner, _NAME_KEYS) or u
                    op = _one(owner, _PASS_KEYS) or p
                    if ou and op:
                        results.append((ou, op))
        for key, child in obj.items():
            # Require an explicit tenant-domain key or declaration; never use
            # a generic global "admin" record as a tenant owner.
            child_bound = bound or (isinstance(key, str) and key == tenant)
            if isinstance(child, (dict, list)):
                walk(child, child_bound, depth + 1)

    walk(node, False, 0)
    return set(results)


def resolve_tenant_owner(v10_home, tenant, environ=None):
    """Return (username, password) for an exact existing tenant owner.

    Explicit complete environment overrides are supported for compatibility,
    but NEVER required when a recoverable tenant-owner journal exists.
    """
    if tenant not in TENANTS:
        raise CredentialError('unsupported v10 tenant')
    env = os.environ if environ is None else environ
    alias = tenant.split('.')[0].upper()
    username = env.get(f'MAGALU_{alias}_ADMIN_USER')
    password = env.get(f'MAGALU_{alias}_ADMIN_PASSWORD')
    if bool(username) != bool(password):
        raise CredentialError(f'incomplete {alias} credential override; refusing fallback')
    if username and password:
        result = (username, password)
    else:
        root = pathlib.Path(v10_home).expanduser().resolve()
        private = root / 'private'
        if not private.is_dir() or private.is_symlink():
            raise CredentialError('existing v10 private journal directory unavailable')
        st = private.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o022:
            raise CredentialError('unsafe private v10 journal directory ownership/permissions')
        matches = set()
        for journal in JOURNALS:
            record = _secure_load(private / journal)
            if record is not None:
                matches.update(_pairs(record, tenant))
        if len(matches) == 0:
            raise CredentialError(
                f'{alias}: no recoverable tenant-owner username/password in approved '
                'v10 private journals; cannot reconstruct a password from WSO2 hashes')
        if len(matches) != 1:
            raise CredentialError(f'{alias}: conflicting tenant-owner credential records; refusing')
        result = next(iter(matches))
    user, secret = result
    if not (0 < len(user) <= 512 and 0 < len(secret) <= 4096):
        raise CredentialError('invalid tenant-owner credential length')
    if any(ch in user for ch in ('\r', '\n', ':')) or any(ch in secret for ch in ('\r', '\n')):
        raise CredentialError('invalid tenant-owner credential format')
    return result
