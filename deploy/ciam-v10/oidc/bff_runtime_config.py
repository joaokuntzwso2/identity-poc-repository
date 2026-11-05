#!/usr/bin/env python3
"""Source-controlled, fail-closed local BFF Cases/TOTP runtime configuration.

This module is deliberately separate from WSO2 provisioning. It never mutates
WSO2 tenants, applications, tokens, databases or existing case ledgers.
"""
import json
import os
import stat
from pathlib import Path

class RuntimeConfigurationError(ValueError):
    pass

POLICY_RELATIVE_PATH = Path("deploy/ciam-v10/oidc/bff-runtime-policy.json")
_REQUIRED = {
    "schema",
    "casesApiAudience",
    "casesScopesEnabled",
    "totpStepupAcr",
    "totpStepupAmr",
    "casesBackend",
    "businessDataDir",
}
_POLICY = {
    "schema": "identity.wso2.ciam.v10.bff-runtime.v1",
    "casesApiAudience": "urn:ciampoc:service-requests:v1",
    "casesScopesEnabled": True,
    "totpStepupAcr": "urn:ciampoc:assurance:totp:v1",
    "totpStepupAmr": "totp",
    "casesBackend": "jsonl",
    "businessDataDir": "var/ciam-business-data",
}

def _check_directory(path, *, private):
    if path.is_symlink() or not path.is_dir():
        raise RuntimeConfigurationError("BFF_CASES_DIRECTORY_INVALID")
    s = path.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid():
        raise RuntimeConfigurationError("BFF_CASES_DIRECTORY_OWNER_INVALID")
    if stat.S_IMODE(s.st_mode) & (0o077 if private else 0o022):
        raise RuntimeConfigurationError("BFF_CASES_DIRECTORY_PERMISSIONS_UNSAFE")

def _read_policy(repo):
    path = repo / POLICY_RELATIVE_PATH
    if path.is_symlink() or not path.is_file():
        raise RuntimeConfigurationError("BFF_RUNTIME_POLICY_MISSING_OR_SYMLINK")
    s = path.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_mode & 0o022:
        raise RuntimeConfigurationError("BFF_RUNTIME_POLICY_WRITABLE")
    if s.st_size > 8192:
        raise RuntimeConfigurationError("BFF_RUNTIME_POLICY_OVERSIZE")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise RuntimeConfigurationError("BFF_RUNTIME_POLICY_INVALID_JSON") from None
    if not isinstance(config, dict) or set(config) != _REQUIRED:
        raise RuntimeConfigurationError("BFF_RUNTIME_POLICY_SCHEMA_INVALID")
    # This first increment intentionally preserves the known-good local JSONL
    # backend. AWS/PostgreSQL needs a separately verified cutover procedure.
    if config != _POLICY:
        raise RuntimeConfigurationError("BFF_RUNTIME_POLICY_SECURITY_DRIFT")
    return config

def build_cases_runtime_env(repo, inherited):
    """Compute fixed security env for every BFF launch or guarded restart.

    Refuse conflicting inherited settings rather than silently accepting a
    downgrade. No files or directories are written until all settings pass.
    """
    repo = Path(repo).expanduser().resolve(strict=True)
    if not isinstance(inherited, dict):
        raise RuntimeConfigurationError("BFF_RUNTIME_ENV_INVALID")
    config = _read_policy(repo)
    parent = repo / "var"
    storage = parent / "ciam-business-data"
    desired = {
        "WSO2_CASES_API_AUDIENCE": config["casesApiAudience"],
        "WSO2_CASES_SCOPES_ENABLED": "1",
        "WSO2_TOTP_STEPUP_ACR": config["totpStepupAcr"],
        "WSO2_TOTP_STEPUP_AMR": config["totpStepupAmr"],
        "CIAM_CASES_BACKEND": config["casesBackend"],
        "CIAM_BUSINESS_DATA_DIR": str(storage),
    }
    for name, value in desired.items():
        if name in inherited and inherited[name] != value:
            raise RuntimeConfigurationError("BFF_RUNTIME_CONFLICT_" + name)
    if not parent.exists():
        try:
            parent.mkdir(mode=0o700)
        except FileExistsError:
            pass
    _check_directory(parent, private=False)
    if storage.is_symlink():
        raise RuntimeConfigurationError("BFF_CASES_DIRECTORY_SYMLINK")
    if not storage.exists():
        try:
            storage.mkdir(mode=0o700)
        except FileExistsError:
            pass
    _check_directory(storage, private=True)
    return desired
