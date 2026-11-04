#!/usr/bin/env python3
"""Safe, credential-redacting v10 authority bridge check (no WSO2 network)."""
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
TARGET=ROOT/'scripts/p2/m2m_bootstrap.py'
try:
    spec=importlib.util.spec_from_file_location('p2_bridge_selfcheck',TARGET)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    admin=module.read_existing_authority_admin(ROOT)
    if not isinstance(admin,module.AuthorityBasic) or not module._approved_basic_header(admin._header):
        raise ValueError('invalid authority header')
    print(json.dumps({'phase':'P2.24','status':'PASS',
                      'code':'AURORA_AUTHORITY_CREDENTIAL_CAPTURED_NO_NETWORK',
                      'networkRequests':0,'remoteManagementWrites':0},sort_keys=True))
except Exception as exc:
    code=str(exc) if type(exc).__name__=='Block' else 'AUTHORITY_BRIDGE_SELF_CHECK_FAILED'
    # Safe error codes only: never print exception values from credential sources.
    if not code.isascii() or not code.replace('_','').isalnum() or len(code)>90:
        code='AUTHORITY_BRIDGE_SELF_CHECK_FAILED'
    print(json.dumps({'phase':'P2.24','status':'BLOCKED','code':code,
                      'networkRequests':0,'remoteManagementWrites':0},sort_keys=True))
    sys.exit(2)
