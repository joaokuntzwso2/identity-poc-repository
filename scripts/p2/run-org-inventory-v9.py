#!/usr/bin/env python3
"""Non-interactive GET-only WSO2 partner discovery after v8 M2M recovery.

Rechecks the approved app, readback-verified authorization and pinned GA image,
refreshes OAuth token with client_credentials, then invokes only GET-only CLI commands.
NO WSO2 management mutations, no partner creation, no secret/UUID printing.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys

TENANT = 'aurora.identity.test'
SCOPE = 'internal_org_organization_view'
APP_FP = '837c9f0ac85efca8'
ROOT_FP = '4548812d1a94a3ff'
CERT_SHA = '2ba361a032ffd4b34f7df066de72b61c5e836a09f7a7bd7105eb87b4094d9712'
JOURNAL = 'p2-aurora-orgview-bootstrap.private.json'
TOKEN = 'p2-aurora-root-token.private.txt'
CERT = 'p2-local-wso2-tls-pinned.pem'

class Block(Exception):
    pass

def require(flag, code):
    if not flag:
        raise Block(code)

def code_only(error):
    val = str(error)
    return val if re.fullmatch(r'[A-Z0-9_]{3,90}', val) else 'ORG_INVENTORY_V9_UNEXPECTED_FAILURE'

def load_module(path):
    require(path.is_file() and not path.is_symlink(), 'EXISTING_M2M_SOURCE_MISSING')
    spec = importlib.util.spec_from_file_location('p2_org_v9_existing_bootstrap', path)
    require(spec is not None and spec.loader is not None, 'EXISTING_M2M_SOURCE_INVALID')
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise Block('EXISTING_M2M_IMPORT_FAILED')
    return module

def verify_completed_journal(module, record):
    require(isinstance(record, dict) and
            record.get('schema') == 'p2.24.aurora.m2m.bootstrap.v1' and
            record.get('phase') == 'COMPLETE' and
            record.get('tenant') == TENANT and
            record.get('appName') == 'P2 Aurora Organization View M2M' and
            record.get('scope') == SCOPE and
            record.get('remoteWritesAttempted') == 2 and
            record.get('reconciledBy') == 'P2_24_GET_ONLY_AUTHORIZATION_READBACK_V8' and
            record.get('originalCreateResponseStillUnverified') is True and
            isinstance(record.get('appId'), str) and module.UUID.fullmatch(record['appId']) and
            module.hash_id(record['appId']) == APP_FP and
            isinstance(record.get('rootId'), str) and module.UUID.fullmatch(record['rootId']) and
            module.hash_id(record['rootId']) == ROOT_FP,
            'V8_COMPLETE_JOURNAL_NOT_PINNED')

def verify_cert(module, path):
    module.safe_private_file(path, max_size=16384)
    try:
        der = ssl.PEM_cert_to_DER_cert(path.read_text('ascii'))
    except Exception:
        raise Block('PINNED_TLS_CERT_FILE_INVALID')
    require(hashlib.sha256(der).hexdigest() == CERT_SHA, 'PINNED_TLS_CERT_FINGERPRINT_CHANGED')

def node_json(repo, env, command):
    try:
        result = subprocess.run(['node', 'scripts/p2/cli.mjs', command], cwd=repo,
                                env=env, capture_output=True, text=True, timeout=75, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Block('GET_ONLY_OPERATOR_COMMAND_UNAVAILABLE')
    try:
        message = json.loads(result.stdout if result.returncode == 0 else result.stderr)
    except (ValueError, TypeError):
        raise Block('OPERATOR_RETURNED_NON_JSON')
    require(isinstance(message, dict), 'OPERATOR_RETURNED_INVALID_RESULT')
    if result.returncode != 0:
        raise Block(code_only(message.get('code', 'ORG_OPERATOR_STOPPED')))
    require(message.get('phase') == 'P2.24-P2.29' and
            message.get('source') == 'WSO2_API_RESPONSE' and
            message.get('tenant') == TENANT and
            message.get('runtimeEvidence') == 'OPERATOR_EXECUTED' and
            isinstance(message.get('result'), dict), 'OPERATOR_EVIDENCE_NOT_VERIFIED')
    return message['result']

def main():
    repo = Path.cwd().resolve()
    require((repo/'scripts/ciam-v10.sh').is_file() and
            (repo/'scripts/p2/cli.mjs').is_file() and
            (repo/'scripts/p2/guarded-org.mjs').is_file(), 'RUN_FROM_PROJECT_ROOT')
    private = Path(os.environ.get('P2_PRIVATE_DIR') or str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    module = load_module(repo/'scripts/p2/m2m_bootstrap.py')
    module.secure_dir(private)
    record = module.read_json_private(private/JOURNAL)
    verify_completed_journal(module, record)
    cert = private/CERT
    verify_cert(module, cert)
    # Source-level runtime guard refuses changed image/journal; no WSO2 writes.
    module.runtime_guard(repo, private)
    admin = module.read_existing_authority_admin(repo)
    http = module.Http(str(cert))
    # Existing project's verified_existing uses GET application+API-authorizations,
    # then an OAuth token request and local atomic token refresh only.
    observed = module.verified_existing(http, private, admin, record)
    require(observed.get('action') == 'ALREADY_VERIFIED' and
            observed.get('remoteManagementWrites') == 0 and
            observed.get('tokenFileReady') is True and
            observed.get('applicationFingerprint') == APP_FP and
            observed.get('rootFingerprint') == ROOT_FP,
            'EXISTING_APP_RECHECK_NOT_VERIFIED')
    module.safe_private_file(private/TOKEN, max_size=8192)
    env = {**os.environ,
           'P2_PRIVATE_DIR': str(private),
           'P2_TOKEN_FILE': str(private/TOKEN),
           'P2_ROOT_ORG_ID': record['rootId'],
           'P2_ORIGIN': 'https://localhost:9444',
           'NODE_EXTRA_CA_CERTS': str(cert)}
    inspection = node_json(repo, env, 'inspect-partner-inventory')
    # Do not require a complete inventory to show structural evidence.
    print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'INSPECTED',
                      'code':'AURORA_ORGANIZATION_LIST_STRUCTURE',
                      'mode':'GET_ONLY_MANAGEMENT', 'managementWrites':0,
                      'oauthTokenRequests':1,'inspection':inspection},indent=2,sort_keys=True),flush=True)
    plan = node_json(repo, env, 'plan-partner')
    require(plan.get('action') in ('CREATE','ALREADY_PRESENT'), 'ORG_PARTNER_PLAN_ACTION_INVALID')
    output = {k:plan[k] for k in ('action','parentFingerprint','organizationFingerprint') if k in plan}
    print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'VERIFIED',
                      'code':'READ_ONLY_PARTNER_PLAN_VERIFIED',
                      'mode':'GET_ONLY_MANAGEMENT','managementWrites':0,
                      'partnerCreated':False,'plan':output},indent=2,sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except Block as error:
        print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'BLOCKED',
                          'code':code_only(error), 'noManagementMutation':True},indent=2,sort_keys=True))
        sys.exit(2)
    except Exception:
        print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'BLOCKED',
                          'code':'READ_ONLY_RUNTIME_UNEXPECTED_FAILURE',
                          'noManagementMutation':True},indent=2,sort_keys=True))
        sys.exit(2)
