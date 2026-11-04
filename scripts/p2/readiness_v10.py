#!/usr/bin/env python3
"""P2.24 GA read-only partner-creation readiness. No WSO2 management writes.

Reuses the installed, previously verified Aurora v8/v9 M2M state. Does not
create or authorize applications, grant permissions, or create organizations.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import urllib.parse

TENANT = 'aurora.identity.test'
VIEW_SCOPE = 'internal_org_organization_view'
CREATE_SCOPE = 'internal_org_organization_create'
APP_FP = '837c9f0ac85efca8'
ROOT_FP = '4548812d1a94a3ff'
CERT_SHA = '2ba361a032ffd4b34f7df066de72b61c5e836a09f7a7bd7105eb87b4094d9712'
JOURNAL = 'p2-aurora-orgview-bootstrap.private.json'
CERT = 'p2-local-wso2-tls-pinned.pem'
TOKEN = 'p2-aurora-root-token.private.txt'
PARTNER_JOURNAL = 'p2-aurora-partner-create.private.json'

class Block(Exception):
    pass

def require(cond, code):
    if not cond:
        raise Block(code)

def safe_code(value):
    return value if isinstance(value, str) and re.fullmatch('[A-Z0-9_]{3,90}', value) else 'P2_V10_READINESS_UNEXPECTED_FAILURE'

def load_module(source):
    require(source.is_file() and not source.is_symlink(), 'M2M_SOURCE_MISSING')
    spec = importlib.util.spec_from_file_location('installed_p2_m2m', source)
    require(spec is not None and spec.loader is not None, 'M2M_SOURCE_INVALID')
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise Block('M2M_SOURCE_IMPORT_FAILED')
    return module

def verify_journal(module, record):
    require(isinstance(record, dict) and
        record.get('schema') == 'p2.24.aurora.m2m.bootstrap.v1' and
        record.get('phase') == 'COMPLETE' and
        record.get('tenant') == TENANT and
        record.get('appName') == 'P2 Aurora Organization View M2M' and
        record.get('scope') == VIEW_SCOPE and
        record.get('remoteWritesAttempted') == 2 and
        record.get('reconciledBy') == 'P2_24_GET_ONLY_AUTHORIZATION_READBACK_V8' and
        record.get('originalCreateResponseStillUnverified') is True and
        isinstance(record.get('appId'),str) and module.UUID.fullmatch(record['appId']) and
        module.hash_id(record['appId']) == APP_FP and
        isinstance(record.get('rootId'),str) and module.UUID.fullmatch(record['rootId']) and
        module.hash_id(record['rootId']) == ROOT_FP and
        isinstance(record.get('resourceId'),str) and module.API_ID.fullmatch(record['resourceId']),
        'COMPLETED_V8_VIEW_JOURNAL_MISMATCH')

def verify_certificate(module, cert):
    module.safe_private_file(cert, max_size=16384)
    try:
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text('ascii'))).hexdigest()
    except Exception:
        raise Block('PINNED_CERTIFICATE_INVALID')
    require(digest == CERT_SHA, 'PINNED_CERTIFICATE_CHANGED')

def api_scope_catalog(module, http, admin, view_id):
    """Two exact filters only; incomplete/paginated collections fail closed."""
    candidates=[]
    view_seen=[]
    for identifier in sorted(module.ALLOWED_API_IDENTIFIERS):
        query=urllib.parse.urlencode({'filter':'identifier eq '+identifier,'limit':'100'})
        status, doc, _ = http.call('GET', f'{module.API_ROOT}?{query}', basic=admin)
        require(status == 200, 'API_RESOURCE_FILTER_HTTP_NOT_200')
        rows=module._complete_filtered_api_resource_page(doc)
        require(len(rows)<=1, 'API_RESOURCE_FILTER_AMBIGUOUS')
        for row in rows:
            require(isinstance(row,dict) and row.get('identifier') == identifier and
                    isinstance(row.get('id'),str) and module.API_ID.fullmatch(row['id']),
                    'API_RESOURCE_SUMMARY_INVALID')
            status, full, _ = http.call('GET', f'{module.API_ROOT}/{row["id"]}', basic=admin)
            require(status == 200 and isinstance(full,dict) and
                    full.get('identifier') == identifier and full.get('id') == row['id'],
                    'API_RESOURCE_DETAIL_MISMATCH')
            scopes=full.get('scopes')
            require(isinstance(scopes,list), 'API_RESOURCE_SCOPES_MISSING')
            names=[]
            for scope in scopes:
                require(isinstance(scope,dict) and isinstance(scope.get('name'),str),
                        'API_RESOURCE_SCOPE_INVALID')
                names.append(scope['name'])
            require(len(names)==len(set(names)), 'API_RESOURCE_DUPLICATE_SCOPE')
            if VIEW_SCOPE in names: view_seen.append(row['id'])
            if CREATE_SCOPE in names: candidates.append(row['id'])
    require(view_seen == [view_id], 'VIEW_API_RESOURCE_CHANGED')
    require(len(candidates) == 1, 'CREATE_SCOPE_MISSING_OR_AMBIGUOUS')
    return module.hash_id(candidates[0])

def plan_cli(repo, module, private, record):
    env = {**os.environ, 'P2_PRIVATE_DIR':str(private),
           'P2_TOKEN_FILE':str(private/TOKEN),
           'P2_ROOT_ORG_ID':record['rootId'],
           'P2_ORIGIN':'https://localhost:9444',
           'NODE_EXTRA_CA_CERTS':str(private/CERT)}
    try:
        p=subprocess.run(['node','scripts/p2/cli.mjs','plan-partner'],cwd=repo,
                         env=env,capture_output=True,text=True,timeout=75,check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Block('PARTNER_PLAN_COMMAND_UNAVAILABLE')
    try:
        doc=json.loads(p.stdout if p.returncode==0 else p.stderr)
    except (ValueError, TypeError):
        raise Block('PARTNER_PLAN_JSON_INVALID')
    if p.returncode != 0:
        raise Block(safe_code(doc.get('code') if isinstance(doc,dict) else None))
    require(isinstance(doc,dict) and doc.get('phase')=='P2.24-P2.29' and
            doc.get('source')=='WSO2_API_RESPONSE' and doc.get('tenant')==TENANT and
            doc.get('runtimeEvidence')=='OPERATOR_EXECUTED' and
            isinstance(doc.get('result'),dict), 'PARTNER_PLAN_EVIDENCE_INVALID')
    result=doc['result']
    require(result.get('action')=='CREATE' and result.get('parentFingerprint')==ROOT_FP,
            'PARTNER_PLAN_NO_LONGER_CREATE')
    return result

def main():
    repo=Path.cwd().resolve()
    require((repo/'scripts/p2/cli.mjs').is_file() and
            (repo/'scripts/p2/guarded-org.mjs').is_file() and
            (repo/'scripts/ciam-v10.sh').is_file(), 'RUN_FROM_REPOSITORY_ROOT')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    module=load_module(repo/'scripts/p2/m2m_bootstrap.py')
    module.secure_dir(private)
    journal=module.read_json_private(private/JOURNAL)
    verify_journal(module, journal)
    verify_certificate(module,private/CERT)
    require(not (private/PARTNER_JOURNAL).exists() and not (private/PARTNER_JOURNAL).is_symlink(),
            'PARTNER_CREATE_JOURNAL_ALREADY_PRESENT')
    # Runtime pin validation is read-only: unchanged image and authority journal.
    module.runtime_guard(repo,private)
    admin=module.read_existing_authority_admin(repo)
    http=module.Http(str(private/CERT))
    # Existing readback refreshes only the local token file; no management writes.
    proof=module.verified_existing(http,private,admin,journal)
    require(proof.get('action')=='ALREADY_VERIFIED' and
            proof.get('remoteManagementWrites') == 0 and
            proof.get('tokenFileReady') is True and
            proof.get('applicationFingerprint') == APP_FP and
            proof.get('rootFingerprint') == ROOT_FP,
            'VIEW_CLIENT_RECHECK_FAILED')
    module.safe_private_file(private/TOKEN,max_size=8192)
    create_fp=api_scope_catalog(module,http,admin,journal['resourceId'])
    plan_cli(repo,module,private,journal)
    print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'PLAN_ONLY',
                      'code':'PARTNER_CREATE_SCOPE_DISCOVERED_NOT_GRANTED',
                      'managementWrites':0,'oauthTokenRequests':1,
                      'partnerExists':False,'partnerCreated':False,
                      'parentFingerprint':ROOT_FP,
                      'createResourceFingerprint':create_fp,
                      'requiredCreateScope':CREATE_SCOPE,
                      'existingViewM2MRemainsReadOnly':True,
                      'nextAction':'SEPARATELY_AUTHORIZE_GUARDED_PARTNER_CREATE_ACTOR'},
                     sort_keys=True,indent=2))

if __name__ == '__main__':
    try:
        main()
    except Block as exc:
        print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'BLOCKED',
                          'code':safe_code(str(exc)), 'managementWrites':0,
                          'noAutomaticRetry':True},sort_keys=True,indent=2))
        sys.exit(2)
    except Exception:
        print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'BLOCKED',
                          'code':'P2_V10_READINESS_UNEXPECTED_FAILURE',
                          'managementWrites':0, 'noAutomaticRetry':True},sort_keys=True,indent=2))
        sys.exit(2)
