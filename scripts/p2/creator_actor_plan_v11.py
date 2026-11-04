#!/usr/bin/env python3
"""P2.24 — GET-only Aurora partner-creator actor existence + permission plan.

Does not create M2M apps, authorize API resources, mint create-scope tokens,
or create partners. Invokes only existing read-only WSO2 authority/M2M checks,
GET requests and one OAuth token request to refresh the existing view token.
No manual secret or UUID inputs; all security controls remain in place.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import sys
import urllib.parse

ROOT_DIR = Path(__file__).resolve().parent
TENANT='aurora.identity.test'
ACTOR_NAME='P2 Aurora Partner Creation M2M'
ACTOR_DESCRIPTION='P2.24 one-time Aurora partner onboarding: organization creation only; no delegated administration or business permissions.'
CREATE_SCOPE='internal_org_organization_create'
VIEW_SCOPE='internal_org_organization_view'
REQUIRED_GRANTS=('client_credentials',)
EXPECTED_FP='4548812d1a94a3ff'
EXPECTED_CREATE_RESOURCE_FP='92f29d96655bba10'
MAX_APPS=4000

class Block(Exception): pass

def require(value, code):
    if not value: raise Block(code)

def safe_code(value):
    return value if isinstance(value,str) and re.fullmatch(r'[A-Z0-9_]{3,90}',value) else 'ACTOR_PLAN_UNEXPECTED_FAILURE'

def load_v10():
    src=ROOT_DIR/'readiness_v10.py'
    require(src.is_file() and not src.is_symlink(),'READINESS_V10_SOURCE_MISSING')
    spec=importlib.util.spec_from_file_location('p2_readiness_v10', src)
    require(spec is not None and spec.loader is not None,'READINESS_V10_SOURCE_INVALID')
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def intended_actor_spec():
    return {'name':ACTOR_NAME,'description':ACTOR_DESCRIPTION,
            'tenantDomain':TENANT,'grantTypes':list(REQUIRED_GRANTS),
            'authorizedScopes':[CREATE_SCOPE],
            'managementApp':True,'existingViewClientMustRemainReadOnly':True,
            'rootOrganizationFingerprint':EXPECTED_FP}

def plan_fingerprint(spec,resource_fp):
    """Digest of immutable public intent only; never encode or hash secrets."""
    data={'actorSpec':spec,'createResourceFingerprint':resource_fp}
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]

def classify_actor_inventory(apps, view_app_id, *, uuid_pattern):
    """Classify a COMPLETE Aurora application inventory; never adopt by name alone."""
    require(isinstance(apps,list) and len(apps)<=MAX_APPS,'APP_INVENTORY_INCOMPLETE')
    require(isinstance(view_app_id,str) and bool(uuid_pattern.fullmatch(view_app_id)), 'VIEW_APP_ID_INVALID')
    seen=set(); matches=[]; view_seen=False
    for app in apps:
        require(isinstance(app,dict) and isinstance(app.get('id'),str)
                and bool(uuid_pattern.fullmatch(app['id'])),'APP_INVENTORY_ITEM_INVALID')
        require(isinstance(app.get('name'),str) and 0 < len(app['name']) <= 512,'APP_INVENTORY_NAME_INVALID')
        require(app['id'] not in seen,'APP_INVENTORY_DUPLICATE_ID')
        seen.add(app['id'])
        view_seen |= app['id']==view_app_id
        if app['name']==ACTOR_NAME: matches.append(app['id'])
    require(view_seen,'PINNED_VIEW_APPLICATION_NOT_IN_INVENTORY')
    require(len(matches)<=1,'MULTIPLE_CREATOR_APPLICATIONS_REQUIRES_RECONCILIATION')
    require(view_app_id not in matches,'VIEW_APPLICATION_MUST_NOT_BE_CREATOR')
    if matches:
        return 'CREATOR_APP_EXISTS_REQUIRES_INDEPENDENT_OWNERSHIP_RECONCILIATION'
    return 'CREATOR_APP_ABSENT_SEPARATE_APPROVAL_REQUIRED'

def check_no_mutation_journals(private):
    for name in ('p2-aurora-partner-create.private.json',
                 'p2-aurora-partner-creator-bootstrap.private.json'):
        path=private/name
        require(not path.exists() and not path.is_symlink(),
                'EXISTING_PARTNER_OR_CREATOR_JOURNAL_STOP')

def prepare(repo,private,v10,m):
    # Verify existing audit evidence with the exact previously source-tested v10 rules.
    m.secure_dir(private)
    record=m.read_json_private(private/v10.JOURNAL)
    v10.verify_journal(m,record)
    v10.verify_certificate(m,private/v10.CERT)
    check_no_mutation_journals(private)
    m.runtime_guard(repo,private)
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/v10.CERT))
    existing=m.verified_existing(http,private,admin,record)
    require(isinstance(existing,dict) and existing.get('action')=='ALREADY_VERIFIED'
            and existing.get('remoteManagementWrites')==0
            and existing.get('tokenFileReady') is True
            and existing.get('applicationFingerprint')==v10.APP_FP
            and existing.get('rootFingerprint')==v10.ROOT_FP,
            'EXISTING_VIEW_CLIENT_READBACK_FAILED')
    m.safe_private_file(private/v10.TOKEN,max_size=8192)
    fp=v10.api_scope_catalog(m,http,admin,record['resourceId'])
    require(fp==EXPECTED_CREATE_RESOURCE_FP,'CREATOR_SCOPE_RESOURCE_FINGERPRINT_DRIFT')
    v10.plan_cli(repo,m,private,record)
    apps=m.inventory(http,m.APP_ROOT,'applications',admin)
    state=classify_actor_inventory(apps,record['appId'],uuid_pattern=m.UUID)
    spec=intended_actor_spec()
    return {'phase':'P2.24','tenant':TENANT,'status':'PLAN_ONLY',
            'code':state,'mode':'GET_ONLY_MANAGEMENT_PLUS_TOKEN_REFRESH',
            'managementWrites':0,'partnerCreated':False,
            'viewM2MRemainsReadOnly':True,
            'viewM2MApplicationFingerprint':v10.APP_FP,
            'rootFingerprint':v10.ROOT_FP,
            'creationResourceFingerprint':fp,
            'actorSpecFingerprint':plan_fingerprint(spec,fp),
            'actorExisting':state.startswith('CREATOR_APP_EXISTS'),
            'existingApplicationsCount':len(apps),
            'proposedScope':CREATE_SCOPE,
            'nextAction':'SEPARATE_CREATE_ACTOR_APPROVAL_AND_WRITE_AHEAD_IMPLEMENTATION'}

def main():
    repo=Path.cwd().resolve()
    require((repo/'scripts/ciam-v10.sh').is_file() and
            (repo/'scripts/p2/cli.mjs').is_file() and
            (repo/'scripts/p2/m2m_bootstrap.py').is_file(), 'RUN_FROM_REPOSITORY_ROOT')
    v10=load_v10()
    m=v10.load_module(repo/'scripts/p2/m2m_bootstrap.py')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    return prepare(repo,private,v10,m)

if __name__=='__main__':
    try:
        print(json.dumps(main(),indent=2,sort_keys=True))
    except Exception as e:
        code=safe_code(str(e)) if type(e).__name__ == 'Block' else 'ACTOR_PLAN_UNEXPECTED_FAILURE'
        print(json.dumps({'phase':'P2.24','tenant':TENANT,'status':'BLOCKED',
                          'code':code,'managementWrites':0,'noAutomaticRetry':True},indent=2,sort_keys=True))
        sys.exit(2)
