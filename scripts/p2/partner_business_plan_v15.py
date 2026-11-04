#!/usr/bin/env python3
"""P2.24 V15: independent GA shared-app readback; never grants access.

Check the exact Aurora partner and existing V14 inspection, then inspect the
second documented GET-only shared-apps API for the same application candidates.
No scope elevation, management POST, application selection, or privilege claim.
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, re, sys
from pathlib import Path

TENANT = 'aurora.identity.test'
PARTNER_FP = 'a9c40a10acabab52'
ROOT_FP = '4548812d1a94a3ff'
APP_NAME = 'P2 Aurora Returns Partner Business Portal'
MAX_CANDIDATES = 50
MAX_SHARED = 1000
V14_SHA = '874b5643937417a05eef8e3cbc646c8651f0f54548779965c78fe4f12368c938'

class Block(Exception): pass

def need(value, code):
    if not value: raise Block(code)

def safe_code(e):
    return str(e) if type(e) is Block and re.fullmatch(r'[A-Z][A-Z0-9_]{4,88}',str(e)) else 'V15_READBACK_UNAVAILABLE'

def load(path, name):
    need(path.is_file() and not path.is_symlink(), 'V15_DEPENDENCY_MISSING')
    s = importlib.util.spec_from_file_location(name,path)
    need(s is not None and s.loader is not None, 'V15_IMPORT_BLOCKED')
    mod = importlib.util.module_from_spec(s)
    try: s.loader.exec_module(mod)
    except Exception: raise Block('V15_IMPORT_BLOCKED')
    return mod

def shape(doc, uuid, partner_id, root_id):
    """Explicit [] is evidence of an empty *shared-app mapping*, not /share policy."""
    if not isinstance(doc,dict):
        return 'COLLECTION_SCHEMA_UNVERIFIED'
    if 'sharedApplications' not in doc or doc['sharedApplications'] is None:
        return 'COLLECTION_OMITTED_UNVERIFIED'
    rows = doc['sharedApplications']
    if not isinstance(rows,list):
        return 'COLLECTION_SCHEMA_UNVERIFIED'
    need(len(rows)<=MAX_SHARED, 'V15_SHARED_APPS_COLLECTION_OVERSIZE')
    seen=set(); found=False; foreign=False
    for row in rows:
        need(isinstance(row,dict) and uuid(row.get('applicationId')) and uuid(row.get('organizationId')),
             'V15_SHARED_APPS_ITEM_INVALID')
        pair=(row['organizationId'],row['applicationId'])
        need(pair not in seen, 'V15_SHARED_APPS_DUPLICATE')
        seen.add(pair)
        need(row['organizationId'] != root_id, 'V15_SHARED_APPS_ROOT_REFERENCE_BLOCKED')
        if row['organizationId']==partner_id: found=True
        else: foreign=True
    if found and foreign: return 'PARTNER_AND_OTHER_ORG_REFERENCE_REVIEW'
    if found: return 'PARTNER_REFERENCE_POLICY_UNVERIFIED'
    if foreign: return 'OTHER_ORG_REFERENCE_NO_PARTNER_PROOF'
    return 'EXPLICIT_EMPTY_MAPPING_POLICY_UNVERIFIED'

def report(base,counts,collision):
    evidence={k:counts.count(k) for k in sorted(set(counts))}
    return {
      'status':'PENDING','code':'V15_GA_SHARED_APPS_CROSSCHECK_PENDING',
      'phase':'P2.24','tenant':TENANT,'mode':'READ_ONLY','managementWrites':0,
      'partnerFingerprint':PARTNER_FP,
      'candidateApplicationCount':base.get('candidateApplicationCount'),
      'crosscheckEvidenceCounts':evidence,
      'dedicatedBusinessAppName':APP_NAME,
      'dedicatedAppNameAlreadyExists':collision,
      'businessAuthorizationVerified':False,'delegatedAdministrationVerified':False,
      'nextAction':'APPROVE_DEDICATED_AURORA_PARTNER_BUSINESS_APP_AFTER_GA_READBACK'
    }

def inspect(repo, private):
    v14_file=repo/'scripts/p2/partner_access_v14.py'
    need(v14_file.is_file() and not v14_file.is_symlink() and
         hashlib.sha256(v14_file.read_bytes()).hexdigest()==V14_SHA,
         'V15_V14_SOURCE_PIN_MISMATCH')
    v14=load(v14_file,'p2_v15_v14_readback')
    base=v14.inspect(repo,private)
    need(base.get('status') in ('PENDING','INSPECTED') and
         base.get('managementWrites')==0 and base.get('partnerFingerprint')==PARTNER_FP and
         base.get('businessAuthorizationVerified') is False,
         'V15_V14_BASELINE_NOT_VERIFIED')
    v13=load(repo/'scripts/p2/partner_v13.py','p2_v15_v13_dependency')
    v12=v13.import_v12(repo)
    m,_,_=v12.sources(repo)
    m.secure_dir(private)
    journal=m.read_json_private(private/v13.PARTNER_JOURNAL)
    need(journal.get('state')=='VERIFIED','V15_PARTNER_JOURNAL_UNVERIFIED')
    details=journal.get('details',{})
    partner_id,root_id=details.get('organizationId'),details.get('parentId')
    need(v14.uuid(m,partner_id) and v14.uuid(m,root_id) and
         m.hash_id(partner_id)==PARTNER_FP and m.hash_id(root_id)==ROOT_FP,
         'V15_PARTNER_IDENTITY_DRIFT')
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/'p2-local-wso2-tls-pinned.pem'))
    apps=m.inventory(http,v14.BASE,'applications',admin)
    need(len(apps)<=v14.MAX_APPS,'V15_APP_LIMIT_EXCEEDED')
    candidates=[]; collisions=[]
    for item in apps:
        app_id=item.get('id')
        need(v14.uuid(m,app_id),'V15_APP_INVENTORY_INVALID')
        code,doc,_=http.call('GET',f'{v14.BASE}/{app_id}',basic=admin)
        need(code==200 and isinstance(doc,dict) and doc.get('id')==app_id,
             'V15_APP_DETAIL_INVALID')
        if doc.get('name')==APP_NAME: collisions.append(app_id)
        if doc.get('isManagementApp') is not False: continue
        grants=((doc.get('inboundProtocolConfiguration') or {}).get('oidc') or {}).get('grantTypes')
        if isinstance(grants,list) and grants==['client_credentials']: continue
        if not isinstance(doc.get('name'),str) or not doc['name'].strip(): continue
        candidates.append(app_id)
    need(len(collisions)<=1,'V15_DEDICATED_APP_NAME_COLLISION')
    need(len(candidates)<=MAX_CANDIDATES,'V15_CANDIDATE_LIMIT_EXCEEDED')
    need(len(candidates)==base['candidateApplicationCount'],
         'V15_APP_INVENTORY_CHANGED_DURING_INSPECTION')
    counts=[]
    for app_id in candidates:
        try:
            code,doc,_=http.call('GET',f'{v14.BASE}/{app_id}/shared-apps',basic=admin)
        except Exception as e:
            # The existing verified HTTP transport may raise instead of
            # returning non-200 status. Missing permission is pending.
            if type(e).__name__=='Block' and str(e) in (
                'WSO2_GET_HTTP_401','WSO2_GET_HTTP_403','WSO2_GET_HTTP_404'):
                counts.append('ENDPOINT_OR_PERMISSION_UNVERIFIED')
                continue
            raise
        if code in (401,403,404):
            counts.append('ENDPOINT_OR_PERMISSION_UNVERIFIED')
            continue
        need(code==200,'V15_SHARED_APPS_HTTP_UNEXPECTED')
        counts.append(shape(doc,lambda value:v14.uuid(m,value),partner_id,root_id))
    return report(base,counts,bool(collisions))

def main(args):
    need(args==['status'],'V15_COMMAND_STATUS_ONLY')
    repo=Path.cwd().resolve()
    need((repo/'scripts/ciam-v10.sh').is_file(),'V15_RUN_FROM_REPOSITORY_ROOT')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    return inspect(repo,private)

if __name__=='__main__':
    try:
        print(json.dumps(main(sys.argv[1:]),sort_keys=True,indent=2),flush=True)
    except Exception as e:
        print(json.dumps({'status':'BLOCKED','code':safe_code(e),'phase':'P2.24',
                          'tenant':TENANT,'managementWrites':0,
                          'businessAuthorizationVerified':False,
                          'delegatedAdministrationVerified':False},sort_keys=True),flush=True)
        sys.exit(2)
