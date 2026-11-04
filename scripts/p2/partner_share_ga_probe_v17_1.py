#!/usr/bin/env python3
"""V17.1 safe GA schema probe. GET only; no access decision, no journal writes.

The V17 safe prewrite guard remains untouched. This tool reports only bounded
field PRESENCE, TYPES and COUNTS from three documented application sharing GETs.
Never print an organization/application ID, URL, credential or arbitrary JSON.
"""
from __future__ import annotations
import hashlib,importlib.util,json,os,re,sys,urllib.parse
from pathlib import Path

TENANT='aurora.identity.test'
APP_FP='7b4495d1ff5af7fd'
PARTNER_FP='a9c40a10acabab52'
SOURCE_SHA='7fd3d6ffeb069cc6eef43e98a4a67c3406a9ac4777965639c9c0e0c19daa4395'
JOURNAL='p2-aurora-partner-only-share-v17.private.json'
FIELDS=('organizations','sharedApplications','sharingMode','links','totalResults',
        'isManagementApp','id','name','inboundProtocolConfiguration')
BASE=f'/t/{TENANT}/api/server/v1/applications'

class Refuse(Exception):pass
def need(ok,code):
    if not ok:raise Refuse(code)
def present(obj,k):
    if k not in obj:return 'OMITTED'
    if obj[k] is None:return 'NULL'
    return 'PRESENT'
def maybe_policy(value):
    if value is None:return 'OMITTED'
    if not isinstance(value,dict):return 'INVALID'
    policy=value.get('policy')
    if policy=='SELECTED_ORG_ONLY':return 'SELECTED_ORG_ONLY'
    if policy is None:return 'OMITTED'
    if isinstance(policy,str):return 'OTHER_POLICY'
    return 'INVALID'
def maybe_roles(mode):
    if not isinstance(mode,dict):return 'OMITTED'
    r=mode.get('roleSharing')
    if isinstance(r,list):r=r[0] if len(r)==1 else None
    if not isinstance(r,dict):return 'OMITTED'
    t=r.get('mode')
    return t if t in ('NONE','ALL','SELECTED') else 'UNKNOWN'
def item_counts(rows, id_field, expected_id):
    counts={'count':len(rows),'targetMatches':0,'otherIdentityCount':0,
            'missingIdentityCount':0,'selectedPolicyCount':0,
            'otherPolicyCount':0,'explicitNoRolesCount':0,'roleModeMissingCount':0,
            'broadRoleModeCount':0}
    if len(rows)>1000:return {'shape':'OVERSIZED'}
    for row in rows:
        if not isinstance(row,dict):return {'shape':'INVALID_ITEM'}
        val=row.get(id_field)
        if not isinstance(val,str):counts['missingIdentityCount']+=1
        elif val==expected_id:counts['targetMatches']+=1
        else:counts['otherIdentityCount']+=1
        sharing=row.get('sharingMode')
        p=maybe_policy(sharing)
        if p=='SELECTED_ORG_ONLY':counts['selectedPolicyCount']+=1
        elif p!='OMITTED':counts['otherPolicyCount']+=1
        r=maybe_roles(sharing)
        if r=='NONE':counts['explicitNoRolesCount']+=1
        elif r=='OMITTED':counts['roleModeMissingCount']+=1
        else:counts['broadRoleModeCount']+=1
    return counts

def summarize(kind,doc,partner_id,app_id):
    if not isinstance(doc,dict):return {'responseShape':'NON_OBJECT'}
    out={'responseShape':'OBJECT','topLevelKeyCount':min(len(doc),1000),
         'recognizedFieldsPresent':sorted(k for k in FIELDS if k in doc),
         'unrecognizedFieldCount':max(0,len(doc)-sum(k in doc for k in FIELDS))}
    if 'totalResults' in doc:
        t=doc['totalResults']
        out['totalResults']=t if type(t) is int and 0<=t<=1000 else 'UNTRUSTED'
    if 'links' in doc:
        links=doc['links']
        if isinstance(links,list) and len(links)<=100:
            out['pagination']={'linkCount':len(links),
                'nextLinkCount':sum(isinstance(i,dict) and i.get('rel')=='next' for i in links),
                'nonNextLinkCount':sum(not isinstance(i,dict) or i.get('rel')!='next' for i in links)}
        else:out['pagination']={'shape':'INVALID'}
    sm=doc.get('sharingMode')
    if 'sharingMode' in doc:
        out['globalPolicy']=maybe_policy(sm)
        out['globalRoleMode']=maybe_roles(sm)
    key='sharedApplications' if kind=='shared-apps' else 'organizations'
    out['collectionPresence']=present(doc,key)
    if kind=='application':
        out['idMatchesPinnedApplication']=doc.get('id')==app_id
        out['isManagementApp']=doc.get('isManagementApp') if type(doc.get('isManagementApp')) is bool else 'UNSPECIFIED'
    elif kind=='shared-apps' and isinstance(doc.get(key),list):
        rows=doc[key]
        out['collection']={'shape':'OVERSIZED'} if len(rows)>1000 else {
            'count':len(rows),
            'targetOrgReferences':sum(isinstance(r,dict) and r.get('organizationId')==partner_id for r in rows),
            'otherOrgReferences':sum(isinstance(r,dict) and isinstance(r.get('organizationId'),str) and r.get('organizationId')!=partner_id for r in rows),
            'invalidItemCount':sum(not isinstance(r,dict) or not isinstance(r.get('organizationId'),str) or not isinstance(r.get('applicationId'),str) for r in rows)}
    elif kind=='share' and isinstance(doc.get(key),list):
        out['collection']=item_counts(doc[key],'id',partner_id)
    return out

def call_inspect(http,path,kind,admin,partner_id,app_id):
    need(path.startswith(BASE+'/') and ('/share' in path or path==f'{BASE}/{app_id}'),
         'V17_1_GET_PATH_NOT_PINNED')
    try:
        status,doc,_=http.call('GET',path,basic=admin)
        if status!=200:
            return {'httpStatus':status if type(status) is int and 100<=status<=599 else 'UNVERIFIED',
                    'responseShape':'NOT_INSPECTED'}
        return {'httpStatus':200,**summarize(kind,doc,partner_id,app_id)}
    except Exception as e:
        code=str(e)
        if re.fullmatch(r'WSO2_GET_HTTP_(401|403|404|400|500|502|503)',code):
            return {'httpStatus':int(code[-3:]),'responseShape':'NOT_INSPECTED'}
        return {'httpStatus':'UNVERIFIED','responseShape':'NOT_INSPECTED'}

def snapshot(http,admin,app_id,partner_id):
    need(bool(re.fullmatch(r'[a-fA-F0-9-]{36}',app_id)) and
         bool(re.fullmatch(r'[a-fA-F0-9-]{36}',partner_id)),'V17_1_INVALID_PINNED_ID')
    fixed=f'{BASE}/{app_id}'
    filtered=urllib.parse.urlencode({'filter':f'id eq {partner_id}',
                                      'recursive':'false','attributes':'sharingMode'})
    paths=(('shareDefault',fixed+'/share?limit=100&recursive=false','share'),
           ('shareFiltered',fixed+'/share?'+filtered,'share'),
           ('sharePolicy',fixed+'/share?attributes=sharingMode&recursive=false','share'),
           ('sharedApps',fixed+'/shared-apps','shared-apps'),
           ('application',fixed,'application'))
    return {key:call_inspect(http,path,kind,admin,partner_id,app_id)
            for key,path,kind in paths}

def main(args,repo=None,private=None):
    need(args==['inspect'],'V17_1_COMMAND_INSPECT_ONLY')
    repo=(repo or Path.cwd()).resolve(strict=True)
    private=private or Path(os.environ.get('P2_PRIVATE_DIR') or
       str(Path.home()/'wso2-ciam-v10/private')).expanduser()
    private=private.absolute()
    source=repo/'scripts/p2/partner_share_v17.py'
    need(source.is_file() and not source.is_symlink() and
         hashlib.sha256(source.read_bytes()).hexdigest()==SOURCE_SHA,
         'V17_1_V17_SOURCE_PIN_MISMATCH')
    need((repo/'scripts/ciam-v10.sh').is_file(),'V17_1_REPO_INVALID')
    spec=importlib.util.spec_from_file_location('v17_readonly_probe',source)
    need(spec is not None and spec.loader is not None,'V17_1_V17_IMPORT_INVALID')
    v17=importlib.util.module_from_spec(spec)
    try:spec.loader.exec_module(v17)
    except Exception:raise Refuse('V17_1_V17_IMPORT_FAILED')
    _,m,http,admin,_,app_id,partner_id,_=v17.runtime(repo,private)
    need(m.hash_id(app_id)==APP_FP and m.hash_id(partner_id)==PARTNER_FP,
         'V17_1_PINNED_AUTHORITY_CHANGED')
    journal=private/JOURNAL
    # Fail closed if the journaling situation is unknown. Read but never edit.
    if journal.is_symlink():raise Refuse('V17_1_PRIVATE_JOURNAL_UNSAFE')
    if journal.exists():
        rec=m.read_json_private(journal)
        need(isinstance(rec,dict) and rec.get('state') in ('INTENT','VERIFIED') and
             rec.get('schema')==v17.SCHEMA,'V17_1_PRIVATE_JOURNAL_UNVERIFIED')
        journal_state=rec['state']
    else:journal_state='ABSENT'
    probes=snapshot(http,admin,app_id,partner_id)
    return {'status':'INSPECTED','code':'V17_1_GA_SHARING_SCHEMA_DIAGNOSTIC',
        'tenant':TENANT,'phase':'P2.24','mode':'GET_ONLY',
        'managementWrites':0,'journalState':journal_state,
        'sharingVerified':False,'businessAuthorizationVerified':False,
        'automaticV17BootstrapUnchanged':True,
        'shareNowAuthorizedByProbe':False,
        'schemaEvidence':probes,
        'nextAction':'REVIEW_EMPTY_STATE_SERIALIZATION_AND_VIEW_PERMISSIONS'}

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),indent=2,sort_keys=True),flush=True)
    except Exception as e:
        code=str(e) if isinstance(e,Refuse) and re.fullmatch(r'V17_1_[A-Z0-9_]+',str(e)) else 'V17_1_READ_ONLY_PROBE_BLOCKED'
        print(json.dumps({'status':'BLOCKED','code':code,'tenant':TENANT,'managementWrites':0,
                          'sharingVerified':False},sort_keys=True),flush=True)
        sys.exit(2)
