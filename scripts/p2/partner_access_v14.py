#!/usr/bin/env python3
"""P2.24 V14: Aurora-only partner application-sharing live evidence.

Read-only management inspection. This is not a sharing grant, a delegated admin
session, or a business authorization decision. Never treats missing data as grant.
Existing V13 partner must pass authenticated independent verification first.
"""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse

TENANT = 'aurora.identity.test'
BASE = f'/t/{TENANT}/api/server/v1/applications'
ROOT_FP = '4548812d1a94a3ff'
PARTNER_FP = 'a9c40a10acabab52'
MAX_APPS = 50
MAX_PAGES = 20
PAGE_SIZE = 100

class Block(Exception): pass

def demand(value,code):
    if not value: raise Block(code)

def safe_code(e):
    if type(e) is Block and re.fullmatch(r'[A-Z][A-Z0-9_]{3,90}',str(e)):
        return str(e)
    return 'V14_READ_ONLY_EVIDENCE_UNAVAILABLE'

def uuid(m,value):
    return isinstance(value,str) and m.UUID.fullmatch(value) is not None

def load(path,name):
    demand(path.is_file() and not path.is_symlink(),'V14_DEPENDENCY_NOT_INSTALLED')
    s=importlib.util.spec_from_file_location(name,path)
    demand(s is not None and s.loader is not None,'V14_DEPENDENCY_IMPORT_INVALID')
    mod=importlib.util.module_from_spec(s)
    try: s.loader.exec_module(mod)
    except Exception: raise Block('V14_DEPENDENCY_IMPORT_FAILED')
    return mod

def next_page_href(href, app_id, seen):
    """Rebase only an allowed cursor; never follow untrusted href verbatim."""
    demand(isinstance(href,str) and 1<=len(href)<=2048,'V14_SHARE_NEXT_HREF_INVALID')
    u=urllib.parse.urlsplit(href)
    demand(not u.scheme and not u.netloc and not u.fragment and not u.username,
           'V14_SHARE_NEXT_FOREIGN_ORIGIN')
    expected=f'{BASE}/{app_id}/share'
    demand(u.path in (expected, expected.removeprefix(f'/t/{TENANT}')),
           'V14_SHARE_NEXT_FOREIGN_PATH')
    pairs=urllib.parse.parse_qsl(u.query,keep_blank_values=True,strict_parsing=True,max_num_fields=6)
    demand(len({k for k,v in pairs})==len(pairs),'V14_SHARE_NEXT_DUPLICATE_QUERY')
    params=dict(pairs)
    demand(set(params).issubset({'limit','recursive','after','next'}) and
           len(set(params).intersection({'after','next'}))==1 and
           params.get('recursive','false')=='false',
           'V14_SHARE_NEXT_UNSAFE_QUERY')
    cursor=params.get('after',params.get('next',''))
    demand(1<=len(cursor)<=512 and all(c.isalnum() or c in '+/=_-' for c in cursor),
           'V14_SHARE_NEXT_UNSAFE_CURSOR')
    demand(cursor not in seen,'V14_SHARE_CURSOR_LOOP')
    seen.add(cursor)
    lim=params.get('limit',str(PAGE_SIZE))
    demand(lim.isdecimal() and 1<=int(lim)<=PAGE_SIZE,'V14_SHARE_LIMIT_INVALID')
    return expected+'?'+urllib.parse.urlencode({'limit':int(lim),'recursive':'false',
                                      'after' if 'after' in params else 'next':cursor})

def read_shares(m,http,admin,app_id):
    demand(uuid(m,app_id),'V14_APP_ID_INVALID')
    expected=f'{BASE}/{app_id}/share'
    path=expected+f'?limit={PAGE_SIZE}&recursive=false'
    rows=[]; ids=set(); seen=set(); total=None; global_mode=None
    for _ in range(MAX_PAGES):
        status,doc,_=http.call('GET',path,basic=admin)
        demand(status==200 and isinstance(doc,dict),'V14_SHARE_GET_NOT_VERIFIED')
        links=doc.get('links',[])
        demand(isinstance(links,list),'V14_SHARE_LINKS_INVALID')
        nxt=[l for l in links if isinstance(l,dict) and l.get('rel')=='next']
        demand(len(nxt)<=1,'V14_SHARE_NEXT_AMBIGUOUS')
        # Never accept malformed link objects.
        demand(all(isinstance(l,dict) and isinstance(l.get('rel'),str) and
                   isinstance(l.get('href'),str) for l in links),
               'V14_SHARE_LINK_INVALID')
        if 'sharingMode' in doc:
            if global_mode is None: global_mode=doc['sharingMode']
            else: demand(global_mode==doc['sharingMode'],'V14_GLOBAL_SHARING_MODE_CHANGED')
        items=doc.get('organizations')
        n=doc.get('totalResults')
        if n is not None:
            demand(type(n) is int and 0<=n<=5000,'V14_SHARE_TOTAL_INVALID')
            if total is None: total=n
            demand(total==n,'V14_SHARE_TOTAL_CHANGED')
        if items is None:
            demand(n==0 and not nxt,'V14_SHARE_COLLECTION_OMITTED_UNVERIFIED')
            items=[]
        demand(isinstance(items,list) and len(items)<=PAGE_SIZE,
               'V14_SHARE_COLLECTION_INVALID')
        for item in items:
            demand(isinstance(item,dict) and uuid(m,item.get('id')) and item['id'] not in ids,
                   'V14_SHARE_ITEM_ID_INVALID_OR_DUPLICATE')
            ids.add(item['id']); rows.append(item)
        demand(total is None or len(rows)<=total,'V14_SHARE_EXCEEDS_TOTAL')
        if not nxt:
            demand(total is None or len(rows)==total,'V14_SHARE_INCOMPLETE_TOTAL')
            return rows,global_mode
        demand(items,'V14_SHARE_EMPTY_NEXT_PAGE')
        path=next_page_href(nxt[0]['href'],app_id,seen)
    raise Block('V14_SHARE_PAGE_LIMIT')

def interpret_shares(rows,global_mode,partner_id,root_id):
    """Read-only evidence classification; never returns business authorization."""
    # Even if the API lists no explicit partner row, a global policy may
    # include this partner or future children. Never infer NOT_SHARED first.
    if global_mode is not None:
        demand(isinstance(global_mode,dict),'V14_SHARE_GLOBAL_MODE_INVALID')
        if global_mode.get('policy') != 'SELECTED_ORG_ONLY':
            return 'BROAD_OR_GLOBAL_SHARING_REVIEW'
    related=[r for r in rows if r['id']==partner_id]
    demand(len(related)<=1,'V14_PARTNER_SHARE_DUPLICATE')
    if not related: return 'NOT_SHARED'
    obj=related[0]
    if obj.get('parentId') not in (None,root_id):
        raise Block('V14_SHARE_PARTNER_PARENT_DRIFT')
    if obj.get('status') not in (None,'ACTIVE'):
        raise Block('V14_SHARE_PARTNER_INACTIVE')
    if global_mode is not None:
        demand(isinstance(global_mode,dict),'V14_SHARE_GLOBAL_MODE_INVALID')
        if global_mode.get('policy')!='SELECTED_ORG_ONLY':
            return 'BROAD_OR_GLOBAL_SHARING_REVIEW'
    policy=(obj.get('sharingMode') or {}).get('policy')
    if policy is None: return 'PRESENT_POLICY_UNVERIFIED'
    if policy!='SELECTED_ORG_ONLY': return 'BROAD_OR_GLOBAL_SHARING_REVIEW'
    sharing=obj.get('sharingMode')
    role_sharing=sharing.get('roleSharing')
    if not isinstance(role_sharing,(dict,list)):
        return 'PRESENT_ROLES_UNVERIFIED'
    if isinstance(role_sharing,dict):
        if role_sharing.get('mode')!='SELECTED' or not isinstance(role_sharing.get('roles'),list):
            return 'PRESENT_ROLES_UNVERIFIED'
        roles=role_sharing['roles']
    else:
        if len(role_sharing)!=1 or role_sharing[0].get('mode')!='SELECTED':
            return 'PRESENT_ROLES_UNVERIFIED'
        roles=role_sharing[0].get('roles')
    if not isinstance(roles,list) or not roles:
        return 'PRESENT_ROLES_UNVERIFIED'
    if not all(isinstance(r,dict) and isinstance(r.get('displayName'),str) and
               isinstance(r.get('audience'),dict) for r in roles):
        return 'PRESENT_ROLES_UNVERIFIED'
    return 'TARGETED_APP_SHARE_POLICY_OBSERVED_BUSINESS_AUTH_UNTESTED'

def inspect(repo,private):
    v13=load(repo/'scripts/p2/partner_v13.py','p2_v14_existing_partner')
    # The existing V13 verify path authenticates to WSO2 and confirms parent,
    # child, creator and read-only M2M readbacks. No management write.
    partner=v13.main(['verify'])
    demand(partner.get('status')=='VERIFIED' and partner.get('managementWrites')==0 and
           partner.get('organizationFingerprint')==PARTNER_FP,
           'V14_V13_PARTNER_VERIFICATION_FAILED')
    v12=v13.import_v12(repo)
    m,_,_=v12.sources(repo)
    m.secure_dir(private)
    journal=m.read_json_private(private/v13.PARTNER_JOURNAL)
    demand(journal.get('schema')==v13.SCHEMA and journal.get('state')=='VERIFIED',
           'V14_PARTNER_JOURNAL_UNVERIFIED')
    partner_id=journal.get('details',{}).get('organizationId')
    root_id=journal.get('details',{}).get('parentId')
    demand(uuid(m,partner_id) and uuid(m,root_id) and
           m.hash_id(partner_id)==PARTNER_FP and m.hash_id(root_id)==ROOT_FP,
           'V14_PARTNER_JOURNAL_IDENTITY_DRIFT')
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/'p2-local-wso2-tls-pinned.pem'))
    apps=m.inventory(http,BASE,'applications',admin)
    demand(len(apps)<=MAX_APPS,'V14_APP_COUNT_EXCEEDS_BOUND')
    candidates=[]
    for row in apps:
        app_id=row.get('id')
        demand(uuid(m,app_id),'V14_APPLICATION_INVENTORY_INVALID')
        status,doc,_=http.call('GET',f'{BASE}/{app_id}',basic=admin)
        demand(status==200 and isinstance(doc,dict) and doc.get('id')==app_id,
               'V14_APP_DETAIL_UNVERIFIED')
        # No management apps, credential-bearing M2M or unlabeled apps are
        # considered business apps. This is only a candidate inventory.
        if doc.get('isManagementApp') is not False: continue
        oidc=(doc.get('inboundProtocolConfiguration') or {}).get('oidc') or {}
        grants=oidc.get('grantTypes')
        if isinstance(grants,list) and grants==['client_credentials']: continue
        if not isinstance(doc.get('name'),str) or not doc['name'].strip(): continue
        candidates.append(app_id)
    outcomes=[]
    for app_id in candidates:
        try:
            rows,mode=read_shares(m,http,admin,app_id)
        except Exception as e:
            # Organization management Basic rights do not imply the separate
            # application-sharing VIEW permission. A missing permission is an
            # explicit pending capability, not a startup failure or a grant.
            code=str(e)
            if type(e).__name__=='Block' and code in ('WSO2_GET_HTTP_401','WSO2_GET_HTTP_403','WSO2_GET_HTTP_404'):
                return {'status':'PENDING','code':'V14_SHARING_READBACK_PERMISSION_OR_ENDPOINT_NOT_VERIFIED',
                        'phase':'P2.24','tenant':TENANT,'managementWrites':0,
                        'candidateApplicationCount':len(candidates),
                        'businessAuthorizationVerified':False,
                        'delegatedAdministrationVerified':False,
                        'nextAction':'VERIFY_INTERNAL_SHARED_APPLICATION_VIEW_WITH_APPROVED_AUTHORITY'}
            # The GA response can omit organizations and totalResults. This
            # does NOT prove an empty share set. Keep inspecting other apps,
            # then report an explicitly unverified state at normal startup.
            # Audit mode still fails until a complete readback is observed.
            if type(e) is Block and code=='V14_SHARE_COLLECTION_OMITTED_UNVERIFIED':
                outcomes.append('COLLECTION_OMITTED_UNVERIFIED')
                continue
            raise
        outcomes.append(interpret_shares(rows,mode,partner_id,root_id))
    return sharing_report(outcomes,len(candidates))

def sharing_report(outcomes,candidate_count):
    """A pending readback is NEVER a negative or positive access decision."""
    counts={k:outcomes.count(k) for k in sorted(set(outcomes))}
    pending=counts.get('COLLECTION_OMITTED_UNVERIFIED',0)>0
    return {'status':'PENDING' if pending else 'INSPECTED',
            'code':('V14_SHARE_COLLECTION_UNVERIFIED_STARTUP_PENDING' if pending
                    else 'V14_PARTNER_APP_SHARING_READBACK_ONLY'),
            'phase':'P2.24','tenant':TENANT,'managementWrites':0,
            'partnerFingerprint':PARTNER_FP,'candidateApplicationCount':candidate_count,
            'shareEvidenceCounts':counts,
            'businessAuthorizationVerified':False,
            'delegatedAdministrationVerified':False,
            'nextAction':('VERIFY_GA_SHARING_RESPONSE_AND_APPROVE_PARTNER_APP' if pending
                          else 'SELECT_AND_AUTHORIZE_A_DEDICATED_PARTNER_BUSINESS_APP')}

def audit_ready(report):
    """Incomplete, broad, or absent sharing never passes an acceptance audit."""
    counts=report.get('shareEvidenceCounts',{})
    return (report.get('status')=='INSPECTED' and
            counts.get('TARGETED_APP_SHARE_POLICY_OBSERVED_BUSINESS_AUTH_UNTESTED',0)>0 and
            counts.get('BROAD_OR_GLOBAL_SHARING_REVIEW',0)==0 and
            counts.get('COLLECTION_OMITTED_UNVERIFIED',0)==0)

def main(args):
    demand(args in (['status'],['audit']),'V14_COMMAND_STATUS_OR_AUDIT_REQUIRED')
    repo=Path.cwd().resolve()
    demand((repo/'scripts/ciam-v10.sh').is_file(), 'V14_RUN_FROM_REPOSITORY_ROOT')
    private=Path(os.environ.get('P2_PRIVATE_DIR') or
                 str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()
    return inspect(repo,private)

if __name__=='__main__':
    mode=sys.argv[1:]
    try:
        out=main(mode)
        print(json.dumps(out,indent=2,sort_keys=True),flush=True)
        # 'status' is informational for startup: missing sharing never asserts
        # authorization and never blocks existing non-partner journeys.
        if mode==['audit'] and not audit_ready(out):
            sys.exit(2)
    except Exception as e:
        print(json.dumps({'status':'BLOCKED','code':safe_code(e),'phase':'P2.24',
            'tenant':TENANT,'managementWrites':0,
            'businessAuthorizationVerified':False,'delegatedAdministrationVerified':False},
            sort_keys=True),flush=True)
        # Fatal drift/unavailable runtime should stop startup; simply not shared
        # remains a normal INSPECTED result (feature not yet activated).
        sys.exit(2)
