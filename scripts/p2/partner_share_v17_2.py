#!/usr/bin/env python3
"""V17.2: empirically calibrate WSO2 7.3 GA's {} sharing empty state.

Before *any* V17 write, prove the SAME authenticated GET interfaces return
nonempty, cross-matching sharing records for a pre-existing unrelated app,
then prove the new V16.3 app has exactly {} on four readback views twice.
No existing-app modifications. No exception to V17's write-ahead intent,
single-POST, selected-org-only, role-NONE, or no-blind-retry rules.
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, re, sys, time, urllib.parse
from pathlib import Path

TENANT='aurora.identity.test'
V17_SHA='fea42472a4a91d4d04c368131ae4e569b5dc1aa8ce8eb5fe8040ccee344f6a53'
V17='scripts/p2/partner_share_v17.py'
STAGE='V17_2'

class Refuse(Exception): pass
def need(ok,code):
    if not ok:raise Refuse(code)

def load_v17(repo):
    path=repo/V17
    need(path.is_file() and not path.is_symlink() and
         hashlib.sha256(path.read_bytes()).hexdigest()==V17_SHA,
         'V17_2_PINNED_V17_SOURCE_CHANGED')
    spec=importlib.util.spec_from_file_location('v17_for_ga_calibration',path)
    need(spec is not None and spec.loader is not None,'V17_2_DEPENDENCY_MISSING')
    module=importlib.util.module_from_spec(spec)
    try: spec.loader.exec_module(module)
    except Exception:raise Refuse('V17_2_DEPENDENCY_IMPORT_FAILED')
    return module

def empty_portal_views(http,admin,app_id,partner_id,base):
    """All 4 response objects must literally equal {}; no missing grant inferred."""
    filtered=urllib.parse.urlencode({'filter':f'id eq {partner_id}',
                                      'recursive':'false','attributes':'sharingMode'})
    views=(f'{base}/{app_id}/share?limit=100&recursive=false',
           f'{base}/{app_id}/share?'+filtered,
           f'{base}/{app_id}/share?attributes=sharingMode&recursive=false',
           f'{base}/{app_id}/shared-apps')
    for path in views:
        try:status,body,_=http.call('GET',path,basic=admin)
        except Exception:return False
        if status!=200 or type(body) is not dict or body != {}:return False
    return True

def positive_control(m,http,admin,v14,app_id,partner_id,base):
    """A remote, *existing* application's populated sharing is a positive control.

    Both documented GETs must agree on at least one organization. A 200 {}
    for the new portal is *never* used as absence evidence without this.
    """
    try:apps=m.inventory(http,base,'applications',admin)
    except Exception:raise Refuse('V17_2_CONTROL_INVENTORY_UNVERIFIED')
    need(type(apps) is list and 1<=len(apps)<=50,
         'V17_2_CONTROL_INVENTORY_INCOMPLETE')
    seen=set(); controls=0
    for row in apps:
        need(type(row) is dict and isinstance(row.get('id'),str) and
             bool(m.UUID.fullmatch(row['id'])) and row['id'] not in seen,
             'V17_2_CONTROL_ID_INVALID')
        candidate=row['id'];seen.add(candidate)
        if candidate==app_id:continue
        try:
            status,detail,_=http.call('GET',f'{base}/{candidate}',basic=admin)
        except Exception:raise Refuse('V17_2_CONTROL_DETAILS_UNVERIFIED')
        need(status==200 and type(detail) is dict and detail.get('id')==candidate,
             'V17_2_CONTROL_DETAILS_CHANGED')
        if detail.get('isManagementApp') is not False:continue
        try:orgs,global_mode=v14.read_shares(m,http,admin,candidate)
        except Exception as e:
            if str(e)=='V14_SHARE_COLLECTION_OMITTED_UNVERIFIED':continue
            raise Refuse('V17_2_POSITIVE_SHARE_READBACK_UNVERIFIED')
        need(type(orgs) is list and len(orgs)<=1000,
             'V17_2_CONTROL_SHARE_ROWS_UNVERIFIED')
        if not orgs:continue
        ids=set()
        for org in orgs:
            need(type(org) is dict and isinstance(org.get('id'),str) and
                 bool(m.UUID.fullmatch(org['id'])) and org['id'] not in ids,
                 'V17_2_CONTROL_SHARE_ROW_INVALID')
            ids.add(org['id'])
        try:status,shared,_=http.call('GET',f'{base}/{candidate}/shared-apps',basic=admin)
        except Exception:raise Refuse('V17_2_POSITIVE_MAPPING_READBACK_UNVERIFIED')
        need(status==200 and type(shared) is dict,
             'V17_2_POSITIVE_MAPPING_SHAPE_INVALID')
        mappings=shared.get('sharedApplications')
        if mappings is None:continue
        need(type(mappings) is list and len(mappings)<=1000,
             'V17_2_POSITIVE_MAPPING_ROWS_INVALID')
        mapped=set()
        for entry in mappings:
            need(type(entry) is dict and isinstance(entry.get('applicationId'),str) and
                 bool(m.UUID.fullmatch(entry['applicationId'])) and
                 isinstance(entry.get('organizationId'),str) and
                 bool(m.UUID.fullmatch(entry['organizationId'])),
                 'V17_2_POSITIVE_MAPPING_ITEM_INVALID')
            pair=(entry['applicationId'],entry['organizationId'])
            need(pair not in mapped,'V17_2_POSITIVE_MAPPING_DUPLICATE')
            mapped.add(pair)
        if any(organization_id in ids for _,organization_id in mapped):
            controls+=1
    need(app_id in seen,'V17_2_PORTAL_NOT_IN_INVENTORY')
    return controls

def calibrate(v17,m,http,admin,v14,app_id,partner_id,root_id):
    """Never return EMPTY when normal V17 remote evidence is nonempty."""
    state=v17.reconcile_snapshot(m,http,admin,v14,app_id,partner_id,root_id)
    if state!='PENDING':return state,False,0
    controls=positive_control(m,http,admin,v14,app_id,partner_id,v17.BASE)
    if controls==0:return 'PENDING',False,0
    # First and second complete inspections each include the filtered and
    # policy view. Each response must be exactly {}, not a silent 403 or 200
    # with an omitted collection and other unreviewed fields.
    for _ in range(2):
        if not empty_portal_views(http,admin,app_id,partner_id,v17.BASE):
            return 'PENDING',False,controls
    # Repeat original V17 readback to catch a concurrent remote share.
    state=v17.reconcile_snapshot(m,http,admin,v14,app_id,partner_id,root_id)
    return ('EMPTY' if state=='PENDING' else state),state=='PENDING',controls

def apply(v17,m,http,admin,v14,private,app_id,partner_id,root_id,command,
          poster=None,sleeper=time.sleep,calibrator=calibrate):
    template=v17.journal_template(app_id,partner_id,v17.body_for(app_id,partner_id))
    file=private/v17.JOURNAL
    # An existing journal MUST use existing V17's strict readback-only path.
    # This branch can never repeat a POST, including ambiguous INTENT.
    if m.safe_private_file(file,required=False):
        return v17.apply_or_check(m,http,admin,v14,private,app_id,partner_id,root_id,
                                  'reconcile',submit=poster or v17.post_once,sleeper=sleeper)
    state,calibrated,count=calibrator(v17,m,http,admin,v14,app_id,partner_id,root_id)
    if state=='EXACT':raise Refuse('V17_2_UNOWNED_SHARE_BLOCKED')
    if state=='PENDING':
        return v17.report('PENDING','V17_2_GA_EMPTY_STATE_NOT_ATTESTED',
            journalState='ABSENT',positiveControlCount=count,
            nextAction='VERIFY_POSITIVE_CONTROL_OR_SHARE_VIEW_PERMISSION')
    need(state=='EMPTY','V17_2_UNEXPECTED_SHARING_STATE')
    if command!='bootstrap':
        return v17.report('PLAN_ONLY','V17_2_CONTROLLED_PREWRITE_READY',
             journalState='ABSENT',positiveControlCount=count,
             calibratedGaEmptyState=calibrated,approvedPolicy=v17.POLICY,
             roleSharingMode=v17.ROLE_MODE)
    # Recheck under the same private lock directly before intent, to minimize
    # the race window. No POST if control or empty evidence has changed.
    state,calibrated,count=calibrator(v17,m,http,admin,v14,app_id,partner_id,root_id)
    if state!='EMPTY':return v17.report('PENDING','V17_2_PREWRITE_STATE_CHANGED',
        journalState='ABSENT',positiveControlCount=count)
    m.exclusive_json(file,template)  # Exclusive, fsynced write-ahead journal.
    try:(poster or v17.post_once)(private/'p2-local-wso2-tls-pinned.pem',admin,app_id,partner_id)
    except Exception:raise Refuse('V17_2_POST_OUTCOME_UNKNOWN_NEVER_RETRY')
    for i in range(4):
        observed=v17.reconcile_snapshot(m,http,admin,v14,app_id,partner_id,root_id)
        if observed=='EXACT':
            m.replace_json(file,{**template,'state':'VERIFIED','postAcknowledged':True})
            return v17.report('VERIFIED','V17_2_PARTNER_ONLY_SHARE_COMPLETED_AND_READBACK_VERIFIED',
                journalState='VERIFIED',managementWritesAttempted=1,sharingVerified=True,
                approvedPolicy=v17.POLICY,roleSharingMode=v17.ROLE_MODE)
        need(observed in ('EMPTY','PENDING'),'V17_2_ASYNC_SHARE_CONFLICT')
        if i<3:sleeper(0.6)
    return v17.report('PENDING','V17_2_ASYNC_ACCEPTED_READBACK_PENDING_NO_RETRY',
        journalState='INTENT',managementWritesAttempted=1,
        nextAction='GET_ONLY_RECONCILIATION')

def main(args,repo=None,private=None):
    need(args in (['bootstrap'],['status'],['reconcile']),'V17_2_COMMAND_INVALID')
    repo=(repo or Path.cwd()).resolve(strict=True)
    private=(private or Path(os.environ.get('P2_PRIVATE_DIR') or
             str(Path.home()/'wso2-ciam-v10/private'))).expanduser().absolute()
    v17=load_v17(repo)
    v16,m,http,admin,v14,app_id,partner_id,root_id=v17.runtime(repo,private)
    with v16.locked(private):
        return apply(v17,m,http,admin,v14,private,app_id,partner_id,root_id,args[0])

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),indent=2,sort_keys=True),flush=True)
    except Exception as e:
        code=str(e) if isinstance(e,Refuse) and re.fullmatch(r'V17_2_[A-Z0-9_]+',str(e)) else 'V17_2_BLOCKED_CHECK_PRIVATE_JOURNAL'
        print(json.dumps({'status':'BLOCKED','code':code,'phase':'P2.24','tenant':TENANT,
               'managementWritesAttempted':'UNKNOWN_CHECK_PRIVATE_JOURNAL',
               'noAutomaticRetry':True,'businessAuthorizationVerified':False,
               'delegatedAdministrationVerified':False,'partnerLoginEnabled':False},
               indent=2,sort_keys=True),flush=True)
        sys.exit(2)
