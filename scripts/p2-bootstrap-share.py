#!/usr/bin/env python3
"""P2.24: bounded Aurora-only application sharing with verified WSO2 readback.

Called by the existing P2 CLI after it has verified the partner identity and parent.
No interactive credentials, cross-tenant applications, unscoped roles, or blind write retries.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / 'scripts' / 'p2-bootstrap-authority.py'
PARTNER_NAME = 'Verde Logistics'
PARTNER_HANDLE = 'verde-logistics'
DOMAIN = 'aurora.identity.test'
PARTNER_SCOPES = ('internal_org_organization_view', 'internal_org_user_mgt_list',
                  'internal_org_user_mgt_view', 'internal_org_group_mgt_view',
                  'internal_org_group_mgt_create', 'internal_org_group_mgt_update')
# IDs are loaded from the existing verified private authority journal, while
# the candidate child UUID must be independently rechecked against WSO2.
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)

spec = importlib.util.spec_from_file_location('p224_authority_existing', BASE)
if spec is None or spec.loader is None:
    raise RuntimeError('EXISTING_AUTHORITY_SOURCE_UNREADABLE')
authority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority)

class Stop(Exception):
    pass

def must(value, code):
    if not value:
        raise Stop(code)
    return value

def check_partner_id(partner_id):
    must(isinstance(partner_id,str) and UUID.fullmatch(partner_id),
         'P2_SHARE_PARTNER_ID_INVALID')

def inspect_share(wire, auth, app_id, partner_id):
    """Require a complete, partner-only inventory; use documented alternate readback
    ONLY if WSO2 omits the primary organizations collection. No inferred emptiness.
    """
    path = authority.APP_PREFIX + '/' + app_id + '/share'
    status, body, _ = wire.call('GET', path, auth=auth)
    must(status == 200, 'P2_SHARE_READBACK_HTTP_' + str(status))
    must(isinstance(body, dict), 'P2_SHARE_READBACK_SHAPE_INVALID')
    # A global sharing policy is outside this fixed-child bootstrap's authority.
    must('sharingMode' not in body, 'P2_SHARE_ALL_ORGS_CONFIGURATION_FORBIDDEN')
    links = body.get('links', [])
    must(isinstance(links, list) and len(links) <= 20 and
         all(isinstance(x, dict) and isinstance(x.get('rel'), str) for x in links),
         'P2_SHARE_LINKS_MALFORMED')
    must(not any(x['rel'] in ('next', 'after') for x in links),
         'P2_SHARE_INVENTORY_INCOMPLETE')
    organizations = body.get('organizations')
    if isinstance(organizations, list):
        must(len(organizations) <= 10000, 'P2_SHARE_LIST_TOO_LARGE')
        if 'totalResults' in body:
            must(type(body['totalResults']) is int and body['totalResults'] == len(organizations),
                 'P2_SHARE_INVENTORY_COUNT_MISMATCH')
        ids = []
        for item in organizations:
            must(isinstance(item, dict) and UUID.fullmatch(str(item.get('id', ''))),
                 'P2_SHARE_ORGANIZATION_ID_INVALID')
            ids.append(item['id'])
        must(len(set(ids)) == len(ids), 'P2_SHARE_DUPLICATE_ORGANIZATIONS')
        must(all(id_ == partner_id for id_ in ids),
             'P2_SHARE_FOREIGN_ORGANIZATION_BLOCKED')
        return 'VERIFIED' if partner_id in ids else 'MISSING'

    # Do not silently accept an empty collection just because the JSON is {}.
    # Require a second, independently documented WSO2 sharing inventory.
    must(organizations is None and 'organizations' not in body,
         'P2_SHARE_ORGANIZATIONS_SHAPE_INVALID')
    must(set(body).issubset({'links', 'totalResults', 'count', 'startIndex'}) and
         not links, 'P2_SHARE_PRIMARY_EMPTY_SHAPE_UNVERIFIED')
    for count_field in ('totalResults', 'count'):
        if count_field in body:
            must(type(body[count_field]) is int and body[count_field] == 0,
                 'P2_SHARE_PRIMARY_EMPTY_COUNT_CONFLICT')
    if 'startIndex' in body:
        must(type(body['startIndex']) is int and body['startIndex'] in (0, 1),
             'P2_SHARE_PRIMARY_EMPTY_START_INVALID')

    # GET /shared-apps is a separate documented endpoint whose collection is
    # `sharedApplications` (NOT `organizations`). The returned applicationId
    # describes the shared child app, not necessarily the root app identifier.
    second_status, second, _ = wire.call('GET', authority.APP_PREFIX + '/' + app_id + '/shared-apps', auth=auth)
    must(second_status == 200, 'P2_SHARE_SECONDARY_HTTP_' + str(second_status))
    must(isinstance(second, dict), 'P2_SHARE_SECONDARY_SHAPE_INVALID')
    must('sharingMode' not in second, 'P2_SHARE_SECONDARY_GLOBAL_POLICY_FORBIDDEN')
    entries = second.get('sharedApplications')
    # IS 7.3.0 GA in this installation returned HTTP 200 + {} on BOTH
    # independently checked endpoints. That is an unverified empty envelope,
    # NOT an attestation that no organization is shared.
    if second == {}:
        return 'EMPTY_UNVERIFIED'
    must(isinstance(entries, list), 'P2_SHARE_SECONDARY_COLLECTION_MISSING')
    must(len(entries) <= 10000, 'P2_SHARE_SECONDARY_LIST_TOO_LARGE')
    second_links = second.get('links', [])
    must(isinstance(second_links, list) and len(second_links) == 0,
         'P2_SHARE_SECONDARY_PAGINATION_UNVERIFIED')
    if 'totalResults' in second:
        must(type(second['totalResults']) is int and second['totalResults'] == len(entries),
             'P2_SHARE_SECONDARY_COUNT_MISMATCH')
    ids = []
    app_ids = []
    for item in entries:
        must(isinstance(item, dict) and
             UUID.fullmatch(str(item.get('organizationId', ''))) and
             isinstance(item.get('applicationId'), str) and
             authority.ID.fullmatch(item['applicationId']),
             'P2_SHARE_SECONDARY_ENTRY_INVALID')
        ids.append(item['organizationId'])
        app_ids.append(item['applicationId'])
    must(len(set(ids)) == len(ids) and len(set(app_ids)) == len(app_ids),
         'P2_SHARE_SECONDARY_DUPLICATES')
    must(all(org_id == partner_id for org_id in ids),
         'P2_SHARE_SECONDARY_FOREIGN_ORGANIZATION_BLOCKED')
    return 'VERIFIED' if partner_id in ids else 'MISSING'

def read_partner(wire, owner, app_protocol, org_id, root_id):
    """Independent authorized API readback of the exact expected child."""
    client_id=app_protocol.get('clientId')
    client_secret=app_protocol.get('clientSecret')
    must(isinstance(client_id,str) and len(client_id)>=8 and
         isinstance(client_secret,str) and len(client_secret)>=8,
         'P2_SHARE_CLIENT_CREDENTIALS_UNAVAILABLE')
    response=wire.call('POST','/t/'+DOMAIN+'/oauth2/token',
        auth=authority.basic(client_id,client_secret),
        form={'grant_type':'client_credentials','scope':' '.join(authority.ROOT_SCOPES)})
    must(response[0]==200, 'P2_SHARE_ROOT_TOKEN_HTTP_'+str(response[0]))
    token=response[1].get('access_token')
    scopes=str(response[1].get('scope','')).split()
    must(isinstance(token,str) and len(token)>=16 and
         set(authority.ROOT_SCOPES).issubset(set(scopes)), 'P2_SHARE_ROOT_TOKEN_INVALID')
    bearer='Bearer '+token
    root=wire.call('GET','/t/'+DOMAIN+'/o/api/server/v1/organizations/self',auth=bearer)
    must(root[0]==200 and root[1].get('id')==root_id and not (root[1].get('parent') or {}).get('id'),
         'P2_SHARE_ROOT_CONTEXT_DRIFT')
    child=wire.call('GET','/t/'+DOMAIN+'/o/api/server/v1/organizations/'+org_id,auth=bearer)
    must(child[0]==200, 'P2_SHARE_PARTNER_READBACK_HTTP_'+str(child[0]))
    record=child[1]
    must(record.get('id')==org_id and record.get('name')==PARTNER_NAME and
         record.get('orgHandle')==PARTNER_HANDLE and record.get('status')=='ACTIVE' and
         (record.get('parent') or {}).get('id')==root_id,
         'P2_SHARE_PARTNER_CONTEXT_INVALID')
    return token

def prove_switch(wire, protocol, root_token, org_id, root_id):
    """Read-only functional proof: a least-privilege organization-switched
    OAuth token must access the precise partner's /organizations/self context.
    An OAuth 400 is NOT proof of absent sharing and is never treated as success.
    """
    if not isinstance(root_token, str) or len(root_token) < 16:
        return False
    response = wire.call('POST', '/t/'+DOMAIN+'/oauth2/token',
        auth=authority.basic(protocol['clientId'], protocol['clientSecret']),
        form={'grant_type':'organization_switch', 'token':root_token,
              'scope':' '.join(PARTNER_SCOPES), 'switching_organization':org_id})
    if response[0] == 400:
        return False
    must(response[0] == 200, 'P2_SHARE_SWITCH_PROBE_HTTP_'+str(response[0]))
    data = response[1]
    must(isinstance(data, dict) and str(data.get('token_type','')).lower()=='bearer' and
         isinstance(data.get('access_token'), str) and
         len(data['access_token']) >= 16 and not any(c.isspace() for c in data['access_token']) and
         set(PARTNER_SCOPES).issubset(set(str(data.get('scope','')).split())),
         'P2_SHARE_SWITCH_TOKEN_UNVERIFIED')
    self_response = wire.call('GET', '/t/'+DOMAIN+'/o/api/server/v1/organizations/self',
        auth='Bearer '+data['access_token'])
    must(self_response[0] == 200, 'P2_SHARE_SWITCH_CONTEXT_HTTP_'+str(self_response[0]))
    org = self_response[1]
    must(isinstance(org, dict) and org.get('id') == org_id and
         org.get('status') == 'ACTIVE' and
         (org.get('parent') or {}).get('id') == root_id,
         'P2_SHARE_SWITCH_CONTEXT_NOT_PARTNER')
    return True

def reconcile(wire, private, owner, prior_app_id, org_id, write=False,
              sleep=time.sleep):
    """Allow exactly one existing application and one existing organization."""
    check_partner_id(org_id)
    must((private/'p2-bootstrap-authority.private.json').exists(),
         'P2_SHARE_AUTHORITY_HANDOFF_MISSING')
    auth_journal=authority.private_read(private/'p2-bootstrap-authority.private.json')
    must(auth_journal.get('schema')=='identity.wso2.p224.authority.v1' and
         auth_journal.get('state')=='verified' and
         auth_journal.get('domain')==DOMAIN and
         auth_journal.get('sourceAppId')==prior_app_id and
         UUID.fullmatch(str(auth_journal.get('rootOrganizationId',''))) and
         authority.ID.fullmatch(str(auth_journal.get('appId',''))) and
         authority.MARKER.fullmatch(str(auth_journal.get('marker',''))),
         'P2_SHARE_AUTHORITY_JOURNAL_DRIFT')
    app_id=auth_journal['appId']
    root_id=auth_journal['rootOrganizationId']
    protocol=authority.verify_app(wire,owner,app_id,auth_journal['marker'])
    # Must validate the existing child, not merely trust a CLI-supplied UUID.
    root_token=read_partner(wire,owner,protocol,org_id,root_id)
    journal_path=private/'p2-bootstrap-share.private.json'
    journal=authority.private_read(journal_path,optional=True)
    if journal:
        must(journal.get('schema')=='identity.wso2.p224.share.v1' and
             journal.get('tenant')==DOMAIN and journal.get('partnerId')==org_id and
             journal.get('appId')==app_id and
             journal.get('state') in ('prepared','post-started','verified'),
             'P2_SHARE_JOURNAL_MISMATCH')
    state=inspect_share(wire,owner,app_id,org_id)
    readback_mode='APPLICATION_SHARING_API'
    if state=='EMPTY_UNVERIFIED':
        # A second complete pair of HTTP 200 {} responses establishes that
        # the behavior is stable, but does not prove absence or success.
        must(inspect_share(wire,owner,app_id,org_id)=='EMPTY_UNVERIFIED',
             'P2_SHARE_EMPTY_SHAPE_CHANGED')
        if prove_switch(wire,protocol,root_token,org_id,root_id):
            state='VERIFIED'
            readback_mode='ORGANIZATION_SWITCH_CONTEXT'
    if state=='VERIFIED':
        if write and (journal is None or journal.get('state')!='verified'):
            authority.private_write(journal_path,{'schema':'identity.wso2.p224.share.v1',
                'tenant':DOMAIN,'partnerId':org_id,'appId':app_id,'state':'verified'})
        return {'stage':'P2_SHARE','mode':'APPLY' if write else 'CHECK',
                'state':'VERIFIED','remoteReadback':'VERIFIED',
                'readbackMode':readback_mode,'remoteWrites':0}
    must(journal is None or journal.get('state')=='prepared',
         'P2_SHARE_PRIOR_POST_OUTCOME_UNCERTAIN_NO_RETRY')
    if not write:
        return {'stage':'P2_SHARE','mode':'CHECK','state':state,
                'remoteWrites':0,'readbackMode': 'EMPTY_HTTP_200_NOT_PROOF' if state=='EMPTY_UNVERIFIED' else 'EXPLICIT_EMPTY_ARRAY'}
    if journal is None:
        journal={'schema':'identity.wso2.p224.share.v1',
                 'tenant':DOMAIN,'partnerId':org_id,'appId':app_id,'state':'prepared'}
        authority.private_write(journal_path,journal)
    journal['state']='post-started'
    authority.private_write(journal_path,journal)
    response=wire.call('POST',authority.APP_PREFIX+'/'+app_id+'/share',
        auth=owner,payload={'shareWithAllChildren':False,
                            'sharedOrganizations':[org_id]})
    must(response[0] in (200,202),
         'P2_SHARE_WRITE_OUTCOME_UNCERTAIN_HTTP_'+str(response[0]))
    for attempt in range(5):
        state=inspect_share(wire,owner,app_id,org_id)
        readback_mode='APPLICATION_SHARING_API'
        if state=='EMPTY_UNVERIFIED':
            must(inspect_share(wire,owner,app_id,org_id)=='EMPTY_UNVERIFIED',
                 'P2_SHARE_POST_EMPTY_SHAPE_CHANGED')
            if prove_switch(wire,protocol,root_token,org_id,root_id):
                state='VERIFIED'
                readback_mode='ORGANIZATION_SWITCH_CONTEXT'
        if state=='VERIFIED':
            journal['state']='verified'
            authority.private_write(journal_path,journal)
            return {'stage':'P2_SHARE','mode':'APPLY','state':'VERIFIED',
                    'remoteReadback':'VERIFIED','readbackMode':readback_mode,'remoteWrites':1}
        if attempt!=4: sleep(1)
    raise Stop('P2_SHARE_NOT_YET_READBACK_VERIFIED_NO_RETRY')

def main():
    must(len(sys.argv)==3 and sys.argv[1] in ('check','apply'),'usage: p2-bootstrap-share.py check|apply PARTNER_ID')
    mode, partner_id=sys.argv[1:]
    check_partner_id(partner_id)
    authority.verify_runtime_image()
    authority.verify_source(ROOT)
    home=Path(os.environ.get('CIAM_V10_HOME',str(Path.home()/'wso2-ciam-v10')))
    private,owner,prior=authority.environment(ROOT,home)
    wire=authority.Wire(authority.tls_context(ROOT))
    lock_path=private/'p2-bootstrap-share.lock'
    fd=None
    if mode=='apply':
        try: fd=os.open(lock_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        except FileExistsError: raise Stop('P2_SHARE_ALREADY_IN_PROGRESS')
    try:
        result=reconcile(wire,private,owner,prior,partner_id,write=mode=='apply')
    finally:
        if fd is not None:
            os.close(fd)
            os.unlink(lock_path)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try: main()
    except Exception as exc:
        if isinstance(exc, (Stop,authority.Stop)):
            code=str(exc)
        elif isinstance(exc, (OSError,ValueError,KeyError,TypeError)):
            code=type(exc).__name__
        else:
            code='P2_SHARE_UNEXPECTED_FAILURE'
        print(json.dumps({'stage':'P2_SHARE','status':'BLOCKED','error':code[:180],
                          'mutationState':'NOT_ASSUMED','secrets':'NEVER_PRINTED'}),file=sys.stderr)
        sys.exit(1)
