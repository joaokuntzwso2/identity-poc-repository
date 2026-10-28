#!/usr/bin/env python3
"""WSO2 org/app sharing with journaled writes. Requires scoped OAuth admin token.
This creates an organization and shares the Aurora app. Delegated user sharing is
separate and must have appropriate permission/scopes. 202 is not success proof.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlencode
SPEC=importlib.util.spec_from_file_location('resources',Path(__file__).parents[1]/'resources/bootstrap.py')
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)
Refuse=r.Refuse
ROOT=Path(__file__).resolve().parent
SPEC_FILE=ROOT/'desired.json'
JOURNAL=r.ROOT/'private/bootstrap-b2b-v4.private.json'
CONFIRM='CREATE_AURORA_PARTNER_ORGANIZATIONS_V4'
DELEGATE='SHARE_LUIZA_AS_AURORA_PARTNER_ADMIN_V4'

def config():
    d=json.loads(SPEC_FILE.read_text());t=r.private_read(r.TENANT_FILE)
    o=r.private_read(r.ROOT/'private/bootstrap-oidc-v10.private.json')
    identities=r.private_read(r.ROOT/'private/bootstrap-identities-v10.private.json')
    if d.get('schema')!='ciampoc.real-iam.phase4.v1' or d['b2b']['brand']!='aurora':raise Refuse('UNEXPECTED_SPEC')
    if o['tenants']['aurora']['clients']['web']['state']!='verified':raise Refuse('APP_NOT_PROVISIONED')
    return d,t,o,identities

def auth():
    token=os.getenv('WSO2_CIAM_V4_ORG_ADMIN_BEARER','')
    if not token or len(token)<32 or '\n' in token:raise Refuse('SCOPED_ORG_ADMIN_BEARER_REQUIRED')
    return 'Bearer '+token

def path(suffix, org=False):
    return '/t/'+r.DOMAINS['aurora']+('/o/api/server/v1/' if org else '/api/server/v1/')+suffix

def req(client,method,url,credential,payload=None):
    status,data,_=client.call(method,url,auth=credential,data=payload)
    return status,data

def get(client,url,credential):
    status,data=req(client,'GET',url,credential)
    if status!=200:raise Refuse('REMOTE_GET_FAILED_'+str(status))
    return data

def org_list(client,credential,name):
    data=get(client,path('organizations?'+urlencode({'filter':f'name eq {name}','limit':30}),True),credential)
    if not isinstance(data,dict) or not isinstance(data.get('organizations'),list):
        raise Refuse('ORG_LIST_RESPONSE_UNEXPECTED')
    if data.get('links') and any(x.get('rel')=='next' for x in data['links']):raise Refuse('ORG_PAGINATION_UNSAFE')
    rows=[x for x in data['organizations'] if x.get('name')==name]
    if len(rows)>1:raise Refuse('DUPLICATE_ORGANIZATION')
    return rows[0] if rows else None

def shared_ids(client,credential,appid):
    value=get(client,path('applications/'+appid+'/share'),credential)
    if not isinstance(value,dict) or not isinstance(value.get('organizations'),list):
        raise Refuse('APP_SHARING_SCHEMA_UNEXPECTED')
    # WSO2 may return id strings or organization objects; don't assume other shapes.
    ids=[]
    for item in value['organizations']:
        if isinstance(item,str):ids.append(item)
        elif isinstance(item,dict) and isinstance(item.get('id'),str):ids.append(item['id'])
        else:raise Refuse('SHARED_ORG_UNEXPECTED_SCHEMA')
    return ids

def execute(mode):
    d,t,o,users=config()
    client=r.HTTPS();credential=auth()
    appid=o['tenants']['aurora']['clients']['web']['id']
    state=r.private_read(JOURNAL,False) or {'schema':'ciampoc.v4.b2b-journal.v1','orgs':{},'appShared':False,'userShared':False}
    if state.get('schema')!='ciampoc.v4.b2b-journal.v1':raise Refuse('JOURNAL_SCHEMA_DRIFT')
    def save():r.atomic_save(JOURNAL,state)
    for entry in d['b2b']['organizations']:
        key=entry['orgHandle'];found=org_list(client,credential,entry['name'])
        existing=state['orgs'].get(key)
        if found and not existing:raise Refuse('UNJOURNALED_ORG_COLLISION_'+key)
        if existing and (not found or found.get('id')!=existing.get('id')):
            raise Refuse('ORG_MISSING_OR_DRIFT')
    if mode=='plan':return {'stage':'CIAM_B2B_V4','mode':'PLAN','remoteWrites':0,'organizations':len(d['b2b']['organizations'])}
    if mode=='apply':
        if os.getenv('WSO2_CIAM_V4_B2B_CONFIRM')!=CONFIRM:raise Refuse('ORG_WRITE_CONFIRMATION_REQUIRED')
        save()
        for entry in d['b2b']['organizations']:
            key=entry['orgHandle']
            if key not in state['orgs']:
                state['orgs'][key]={'state':'post-started'};save()
                code,_=req(client,'POST',path('organizations',True),credential,entry)
                if code!=201:raise Refuse('ORG_POST_UNCERTAIN_NO_RETRY_'+str(code))
                found=org_list(client,credential,entry['name'])
                if not found or not found.get('id'):raise Refuse('ORG_POST_NO_READBACK')
                state['orgs'][key]={'id':found['id'],'state':'verified'};save()
        ids=[x['id'] for x in state['orgs'].values()]
        if not state['appShared']:
            state['appShared']='post-started';save()
            code,_=req(client,'POST',path('applications/'+appid+'/share'),credential,
                {'shareWithAllChildren':False,'sharedOrganizations':ids})
            if code not in (200,201):raise Refuse('APP_SHARE_UNCERTAIN_NO_RETRY_'+str(code))
        if not set(ids).issubset(set(shared_ids(client,credential,appid))):raise Refuse('APP_SHARE_NO_READBACK')
        state['appShared']=True;save()
        return {'stage':'CIAM_B2B_V4','mode':'APPLY','organization':'VERIFIED','appSharing':'VERIFIED','delegatedAdmin':'NOT_YET_VERIFIED'}
    if mode=='delegate':
        if os.getenv('WSO2_CIAM_V4_B2B_DELEGATE_CONFIRM')!=DELEGATE:raise Refuse('DELEGATION_CONFIRMATION_REQUIRED')
        if not state['appShared']:raise Refuse('APP_SHARING_NOT_VERIFIED')
        if state['userShared']:raise Refuse('DELEGATION_ALREADY_REQUESTED_USE_VERIFY')
        user=users['tenants']['aurora']['users']['admin-luiza']['id']
        ids=[x['id'] for x in state['orgs'].values()]
        if len(ids)!=1:raise Refuse('ONE_ORG_ONLY_FOR_DELEGATION')
        state['userShared']='post-started';save()
        code,_=req(client,'POST','/t/'+r.DOMAINS['aurora']+'/api/server/v2/users/share',credential,{
           'userCriteria':{'userIds':[user]},
           'organizations':[{'orgId':ids[0], 'policy':'SELECTED_ORG_ONLY',
              'roleAssignment':{'mode':'SELECTED','roles':[
                 {'displayName':'Administrator','audience':{'type':'organization','display':d['b2b']['organizations'][0]['name']}}
              ]}}]})
        if code!=202:raise Refuse('USER_SHARE_UNCERTAIN_'+str(code))
        return {'stage':'CIAM_B2B_V4','mode':'DELEGATE','result':'ASYNC_ACCEPTED_NOT_VERIFIED','next':'verify'}
    if mode=='verify':
        for entry in d['b2b']['organizations']:
            key=entry['orgHandle'];found=org_list(client,credential,entry['name']);n=state['orgs'].get(key)
            if not found or not n or found.get('id')!=n['id']:raise Refuse('ORG_NOT_VERIFIED')
        ids=[x['id'] for x in state['orgs'].values()]
        if not set(ids).issubset(set(shared_ids(client,credential,appid))):raise Refuse('APP_NOT_SHARED')
        shared='NOT_REQUESTED'
        if state['userShared']:
            uid=users['tenants']['aurora']['users']['admin-luiza']['id']
            info=get(client,'/t/'+r.DOMAINS['aurora']+'/api/server/v2/users/'+uid+'/share',credential)
            if not isinstance(info,dict) or not isinstance(info.get('organizations'),list):raise Refuse('SHARED_USERS_SCHEMA_UNEXPECTED')
            records=[x for x in info['organizations'] if x.get('orgId') in ids]
            if len(records)!=len(ids) or not all(any(y.get('displayName')=='Administrator' for y in x.get('roles',[])) for x in records):
                raise Refuse('DELEGATED_ADMIN_READBACK_MISSING')
            state['userShared']=True;save();shared='READBACK_VERIFIED_LOGIN_NOT_TESTED'
        return {'stage':'CIAM_B2B_V4','mode':'VERIFY','orgs':'VERIFIED','appSharing':'VERIFIED','delegatedAdmin':shared}
    raise Refuse('USAGE_PLAN_APPLY_DELEGATE_VERIFY')

if __name__=='__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('plan','apply','delegate','verify'):
            raise Refuse('USAGE: b2b-bootstrap.py plan|apply|delegate|verify')
        print(json.dumps(execute(sys.argv[1]),indent=2))
    except (Refuse,KeyError,ValueError,OSError,TypeError) as e:
        print('REFUSED: '+str(e),file=sys.stderr);sys.exit(2)
