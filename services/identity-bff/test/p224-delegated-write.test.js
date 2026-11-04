import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const path=resolve(dirname(fileURLToPath(import.meta.url)),'../../../scripts');
const m=await import('file://'+path+'/p224-delegated-write-core.mjs');
const t=await import('file://'+path+'/p224-user-token-core.mjs');
const runner=await import('file://'+path+'/p224-delegated-write.mjs');
const apiId='a1111111-a111-4111-8111-111111111111';
const userId='b2222222-b222-4222-8222-222222222222';
const appId='c3333333-c333-4333-8333-333333333333';
const grant=(scopes)=>({id:apiId,policyIdentifier:'RBAC',authorizedScopes:scopes.map(name=>({name}))});
const p={username:'p2-verde-member-1122334455667788',email:'p2-verde-member-1122334455667788@aurora.identity.test',password:'a'.repeat(42)+'Aa9!'};
const member={id:userId,userName:'PRIMARY/'+p.username,active:true,emails:[{value:p.email}],roles:[]};
const mem=initial=>{let value=initial,history=[];return {load:()=>value,save:x=>{value=structuredClone(x);history.push(structuredClone(x));},history};};
const page=rows=>({totalResults:rows.length,Resources:rows});
const now=1760000000;
const token={token_type:'Bearer',access_token:'legitimate-test-token-123',expires_in:900,scope:m.REQUIRED.join(' ')};
const intro={active:true,aut:'APPLICATION_USER',org_id:m.PARTNER,client_id:'client-verified',
 sub:m.USER,username:'p2-verde-operator@another-qualified-partner-format',iat:now-10,exp:now+600,
 scope:m.REQUIRED.join(' ')};

test('WSO2 authorized API must stay exact: baseline or only list/view/create',()=>{
 assert.equal(m.checkPermissions(grant([t.SCOPE]),apiId),'BASE');
 assert.equal(m.checkPermissions(grant(m.REQUIRED),apiId),'EXTENDED');
 assert.equal(t.verifyAuthorizedApi(grant(m.REQUIRED),apiId),true);
 for(const scopes of [[t.SCOPE,m.VIEW],[t.SCOPE,m.CREATE],
   [...m.REQUIRED,'internal_org_user_mgt_update'],[t.SCOPE,t.SCOPE,m.CREATE]]){
  assert.throws(()=>m.checkPermissions(grant(scopes),apiId));
  assert.throws(()=>t.verifyAuthorizedApi(grant(scopes),apiId));
 }
 assert.throws(()=>m.checkPermissions(grant(m.REQUIRED),m.ROOT));
});
test('immutable user subject, token organization, client and exact create scope are required',()=>{
 assert.equal(m.validateToken(token,intro,'client-verified',now),token.access_token);
 for(const bad of [{sub:'another-user'},{org_id:m.ROOT},{client_id:'wrong'},
   {aut:'APPLICATION'},{scope:t.SCOPE}]){
  assert.throws(()=>m.validateToken(token,{...intro,...bad},'client-verified',now));
 }
 assert.throws(()=>m.validateToken({...token,scope:t.SCOPE},intro,'client-verified',now));
});
test('newly-created member must be ordinary, active, owned and in Verde',()=>{
 assert.equal(m.safeUser(member,p),userId);
 for(const delta of [{active:false},{userName:'different'},{emails:[]},
   {roles:[{value:m.ROLE}]},{id:m.USER}]){
  assert.throws(()=>m.safeUser({...member,...delta},p));
 }
 assert.equal(m.exactUserName('PRIMARY/'+p.username,p.username),true);
 assert.equal(m.exactUserName(p.username+'@'+m.TENANT,p.username),true);
 assert.equal(m.exactUserName(p.username+'@other-tenant',p.username),false);
 assert.equal(m.userPayload(p).active,true);
});
test('organization context prohibits Aurora root and Brisa',()=>{
 assert.equal(m.verifyContext({id:m.PARTNER,parent:{id:m.ROOT},status:'ACTIVE'}),true);
 for(const obj of [{id:m.ROOT,parent:{id:m.ROOT},status:'ACTIVE'},
   {id:m.PARTNER,parent:{id:m.PARTNER},status:'ACTIVE'},
   {id:m.PARTNER,parent:{id:m.ROOT},status:'DISABLED'}]){
  assert.throws(()=>m.verifyContext(obj));
 }
});
test('read-only authorization plan never PATCHes or creates a private record',async()=>{
 const j=mem();let patches=0;
 const request=async(method,url,body)=>{
  if(method==='PATCH')patches++;
  return {authorizedAPIs:[grant([t.SCOPE])]};
 };
 assert.equal(await m.remoteAuthorization({request,appId,resourceId:apiId,journal:j,apply:false}),
  'AUTHORIZATION_REQUIRED');
 assert.equal(patches,0);assert.equal(j.history.length,0);
});
test('one authorized API PATCH, journaled before write, then exact readback',async()=>{
 const j=mem();let scopes=[t.SCOPE],patches=0;
 const request=async(method,url,body)=>{
  if(method==='PATCH'){patches++;assert.deepEqual(body,{addedScopes:[m.VIEW,m.CREATE],removedScopes:[]});scopes=m.REQUIRED;return {};}
  return {authorizedAPIs:[grant(scopes)]};
 };
 assert.equal(await m.remoteAuthorization({request,appId,resourceId:apiId,journal:j,apply:true}),'EXTENDED');
 assert.equal(patches,1);assert.equal(j.load().authPhase,'verified');
 assert.equal(await m.remoteAuthorization({request,appId,resourceId:apiId,journal:j,apply:true}),'EXTENDED');
 assert.equal(patches,1);
 assert.equal(j.history[1].authPhase,'started');
});
test('uncertain remote authorization never reissues PATCH blindly',async()=>{
 const j=mem();let patches=0;
 const request=async(method)=>{
  if(method==='PATCH'){patches++;throw Error('transport');}
  return {authorizedAPIs:[grant([t.SCOPE])]};
 };
 await assert.rejects(m.remoteAuthorization({request,appId,resourceId:apiId,journal:j,apply:true}));
 await assert.rejects(m.remoteAuthorization({request,appId,resourceId:apiId,journal:j,apply:true}),
   /P224W_AUTH_UPDATE_OUTCOME_UNCERTAIN_NO_RETRY/);
 assert.equal(patches,1);
});
test('successful but uncertain authorization can only adopt full WSO2 scope readback',async()=>{
 const j=mem({schema:'identity.wso2.p224.member.v1',partnerId:m.PARTNER,
   ...p,phase:'prepared',authPhase:'started'});
 const request=async()=>({authorizedAPIs:[grant(m.REQUIRED)]});
 assert.equal(await m.remoteAuthorization({request,appId,resourceId:apiId,journal:j,apply:true}),'EXTENDED');
 assert.equal(j.load().authPhase,'verified');
});
test('read-only member plan does not create or journal a person',async()=>{
 const j=mem();let posts=0;
 const client=async method=>{if(method==='POST')posts++;return page([]);};
 const o=await m.reconcileMember({read:client,write:client,journal:j,apply:false});
 assert.equal(o.state,'CREATE_REQUIRED');assert.equal(posts,0);assert.equal(j.history.length,0);
});
test('one delegated SCIM POST with journal and readback; rerun NOOP',async()=>{
 const j=mem({schema:'identity.wso2.p224.member.v1',partnerId:m.PARTNER,
   ...p,phase:'prepared',authPhase:'verified'});
 let rows=[],posts=0;
 const client=async(method,url,body)=>{
  if(method==='POST'){posts++;assert.equal(body.userName,p.username);rows=[member];return {id:userId};}
  if(url===m.apiBase+'/'+userId)return member;
  return page(rows);
 };
 const one=await m.reconcileMember({read:client,write:client,journal:j,apply:true});
 assert.equal(one.state,'WSO2_DELEGATED_USER_CREATE_VERIFIED');assert.equal(one.remoteWrites,1);
 assert.equal(j.history[0].phase,'post-started');assert.equal(j.load().phase,'verified');
 const second=await m.reconcileMember({read:client,write:client,journal:j,apply:true});
 assert.equal(second.remoteWrites,0);assert.equal(posts,1);
});
test('uncertain user creation stops, then adopts only exact verified remote user',async()=>{
 const j=mem({schema:'identity.wso2.p224.member.v1',partnerId:m.PARTNER,
   ...p,phase:'prepared',authPhase:'verified'});
 let rows=[],posts=0;
 const client=async(method,url)=>{
  if(method==='POST'){posts++;throw Error('simulated connection loss');}
  if(url===m.apiBase+'/'+userId)return member;
  return page(rows);
 };
 await assert.rejects(m.reconcileMember({read:client,write:client,journal:j,apply:true}));
 await assert.rejects(m.reconcileMember({read:client,write:client,journal:j,apply:true}),
  /P224W_CREATE_OUTCOME_UNCERTAIN_NO_RETRY/);
 assert.equal(posts,1);
 rows=[member];
 assert.equal((await m.reconcileMember({read:client,write:client,journal:j,apply:true})).remoteWrites,0);
 assert.equal(posts,1);
});
test('SCIM pagination and foreign/unverified records block before user mutation',async()=>{
 const j=mem({schema:'identity.wso2.p224.member.v1',partnerId:m.PARTNER,
   ...p,phase:'prepared',authPhase:'verified'});
 let posts=0;
 const client=async method=>{if(method==='POST')posts++;return {totalResults:2,Resources:[member]};};
 await assert.rejects(m.reconcileMember({read:client,write:client,journal:j,apply:true}),
   /P224W_SCIM_PAGE_METADATA_INVALID/);
 assert.equal(posts,0);
});

test('HTTP boundary: owner cannot POST users, user cannot PATCH app or use root/Brisa',async()=>{
  let calls=0;
  const request=async()=>{calls++;return {status:200,text:async()=>JSON.stringify({ok:true})};};
  const owner=runner.jsonClient('safe-test-bearer-value-00001','owner',request);
  const delegated=runner.jsonClient('safe-test-bearer-value-00001','user',request);
  await assert.rejects(owner('POST',m.apiBase,m.userPayload(p)),/P224W_METHOD_OR_URL_DENIED/);
  await assert.rejects(delegated('PATCH',m.appBase+'/'+appId+'/authorized-apis/'+apiId,
    {addedScopes:[m.VIEW]}),/P224W_METHOD_OR_URL_DENIED/);
  await assert.rejects(delegated('POST','https://localhost:9444/t/brisa.identity.test/o/scim2/Users',
    m.userPayload(p)),/P224W_METHOD_OR_URL_DENIED/);
  await assert.rejects(delegated('POST','https://localhost:9444/t/aurora.identity.test/scim2/Users',
    m.userPayload(p)),/P224W_METHOD_OR_URL_DENIED/);
  await assert.rejects(delegated('POST',m.apiBase+'?unexpected=1',
    m.userPayload(p)),/P224W_METHOD_OR_URL_DENIED/);
  assert.equal(calls,0);
  assert.deepEqual(await owner('GET',m.orgSelf),{ok:true});
  assert.equal(calls,1);
});
