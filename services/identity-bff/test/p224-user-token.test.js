import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const here=dirname(fileURLToPath(import.meta.url));
const dir=resolve(here,'../../../scripts');
const m=await import('file://'+dir+'/p224-user-token-core.mjs');
const RID='c1885551-a211-4bcb-b3d0-123456789abc';
const AID='d2345678-a211-4bcb-b3d0-123456789abc';
const org={id:m.PARTNER,parent:{id:m.ROOT},status:'ACTIVE'};
const token={access_token:'genuine-token-value-for-fixture',token_type:'Bearer',expires_in:900,scope:m.SCOPE};
const introspection=(now)=>({active:true,aut:'APPLICATION_USER',org_id:m.PARTNER,
  client_id:'clientid12345',sub:m.USER,username:'p2-verde-operator@'+m.PARTNER,
  scope:m.SCOPE,iat:now-10,exp:now+850});
function makeJournal(initial=null){let value=initial;const writes=[];return {
 load:()=>value,save:v=>{value=structuredClone(v);writes.push(structuredClone(v));},writes};}
function testWire(){let app=null,auth=[];const calls=[];const wire=async(method,url,payload)=>{
  calls.push({method,url,payload});
  if(url.endsWith('/organizations/self'))return org;
  if(url.endsWith('/applications?limit=100&offset=0'))
    return {totalResults:app?1:0,applications:app?[{id:AID,name:m.CLIENT_NAME}]:[]};
  if(method==='POST'&&url.endsWith('/applications')){
    app={id:AID,...payload};return {id:AID};
  }
  if(method==='GET'&&url.endsWith('/applications/'+AID))return app;
  if(method==='GET'&&url.endsWith('/applications/'+AID+'/inbound-protocols/oidc'))
    return {grantTypes:['password'],publicClient:false,clientId:'clientid12345',clientSecret:'private-secret-123'};
  if(method==='GET'&&url.endsWith('/applications/'+AID+'/authorized-apis'))
    return {authorizedAPIs:auth};
  if(method==='POST'&&url.endsWith('/applications/'+AID+'/authorized-apis')){
    auth=[{id:RID,policyIdentifier:'RBAC',authorizedScopes:[{name:payload.scopes[0]}]}];return {};
  }
  throw Error('unexpected '+method+' '+url);
 };return {wire,calls,changeApp:fn=>app=fn(app),changeOrg:()=>{org.id='wrong'}};
}
test('delegated journal must own an actual user with private password',()=>{
 const valid={schema:'identity.wso2.p224.delegation.v1',partnerId:m.PARTNER,rootId:m.ROOT,
  tenant:m.TENANT,user:{id:m.USER,phase:'verified',password:'VeryLongPrivateTestPassword12345!!'},
  role:{id:m.ROLE,phase:'verified'},assignment:{phase:'verified'},membership:{phase:'verified'}};
 assert.equal(m.verifyDelegateJournal(valid).username,'p2-verde-operator');
 for(const change of [x=>x.user.id=m.ROOT,x=>x.assignment.phase='none',x=>x.user.password='short',
 x=>x.partnerId=m.ROOT]){
  const changed=structuredClone(valid);change(changed);
  assert.throws(()=>m.verifyDelegateJournal(changed),/P224_USER_PRIVATE_DELEGATE_NOT_VERIFIED/);
 }
});
test('introspection requires real end user, exact tenant, client and identity',()=>{
 const now=1760000000,base=introspection(now);
 assert.equal(m.verifyIntrospection(base,'clientid12345',now),true);
 const noScope={...base};delete noScope.scope;
 assert.equal(m.verifyIntrospection(noScope,'clientid12345',now),true);
 assert.equal(m.verifyIntrospection({...base,username:'PRIMARY/p2-verde-operator@'+m.PARTNER},'clientid12345',now),true);
 const variations=[{active:false},{aut:'APPLICATION'},{org_id:m.ROOT},{client_id:'wrong'},
   {username:'unrelated'}, {scope:'openid'}, {exp:now-1}, {iat:now+300}];
 for(const delta of variations){
  assert.throws(()=>m.verifyIntrospection({...base,...delta},'clientid12345',now));
 }
});
test('malformed OAuth tokens and ungranted scopes cannot authorize SCIM',()=>{
 assert.equal(m.verifyOAuthToken(token),token.access_token);
 for(const d of [{scope:'openid'},{token_type:'MAC'},{access_token:'foo'},{expires_in:100000}])
   assert.throws(()=>m.verifyOAuthToken({...token,...d}));
});
test('org local application is only password grant, with organization audience',()=>{
 const app={id:AID,name:m.CLIENT_NAME,description:'p224-userapp-'+('a'.repeat(32)),isManagementApp:false,
  associatedRoles:{allowedAudience:'ORGANIZATION',roles:[{id:m.ROLE}]}};
 assert.equal(m.verifyApp(app,AID,app.description),true);
 for(const delta of [{isManagementApp:true},{associatedRoles:{allowedAudience:'APPLICATION'}},
    {associatedRoles:{allowedAudience:'ORGANIZATION',roles:[{id:m.ROOT}]}}])
    assert.throws(()=>m.verifyApp({...app,...delta},AID,app.description));
 for(const grants of [['client_credentials'],['password','client_credentials'],['authorization_code']])
   assert.throws(()=>m.verifyAppProtocol({grantTypes:grants,publicClient:false,clientId:'someclientid',clientSecret:'someprivatevalue'}));
 assert.equal(m.verifyAppProtocol({grantTypes:['password'],publicClient:false,
   clientId:'someclientid',clientSecret:'someprivatevalue'}).clientId,'someclientid');
});
test('read-only plan never creates user application',async()=>{
 const x=testWire(),j=makeJournal();const out=await m.reconcileUserApp({client:x.wire,usersResourceId:RID,journal:j});
 assert.equal(out.state,'CREATE_REQUIRED');assert.equal(j.writes.length,0);
 assert.equal(x.calls.filter(z=>z.method==='POST').length,0);
});
test('one apply provisions app, one exact API authorization, rerun is no-op',async()=>{
 const x=testWire(),j=makeJournal();
 const first=await m.reconcileUserApp({client:x.wire,usersResourceId:RID,journal:j,write:true});
 assert.equal(first.state,'VERIFIED');
 assert.equal(j.load().phase,'verified');
 assert.equal(x.calls.filter(z=>z.method==='POST').length,2);
 assert.equal((await m.reconcileUserApp({client:x.wire,usersResourceId:RID,journal:j})).state,'VERIFIED');
 await m.reconcileUserApp({client:x.wire,usersResourceId:RID,journal:j,write:true});
 assert.equal(x.calls.filter(z=>z.method==='POST').length,2);
});
test('wrong/foreign org cannot authorize any application writes',async()=>{
 const x=testWire(),j=makeJournal();
 const guarded=async(method,url,body)=>url.endsWith('/organizations/self')
   ?{id:m.ROOT,parent:null,status:'ACTIVE'}:x.wire(method,url,body);
 await assert.rejects(m.reconcileUserApp({client:guarded,usersResourceId:RID,journal:j,write:true}),
   /P224_USER_APP_ORGANIZATION_CONTEXT_WRONG/);
 assert.equal(x.calls.filter(z=>z.method==='POST').length,0);
});
test('uncertain application POST must not be automatically repeated',async()=>{
 const x=testWire(),j=makeJournal();let attempts=0;
 const noisy=async(method,url,body)=>{
   if(method==='POST'&&url.endsWith('/applications')){attempts++;throw Error('simulated transport');}
   return x.wire(method,url,body);
 };
 await assert.rejects(m.reconcileUserApp({client:noisy,usersResourceId:RID,journal:j,write:true}));
 await assert.rejects(m.reconcileUserApp({client:noisy,usersResourceId:RID,journal:j,write:true}),
   /P224_USER_APP_CREATE_UNCERTAIN_NO_RETRY/);
 assert.equal(attempts,1);
});
test('verified role mapping and extra authorizations are required',async()=>{
 const x=testWire(),j=makeJournal();await m.reconcileUserApp({client:x.wire,usersResourceId:RID,journal:j,write:true});
 assert.throws(()=>m.verifyAuthorizedApi({id:RID,authorizedScopes:['internal_org_user_mgt_list','internal_org_user_mgt_create']},RID));
 assert.throws(()=>m.parseAppList({totalResults:1}));
 assert.throws(()=>m.parseAppList({totalResults:0,applications:[{id:AID}]}));
});
test('accepted token must pass positives and negative scopes with exact statuses',async()=>{
 const now=1760000000;
 const accepted=await m.acceptance({oauth:async(kind,form)=>kind==='token'?token:introspection(now),
 read:async url=>url.startsWith('https://localhost:9444/t/aurora.identity.test/o/scim2/Users?')?200:403,
 clientId:'clientid12345',username:'p2-verde-operator',password:'VeryLongPrivateTestPassword12345!!',now});
 assert.equal(accepted.state,'WSO2_USER_TOKEN_ACCEPTANCE_VERIFIED');
 assert.equal(accepted.otherPartnerDenial,'NOT_EXECUTED_NO_SECOND_VERIFIED_PARTNER');
});
test('a false positive in Brisa or root is a hard failure',async()=>{
 const now=1760000000,auth=async kind=>kind==='token'?token:introspection(now);
 await assert.rejects(m.acceptance({oauth:auth,read:async()=>200,clientId:'clientid12345',
   username:'p2-verde-operator',password:'VeryLongPrivateTestPassword12345!!',now}),
   /P224_ACCEPT_NEGATIVE_NOT_DENIED/);
});
test('a denied positive list cannot be treated as delegated authorization',async()=>{
 const now=1760000000;
 await assert.rejects(m.acceptance({oauth:async kind=>kind==='token'?token:introspection(now),
 read:async()=>403,clientId:'clientid12345',username:'p2-verde-operator',
 password:'VeryLongPrivateTestPassword12345!!',now}),/P224_ACCEPT_POSITIVE_DENIED/);
});
