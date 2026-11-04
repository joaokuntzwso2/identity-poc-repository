import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcile, ROOT_SCOPES, PARTNER_SCOPES, checkScopes } from '../../../scripts/p2-bootstrap-core.mjs';
import { createOAuthProvider,verifyRuntimeImage } from '../../../scripts/p2-bootstrap-auto.mjs';
const R='11111111-1111-4111-8111-111111111111', P='22222222-2222-4222-8222-222222222222', G='33333333-3333-4333-8333-333333333333';
function fixture({exists=false, wrongParent=false, badPartner=false, scopes=true}={}) {
  let created=exists, group=false; const calls=[];
  const rootPath='https://localhost:9444/t/aurora.identity.test/o/api/server/v1/organizations';
  const orgPath=rootPath+'/self';
  const partnerPath='https://localhost:9444/t/aurora.identity.test/o';
  const scim=partnerPath+'/scim2/Groups';
  const rpc=async(method,url,body)=>{
    calls.push({boundary:'root',method,url,body});
    if(method==='GET' && url===orgPath)return {id:R,type:'TENANT'};
    if(method==='GET' && url.startsWith(rootPath+'?'))return {organizations:created?[{id:P,name:'Verde Logistics',orgHandle:'verde-logistics'}]:[]};
    if(method==='GET' && url===rootPath+'/'+P)return {id:P,parent:{id:wrongParent?'44444444-4444-4444-8444-444444444444':R},name:'Verde Logistics',orgHandle:'verde-logistics',status:'ACTIVE'};
    if(method==='POST' && url===rootPath){created=true;return{id:P};}
    throw Error('unexpected_root_call:'+method+':'+url);
  };
  const ppc=async(method,url,body)=>{
    calls.push({boundary:'partner',method,url,body});
    if(method==='GET' && url===partnerPath+'/api/server/v1/organizations/self')
      return{id:badPartner?R:P,parent:{id:R},status:'ACTIVE'};
    if(method==='GET' && url===scim+'?startIndex=1&count=100')return {Resources:group?[{id:G,displayName:'PRIMARY/p2-partner-operations'}]:[],totalResults:group?1:0};
    if(method==='GET' && url===partnerPath+'/scim2/Users?startIndex=1&count=100')return {Resources:[],totalResults:0};
    if(method==='GET' && url===scim+'/'+G)return {id:G,displayName:'PRIMARY/p2-partner-operations',members:[],roles:[]};
    if(method==='POST' && url===scim){group=true;return{id:G};}
    throw Error('unexpected_partner_call:'+method+':'+url);
  };
  let rootRequests=0,partnerRequests=0;
  const tokenProvider={
    root:async(_,s)=>{rootRequests++;assert.deepEqual(s,ROOT_SCOPES);return{scope:scopes?s.join(' '):'internal_org_organization_view',access_token:'a'.repeat(40)};},
    partner:async(_,id,s,t)=>{partnerRequests++;assert.equal(id,P);assert.equal(t,'a'.repeat(40));assert.deepEqual(s,PARTNER_SCOPES);return{scope:s.join(' '),access_token:'b'.repeat(40)};}
  };
  const shareApplication=async(id,mode)=>{calls.push({boundary:'sharing',id,mode});return {state:'VERIFIED',remoteReadback:'VERIFIED'};};
  const options={tokenProvider,rootClientFactory:()=>rpc,partnerClientFactory:()=>ppc,shareApplication};
  return {options,calls,counts:()=>({rootRequests,partnerRequests}),state:()=>({created,group})};
}
test('dry run reads root only, does not switch or write',async()=>{
  const f=fixture();const r=await reconcile({...f.options,write:false});
  assert.equal(r.mode,'CHECK');assert.equal(r.liveEvidence,'PENDING');
  assert.deepEqual(r.decisions,['CREATE_REQUIRES_APPROVAL']);
  assert.ok(f.calls.every(c=>c.method==='GET' && c.boundary==='root'));
  assert.equal(f.counts().partnerRequests,0);
});
test('one authorized bootstrap invocation creates partner then group with readback',async()=>{
  const f=fixture(); const r=await reconcile({...f.options,write:true});
  assert.equal(r.liveEvidence,'WSO2_READBACK_VERIFIED');assert.equal(r.partnerId,P);assert.equal(r.groupId,G);
  assert.equal(f.state().created,true);assert.equal(f.state().group,true);
  assert.deepEqual(r.decisions,['CREATED','CREATED']);
  assert.equal(r.applicationSharing,'VERIFIED');
  const shareCall=f.calls.find(c=>c.boundary==='sharing');
  assert.equal(shareCall.id,P);assert.equal(shareCall.mode,'apply');
});
test('rerun is idempotent when both resources exist',async()=>{
  const f=fixture({exists:true});await reconcile({...f.options,write:true});
  f.calls.length=0;const r=await reconcile({...f.options,write:true});
  assert.deepEqual(r.decisions,['NOOP','NOOP']);
  assert.equal(f.calls.some(c=>c.boundary==='root' && c.method!=='GET'),false);
  assert.equal(r.applicationSharing,'VERIFIED');
});
test('root token lacking create permission fails before a single API call',async()=>{
  const f=fixture({scopes:false});
  await assert.rejects(reconcile({...f.options,write:true}),/missing_scopes/);
  assert.equal(f.calls.length,0);
});
test('foreign root parent is rejected before partner token',async()=>{
  const f=fixture({exists:true,wrongParent:true});
  await assert.rejects(reconcile({...f.options,write:true}),/partner_parent_or_identity_mismatch/);
  assert.equal(f.counts().partnerRequests,0);
});
test('switched token for root rather than partner fails without SCIM write',async()=>{
  const f=fixture({exists:true,badPartner:true});
  await assert.rejects(reconcile({...f.options,write:true}),/token_organization_context_or_status_mismatch/);
  assert.equal(f.calls.filter(x=>x.boundary==='partner'&&x.method!=='GET').length,0);
});
test('cannot redirect automated bootstrap to Brisa or arbitrary groups',async()=>{
  const f=fixture();
  for(const plan of [{tenant:'brisa.identity.test',name:'Verde Logistics',handle:'verde-logistics',group:'p2-partner-operations'},
    {tenant:'aurora.identity.test',name:'Verde Logistics',handle:'verde-logistics',group:'Administrator'}]) {
    await assert.rejects(reconcile({...f.options,plan,write:true}),/BOOTSTRAP_TARGET_BLOCKED/);
  }
  assert.equal(f.calls.length,0);
});
test('granted scope validation is strict, not implied by asking for scopes',()=>{
  assert.throws(()=>checkScopes('internal_org_organization_view',ROOT_SCOPES),/missing_scopes/);
});
test('OAuth client-credentials and org-switch requests use correct WSO2 endpoint and scopes',async()=>{
  const calls=[];const request=async(url,init)=>{
    calls.push({url,method:init.method,auth:init.headers.authorization,params:new URLSearchParams(init.body)});
    return {ok:true,status:200,text:async()=>JSON.stringify({token_type:'Bearer',access_token:'x'.repeat(40),
      expires_in:3600,scope:calls.length===1?ROOT_SCOPES.join(' '):PARTNER_SCOPES.join(' ')})};
  };
  const p=createOAuthProvider({credentials:{clientId:'client-id',clientSecret:'client-secret'},request});
  await p.root('aurora.identity.test',ROOT_SCOPES);
  await p.partner('aurora.identity.test',P,PARTNER_SCOPES,'x'.repeat(40));
  assert.equal(calls[0].params.get('grant_type'),'client_credentials');
  assert.equal(calls[1].params.get('grant_type'),'organization_switch');
  assert.equal(calls[1].params.get('switching_organization'),P);
  assert.ok(calls.every(c=>c.url==='https://localhost:9444/t/aurora.identity.test/oauth2/token'));
});
test('OAuth insufficient grants never returns token or assumes privilege',async()=>{
  const p=createOAuthProvider({credentials:{clientId:'client-id',clientSecret:'client-secret'},
    request:async()=>({ok:true,status:200,text:async()=>JSON.stringify({token_type:'Bearer',
      access_token:'a'.repeat(40),expires_in:3600,scope:'internal_org_organization_view'})})});
  await assert.rejects(p.root('aurora.identity.test',ROOT_SCOPES),/missing_grants/);
  await assert.rejects(p.root('brisa.identity.test',ROOT_SCOPES),/BOOTSTRAP_TENANT_BLOCKED/);
});

test('bootstrap cannot run on a silently upgraded or uninspectable WSO2 image',()=>{
  assert.deepEqual(verifyRuntimeImage(()=> 'wso2/wso2is:7.3.0'),{
    runtimeImageTag:'wso2/wso2is:7.3.0',updateLevel:'NOT_ATTESTED_BY_IMAGE_TAG'});
  assert.throws(()=>verifyRuntimeImage(()=> 'wso2/wso2is:7.3.0.18'),/unapproved_wso2_image/);
  assert.throws(()=>verifyRuntimeImage(()=> {throw Error('no docker');}),/cannot_inspect/);
});

test('read-only existing partner checks application sharing but does not write',async()=>{
  const f=fixture({exists:true});
  const result=await reconcile({...f.options,write:false});
  assert.equal(result.applicationSharing,'VERIFIED');
  assert.ok(f.calls.some(c=>c.boundary==='sharing' && c.mode==='check'));
  assert.ok(f.calls.filter(c=>c.boundary==='root').every(c=>c.method==='GET'));
});
test('partner group access blocked if application sharing is absent or unverified',async()=>{
  const f=fixture({exists:true});
  let partnerGrant=false;
  const real=f.options.tokenProvider.partner;
  f.options.tokenProvider.partner=async(...args)=>{partnerGrant=true;return real(...args);};
  await assert.rejects(reconcile({...f.options,shareApplication:async()=>({state:'MISSING'}),write:true}),
    /sharing_not_verified/);
  assert.equal(partnerGrant,false);
  assert.ok(f.calls.every(x=>x.boundary!=='partner'));
});
test('missing application sharing stage blocks before partner token and group writes',async()=>{
  const f=fixture({exists:true});
  await assert.rejects(reconcile({...f.options,shareApplication:null,write:true}),
    /sharing_stage_required/);
  assert.ok(f.calls.every(x=>x.boundary!=='partner'));
});
test('OAuth errors show grant stage and safe error code, never a token',async()=>{
  const provider=createOAuthProvider({credentials:{clientId:'client-id',clientSecret:'client-secret'},
    request:async()=>({ok:false,status:400,text:async()=>JSON.stringify({error:'invalid_grant',
      error_description:'contains_secret_NEVER_PRINT'})})});
  await assert.rejects(provider.root('aurora.identity.test',ROOT_SCOPES),
    e=>e.message.includes('root_token_http_400_invalid_grant') && !e.message.includes('NEVER_PRINT'));
  await assert.rejects(provider.partner('aurora.identity.test',P,PARTNER_SCOPES,'secret-token'),
    e=>e.message.includes('organization_switch_token_http_400_invalid_grant') && !e.message.includes('NEVER_PRINT'));
});
