import test from 'node:test';
import assert from 'node:assert/strict';
import {runRecovery} from './recover-aurora-owner.mjs';
const D='aurora.identity.test';

function createFixture({putStatus=200,ownerStatus=200,ownerName='labtenantadmin',badDomain=false,
    appStatus=200,accountExists=true,alreadyPending=false,confirm=true,networkPut=false}={}){
 const initial={schema:'identity.wso2.tenant-brand.v1',originHash:'fake-hash',domains:{aurora:D,brisa:'brisa.identity.test'},
  tenants:{aurora:{domain:badDomain?'unowned.identity.test':D,owned:true,state:'create-started',owner:{
   username:'labtenantadmin',password:'a'.repeat(40),email:'lab-tenant-admin@example.invalid',
   firstname:'Identity',lastname:'Lab'}}},clients:{existing:{id:'preserve-this'}}};
 if(alreadyPending)initial.tenants.aurora.ownerRecovery={state:'update-started',candidatePassword:'b'.repeat(28),tenantId:'tenant-1',ownerId:'owner-1'};
 let journal=structuredClone(initial), saves=0;
 const calls=[];
 const fetchImpl=async(_url,opts)=>{
  const url=new URL(_url);
  const method=opts.method||'GET';
  calls.push({method,path:url.pathname,auth:opts.headers.Authorization});
  if(method==='PUT'){
   if(networkPut)throw Error('SENSITIVE_NETWORK_ERROR');
   assert.equal(url.pathname,'/api/server/v1/tenants/tenant-1/owners/owner-1');
   const body=JSON.parse(opts.body);
   assert.equal(body.password.length,28);
   assert.equal(body.email,'lab-tenant-admin@example.invalid');
   return {status:putStatus};
  }
  if(url.pathname==='/api/server/v1/tenants')
   return {status:200,text:async()=>JSON.stringify({totalResults:1,tenants:accountExists?[{
    id:'tenant-1',domain:D,lifecycleStatus:{activated:true}}]:[]})};
  if(url.pathname==='/api/server/v1/tenants/tenant-1/owners')
   return {status:ownerStatus,text:async()=>JSON.stringify([{id:'owner-1',username:ownerName}])};
  if(url.pathname==='/api/server/v1/tenants/tenant-1/owners/owner-1')
   return {status:200,text:async()=>JSON.stringify({id:'owner-1',username:ownerName,
    email:'lab-tenant-admin@example.invalid',firstname:'Identity',lastname:'Lab'})};
  if(url.pathname===`/t/${D}/api/server/v1/applications`)
   return {status:appStatus,text:async()=>JSON.stringify({applications:[]})};
  throw Error('UNEXPECTED_ROUTE');
 };
 const env={WSO2_BASE_URL:'https://localhost:9443',WSO2_ADMIN_USER:'admin',WSO2_ADMIN_PASSWORD:'sensitive',
   NODE_EXTRA_CA_CERTS:'/private/trusted.pem', ...(confirm?{WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES',
    WSO2_OWNER_RECOVERY_CONFIRM:'RESET_JOURNALED_AURORA_OWNER'}:{})};
 const execute=(mode)=>runRecovery({mode,env,fetchImpl,generate:()=> 'c'.repeat(28),
  loadState:()=>({state:structuredClone(journal),revision:'fixture'}),
  saveState:(next)=>{journal=structuredClone(next);saves++}});
 return {execute,calls,get state(){return journal;},get saves(){return saves;}};
}

test('check: GET-only evidence, no journal changes',async()=>{
 const a=createFixture(),out=await a.execute('check');
 assert.equal(out.ownerConfirmed,true);
 assert.equal(out.remoteWrites,0);
 assert.equal(a.calls.some(x=>x.method!=='GET'),false);
 assert.equal(a.saves,0);
});
test('one 200 PUT + owner authentication updates only journaled password',async()=>{
 const a=createFixture(),out=await a.execute('apply');
 assert.equal(out.ownerCredentialsVerified,true);
 assert.equal(a.calls.filter(x=>x.method==='PUT').length,1);
 assert.equal(a.state.tenants.aurora.owner.password.length,28);
 assert.equal(a.state.tenants.aurora.ownerRecovery,undefined);
 assert.equal(a.state.tenants.aurora.state,'create-started');
 assert.deepEqual(a.state.clients,{existing:{id:'preserve-this'}});
 assert.equal(a.saves,2);
});
test('206 is not full success and leaves recoverable prewrite state',async()=>{
 const a=createFixture({putStatus:206});
 await assert.rejects(a.execute('apply'),/OWNER_UPDATE_NOT_FULLY_SUCCESSFUL_STOP/);
 assert.equal(a.saves,1);
 assert.equal(a.state.tenants.aurora.owner.password.length,40);
 assert.equal(a.state.tenants.aurora.ownerRecovery.state,'update-started');
 await assert.rejects(a.execute('apply'),/UPDATE_ALREADY_ATTEMPTED_USE_RESUME/);
 assert.equal(a.calls.filter(x=>x.method==='PUT').length,1);
 const r=await a.execute('resume');
 assert.equal(r.ownerCredentialsVerified,true);
 assert.equal(a.calls.filter(x=>x.method==='PUT').length,1);
});
test('network uncertainty is not retried and prewrite state is preserved',async()=>{
 const a=createFixture({networkPut:true});
 await assert.rejects(a.execute('apply'),/NETWORK_OUTCOME_UNKNOWN_STOP/);
 assert.equal(a.state.tenants.aurora.ownerRecovery.state,'update-started');
 await assert.rejects(a.execute('apply'),/UPDATE_ALREADY_ATTEMPTED_USE_RESUME/);
 assert.equal(a.calls.filter(x=>x.method==='PUT').length,1);
});
test('owner 401 after PUT never marks credential verified',async()=>{
 const a=createFixture({appStatus:401});
 await assert.rejects(a.execute('apply'),/OWNER_LOGIN_NOT_VERIFIED_STOP/);
 assert.equal(a.state.tenants.aurora.owner.password.length,40);
 assert.equal(a.state.tenants.aurora.ownerRecovery.state,'update-started');
});
test('no explicit recovery consent causes zero writes',async()=>{
 const a=createFixture({confirm:false});
 await assert.rejects(a.execute('apply'),/EXPLICIT_RECOVERY_CONFIRMATION_REQUIRED/);
 assert.equal(a.calls.some(x=>x.method==='PUT'),false);
 assert.equal(a.saves,0);
});
test('owner username mismatch prevents mutation',async()=>{
 const a=createFixture({ownerName:'unrelated'});
 await assert.rejects(a.execute('apply'),/OWNER_IDENTITY_MISMATCH_STOP/);
 assert.equal(a.saves,0);
});
test('tenant domain mismatch prevents any remote call',async()=>{
 const a=createFixture({badDomain:true});
 await assert.rejects(a.execute('apply'),/UNEXPECTED_JOURNAL_NO_CHANGE/);
 assert.equal(a.calls.length,0);
});
test('tenant missing prevents owner update',async()=>{
 const a=createFixture({accountExists:false});
 await assert.rejects(a.execute('apply'),/TENANT_IDENTITY_UNVERIFIED_STOP/);
 assert.equal(a.calls.filter(x=>x.method==='PUT').length,0);
});
test('owner inventory HTTP error stops without changing journal',async()=>{
 const a=createFixture({ownerStatus:403});
 await assert.rejects(a.execute('apply'),/OWNERS_UNAVAILABLE_STOP/);
 assert.equal(a.saves,0);
});
test('resume cannot send a second PUT',async()=>{
 const a=createFixture({alreadyPending:true});
 await assert.rejects(a.execute('apply'),/UPDATE_ALREADY_ATTEMPTED_USE_RESUME/);
 const out=await a.execute('resume');
 assert.equal(out.ownerCredentialsVerified,true);
 assert.equal(a.calls.filter(x=>x.method==='PUT').length,0);
});
