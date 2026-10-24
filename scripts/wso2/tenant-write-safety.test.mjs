// Safe offline tests; extracts the actual bootstrap function. No network, Docker or journal reads.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';

const src=readFileSync(join(dirname(fileURLToPath(import.meta.url)),'tenant-brand-bootstrap.mjs'),'utf8');
const match=src.match(/^export async function bootstrapTenants\([\s\S]*?^\}/m);
assert.ok(match,'expected exported bootstrapTenants function');
const code=match[0].replace('export async function','async function');
const domain=b=>`${b}.identity.test`;
const own=()=>({username:'labtenantadmin',password:'synthetic-not-secret',email:'lab-tenant-admin@example.invalid',firstname:'Identity',lastname:'Lab'});
const existing=(brand,state='create-started')=>({domain:domain(brand),owned:true,state,owner:own()});

function lab({initial={},remote=[],postStatus=201,postError,failDetails=false,missingAfterPost=false,ownerMismatch=false,ownerIdMismatch=false,deactivated=false}={}){
 const journal={tenants:structuredClone(initial),clients:{},acceptance:'NOT_VERIFIED'};
 const remoteMap=new Map(remote.map(b=>[domain(b),{id:`tenant-${b}`,ownerId:`owner-${b}`,owner:own()}]));
 const calls=[];const persisted=[];
 const ctx={
  process:{env:{}},fetch:()=>{throw Error('LIVE_NETWORK_FORBIDDEN')},
  console:{log:()=>{}},statePath:'synthetic-private-journal',
  BRANDS:['aurora','brisa'],ROOT_TENANT_LIST:'/api/server/v1/tenants',
  ID:/^[a-zA-Z0-9-]{5,128}$/,
  requireLab:()=>({base:'https://localhost:9443',domains:{aurora:domain('aurora'),brisa:domain('brisa')}}),
  config:()=>({}),deploymentPlan:()=>({apps:[]}),
  readState:()=>journal,
  privateWrite:(_p,s)=>persisted.push(structuredClone(s)),
  remoteTenants:async()=>new Set([...remoteMap.keys()]),
  safeOwner:own,
  jsonCall:async(_fetch,_base,path,opts)=>{
   const method=opts.method||'GET';
   calls.push({method,path,auth:opts.auth?.username});
   assert.equal(opts.auth?.username,'superadmin','only super tenant auth is acceptable during root inventory');
   if(method==='POST'){
    if(postError)throw Error(postError);
    if(!missingAfterPost)remoteMap.set(opts.payload.domain,{
     id:`tenant-${opts.payload.domain.split('.')[0]}`,ownerId:`owner-${opts.payload.domain.split('.')[0]}`,owner:structuredClone(opts.payload.owners[0])
    });
    return {status:postStatus,data:{}};
   }
   const base='/api/server/v1/tenants/';
   assert.ok(path.startsWith(base),'unexpected request endpoint');
   const tail=path.slice(base.length).split('/');
   if(tail[0]==='domain'){
    const domainName=decodeURIComponent(tail[1]);const r=remoteMap.get(domainName);
    return {status:r?200:404,data:r?{domain:domainName,id:r.id,lifecycleStatus:{activated:!deactivated}}:{}};
   }
   const r=[...remoteMap.values()].find(x=>x.id===tail[0]);
   if(tail.length===2&&tail[1]==='owners')return {status:200,data:r?[{id:r.ownerId,username:ownerMismatch?'some-other-owner':r.owner.username}]:[]};
   if(tail.length===3&&tail[1]==='owners')return {status:200,data:r?{
    ...r.owner,id:ownerIdMismatch?'wrong-owner':r.ownerId,
    ...(failDetails?{email:'wrong@example.invalid'}:{})}:null};
   throw Error('UNEXPECTED_API_ROUTE');
  }
 };
 const run=runInNewContext(`${code}\nbootstrapTenants`,ctx,{timeout:2000});
 return {journal,persisted,calls,remoteMap,
  run:(onlyTenants=true)=>run({env:{WSO2_ADMIN_USER:'superadmin',WSO2_ADMIN_PASSWORD:'not-a-real-secret'},stateFile:'synthetic-private-journal',onlyTenants,emit:()=>{}})};
}

test('reconcile already created Aurora without Basic GET or second POST, create Brisa exactly once',async()=>{
 const aurora=existing('aurora');
 aurora.ownerRecovery={state:'update-started',candidatePassword:'a'.repeat(28),tenantId:'tenant-aurora',ownerId:'owner-aurora'};
 const x=lab({initial:{aurora},remote:['aurora']});
 await x.run();
 assert.deepEqual(x.calls.filter(c=>c.method==='POST').map(c=>c.path),['/api/server/v1/tenants']);
 assert.equal(x.journal.tenants.aurora.state,'created');
 assert.equal(x.journal.tenants.aurora.ownerRecovery.candidatePassword,'a'.repeat(28));
 assert.equal(x.journal.tenants.aurora.owner.password,'synthetic-not-secret');
 assert.equal(x.journal.tenants.aurora.ownerAuthentication,'NOT_VERIFIED');
 assert.equal(x.journal.tenants.brisa.state,'created');
 assert.equal(x.journal.tenants.brisa.createOutcome,'ACKNOWLEDGED_201');
 assert.ok(x.calls.every(c=>!c.path.startsWith('/t/')));
});

test('clean first run creates both and rerun has zero additional writes',async()=>{
 const x=lab();await x.run();await x.run();
 assert.equal(x.calls.filter(c=>c.method==='POST').length,2);
 assert.equal(x.journal.tenants.aurora.state,'created');
 assert.equal(x.journal.tenants.brisa.state,'created');
});

test('unowned preexisting Aurora is refused without any POST',async()=>{
 const x=lab({remote:['aurora']});
 await assert.rejects(x.run(),/TENANT_ALREADY_EXISTS_UNOWNED_aurora/);
 assert.equal(x.calls.length,0);
});

test('prepared Aurora with newly appearing domain is refused',async()=>{
 const x=lab({initial:{aurora:existing('aurora','prepared')},remote:['aurora']});
 await assert.rejects(x.run(),/TENANT_PREPARED_BUT_DOMAIN_EXISTS_aurora/);
 assert.equal(x.calls.length,0);
});

test('unknown POST outcome fails closed and never retries',async()=>{
 const x=lab({postError:'TIMEOUT'});
 await assert.rejects(x.run(),/TIMEOUT/);
 await assert.rejects(x.run(),/TENANT_CREATE_OUTCOME_UNCERTAIN_aurora/);
 assert.equal(x.calls.filter(c=>c.method==='POST').length,1);
});

test('206 returns error without marking created or creating Brisa',async()=>{
 const x=lab({postStatus:206});
 await assert.rejects(x.run(),/TENANT_CREATE_HTTP_206_aurora/);
 assert.equal(x.journal.tenants.aurora.state,'create-started');
 assert.equal(x.journal.tenants.aurora.createOutcome,'PARTIAL_206');
 assert.equal(x.journal.tenants.brisa,undefined);
});

test('previous 409 collision will not be adopted later even if a tenant appears',async()=>{
 const x=lab({initial:{aurora:{...existing('aurora'),createOutcome:'CONFLICT_409'}},remote:['aurora']});
 await assert.rejects(x.run(),/TENANT_CREATE_PREVIOUS_AMBIGUOUS_RESPONSE_aurora/);
 assert.equal(x.calls.length,0);
});

test('missing readback blocks continuation',async()=>{
 const x=lab({missingAfterPost:true});
 await assert.rejects(x.run(),/TENANT_NOT_PRESENT_AFTER_CREATE_aurora/);
 assert.equal(x.journal.tenants.aurora.state,'create-started');
});

test('wrong owner is rejected before Brisa POST',async()=>{
 const x=lab({initial:{aurora:existing('aurora')},remote:['aurora'],ownerMismatch:true});
 await assert.rejects(x.run(),/ROOT_OWNER_MISMATCH_aurora/);
 assert.equal(x.calls.filter(c=>c.method==='POST').length,0);
});

test('profile mismatch is rejected before Brisa POST',async()=>{
 const x=lab({initial:{aurora:existing('aurora')},remote:['aurora'],failDetails:true});
 await assert.rejects(x.run(),/ROOT_OWNER_DETAILS_MISMATCH_aurora/);
 assert.equal(x.calls.filter(c=>c.method==='POST').length,0);
});

test('tenant ID change is refused',async()=>{
 const a=existing('aurora','created');a.tenantId='unexpected-tenant-id';
 const x=lab({initial:{aurora:a},remote:['aurora']});
 await assert.rejects(x.run(),/ROOT_TENANT_ID_CHANGED_aurora/);
});

test('recovery owner ID mismatch is refused',async()=>{
 const a=existing('aurora');a.ownerRecovery={state:'update-started',candidatePassword:'a'.repeat(28),tenantId:'tenant-aurora',ownerId:'wrong-owner'};
 const x=lab({initial:{aurora:a},remote:['aurora']});
 await assert.rejects(x.run(),/ROOT_OWNER_RECOVERY_ID_MISMATCH_aurora/);
});

test('deactivated tenant fails closed',async()=>{
 const x=lab({initial:{aurora:existing('aurora')},remote:['aurora'],deactivated:true});
 await assert.rejects(x.run(),/ROOT_TENANT_READBACK_FAILED_aurora/);
});

test('full bootstrap halts before tenant-scoped OIDC writes without OAuth management authorization',async()=>{
 const x=lab();
 await assert.rejects(x.run(false),/TENANT_OIDC_MANAGEMENT_OAUTH_NOT_CONFIGURED/);
 assert.equal(x.journal.tenants.brisa.state,'created');
 assert.equal(x.journal.acceptance,'NOT_VERIFIED');
 assert.equal(x.calls.filter(c=>c.method==='POST').length,2);
});
