import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,mkdirSync,writeFileSync,chmodSync,rmSync,readFileSync,existsSync,symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execute,copyPassword } from './owner-password-repair.mjs';

function fixture(t) {
  const root=mkdtempSync(join(tmpdir(),'wso2-owner-v6-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  mkdirSync(join(root,'var/wso2/tls'),{recursive:true});
  writeFileSync(join(root,'var/wso2/tls/wso2-local.pem'),'test certificate (network mocked)');
  const id={aurora:'a1111111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',brisa:'b2222222-bbbb-bbbb-bbbb-bbbbbbbbbbbb'};
  const oid={aurora:'c3333333-cccc-cccc-cccc-cccccccccccc',brisa:'d4444444-dddd-dddd-dddd-dddddddddddd'};
  const tenants={};
  for(const brand of ['aurora','brisa']) {
    tenants[brand]={owned:true,state:'created',domain:`${brand}.identity.test`,tenantId:id[brand],ownerId:oid[brand],
      owner:{username:'labtenantadmin',password:'Q'.repeat(40),email:'lab-tenant-admin@example.invalid',
        firstname:'Identity',lastname:'Lab'}};
  }
  tenants.aurora.ownerRecovery={state:'update-started',candidatePassword:'U'.repeat(28),tenantId:id.aurora,ownerId:oid.aurora};
  const source={schema:'identity.wso2.tenant-brand.v1',tenants};
  const sourcePath=join(root,'var/wso2/tenant-brand.private.json');
  writeFileSync(sourcePath,JSON.stringify(source),{mode:0o600});chmodSync(sourcePath,0o600);
  const env={WSO2_BASE_URL:'https://localhost:9443',WSO2_ADMIN_USER:'root-admin',WSO2_ADMIN_PASSWORD:'test-credential',
    NODE_EXTRA_CA_CERTS:join(root,'var/wso2/tls/wso2-local.pem'),WSO2_OWNER_RESET_CONFIRM:'RESET_EXISTING_OWNER_WITH_WRITE_AHEAD_JOURNAL'};
  const calls=[];let putStatus=200,afterWriteFailure=false;
  const fetchImpl=async (url,options)=>{
    const u=new URL(url);const p=u.pathname;
    calls.push({method:options.method,path:p});
    if(options.method==='PUT') return new Response(null,{status:putStatus});
    if(afterWriteFailure && calls.some(c=>c.method==='PUT')) throw Error('simulated readback failure');
    if(p==='/api/server/v1/tenants') return Response.json({tenants:Object.keys(tenants).map(brand=>({id:id[brand],domain:`${brand}.identity.test`,lifecycleStatus:{activated:true}}))});
    for(const brand of ['aurora','brisa']) {
      if(p===`/api/server/v1/tenants/${id[brand]}/owners`)
        return Response.json([{id:oid[brand],username:'labtenantadmin'}]);
      if(p===`/api/server/v1/tenants/${id[brand]}/owners/${oid[brand]}`)
        return Response.json({id:oid[brand],username:'labtenantadmin',email:'lab-tenant-admin@example.invalid',firstname:'Identity',lastname:'Lab'});
    }
    return new Response(null,{status:404});
  };
  return {root,id,oid,env,calls,fetchImpl,sourcePath,
    setPutStatus:v=>{putStatus=v;},setReadbackFailure:v=>{afterWriteFailure=v;}};
}
const testPassword=()=>'secure-Lab-ownerPassword99Aa1!';

test('preflight is GET-only and confirms the exact Brisa owner',async t=>{
  const f=fixture(t);
  const r=await execute({mode:'check',brand:'brisa',...f,generatePassword:testPassword});
  assert.equal(r.mode,'GET_ONLY');
  assert.equal(r.remoteWrites,0);
  assert.equal(f.calls.length,3);
  assert(f.calls.every(c=>c.method==='GET'));
  assert.equal(existsSync(join(f.root,'var/wso2/owner-password-repair.private.json')),false);
});

test('authorized Brisa PUT is journaled before network call and cannot be retried',async t=>{
  const f=fixture(t);
  const source=readFileSync(f.sourcePath,'utf8');
  const result=await execute({mode:'apply',brand:'brisa',...f,generatePassword:testPassword});
  assert.equal(result.remoteWriteCount,1);
  assert.equal(result.state,'OWNER_READBACK_CONFIRMED_PASSWORD_UNVERIFIED');
  assert.equal(readFileSync(f.sourcePath,'utf8'),source);
  assert.equal(f.calls.filter(c=>c.method==='PUT').length,1);
  const journal=JSON.parse(readFileSync(join(f.root,'var/wso2/owner-password-repair.private.json'),'utf8'));
  assert.equal(journal.tenants.brisa.password,testPassword());
  assert.equal(journal.tenants.brisa.remoteWriteCount,1);
  let copied;
  const copy=copyPassword({root:f.root,brand:'brisa',copy:x=>{copied=x;}});
  assert.equal(copy.clipboard,'SET');assert.equal(copied,testPassword());
  await assert.rejects(execute({mode:'apply',brand:'brisa',...f,generatePassword:testPassword}),/PREVIOUS_RESET_INTENT_EXISTS_NO_RETRY/);
  assert.equal(f.calls.filter(c=>c.method==='PUT').length,1);
});

test('Aurora pending recovery requires separate override, preserving original journal',async t=>{
  const f=fixture(t);
  const source=readFileSync(f.sourcePath,'utf8');
  await assert.rejects(execute({mode:'apply',brand:'aurora',...f,generatePassword:testPassword}),/AURORA_PREVIOUS_RECOVERY_UNRESOLVED/);
  assert.equal(f.calls.filter(c=>c.method==='PUT').length,0);
  f.env.WSO2_AURORA_PENDING_RECOVERY_CONFIRM='SUPERSEDE_UNRESOLVED_AURORA_RECOVERY_WITH_NEW_REPAIR';
  const r=await execute({mode:'apply',brand:'aurora',...f,generatePassword:testPassword});
  assert.equal(r.remoteWriteCount,1);
  assert.equal(readFileSync(f.sourcePath,'utf8'),source);
  assert.equal(JSON.parse(readFileSync(f.sourcePath)).tenants.aurora.ownerRecovery.state,'update-started');
});

test('HTTP 206 partial response is persisted as uncertain and never retried',async t=>{
  const f=fixture(t);f.setPutStatus(206);
  await assert.rejects(execute({mode:'apply',brand:'brisa',...f,generatePassword:testPassword}),/OWNER_UPDATE_NOT_200_DO_NOT_RETRY/);
  const j=JSON.parse(readFileSync(join(f.root,'var/wso2/owner-password-repair.private.json')));
  assert.equal(j.tenants.brisa.state,'WRITE_OUTCOME_UNCERTAIN');
  assert.throws(()=>copyPassword({root:f.root,brand:'brisa',copy:()=>{}}),/NO_ACKNOWLEDGED_RESET_PASSWORD/);
  await assert.rejects(execute({mode:'apply',brand:'brisa',...f,generatePassword:testPassword}),/PREVIOUS_RESET_INTENT_EXISTS_NO_RETRY/);
  assert.equal(f.calls.filter(c=>c.method==='PUT').length,1);
});

test('HTTP 200 with readback failure preserves acknowledged status and never retries',async t=>{
  const f=fixture(t);f.setReadbackFailure(true);
  const r=await execute({mode:'apply',brand:'brisa',...f,generatePassword:testPassword});
  assert.equal(r.state,'HTTP_200_ACKNOWLEDGED_NOT_AUTHENTICATED');
  const state=await execute({mode:'status',root:f.root});
  assert.equal(state.brisa.remoteWriteCount,1);
});

test('fail closed for symlinked private journal and unknown remote identity',async t=>{
  const f=fixture(t);
  const source=readFileSync(f.sourcePath);
  rmSync(f.sourcePath);
  const real=join(f.root,'original-private.json');
  writeFileSync(real,source,{mode:0o600});symlinkSync(real,f.sourcePath);
  await assert.rejects(execute({mode:'check',brand:'brisa',...f}),/PRIVATE_FILE_UNSAFE/);
  assert.equal(f.calls.length,0);
});
