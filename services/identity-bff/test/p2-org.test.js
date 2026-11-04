import test from 'node:test';
import assert from 'node:assert/strict';
import { planPartner, applyPartner, planPartnerDeactivation, deactivatePartner, rootTenant } from '../../../scripts/p2-org-core.mjs';

const tenant='aurora.identity.test', base='https://localhost:9444';
const rootId='123e4567-e89b-42d3-a456-426614174000';
const childId='123e4567-e89b-42d3-a456-426614174001';
function fixture({existing=false,childParent=rootId,afterWriteMismatch=false,nextPage=false,
  rootType='TENANT',afterWriteStatus='ACTIVE',hasChildren=false}={}) {
  const calls=[]; let child=existing?{
    id:childId,name:'Verde Logistics',orgHandle:'verde-logistics',status:'ACTIVE',parent:{id:childParent},attributes:[],hasChildren
  }:null;
  const client=async(method,url,body)=>{
    const u=new URL(url);calls.push({method,path:u.pathname,body});
    if(method==='GET' && u.pathname.endsWith('/self'))return {id:rootId,type:rootType,name:'Aurora'};
    if(method==='GET' && u.pathname.endsWith('/organizations'))return {
      organizations:child?[{id:childId,name:child.name,orgHandle:child.orgHandle}]:[],
      links:nextPage?[{rel:'next'}]:[]
    };
    if(method==='GET' && u.pathname.endsWith(`/${childId}`))return child;
    if(method==='POST' && u.pathname.endsWith('/organizations')){
      child={id:childId,name:body.name,orgHandle:body.orgHandle,status:afterWriteStatus,
        parent:{id:afterWriteMismatch?'123e4567-e89b-42d3-a456-426614174002':rootId},attributes:[]};
      return {id:childId};
    }
    if(method==='PUT' && u.pathname.endsWith(`/${childId}`)){
      child={...child,...body};return child;
    }
    throw new Error('unexpected_fixture_call');
  };
  return {client,calls};
}
test('Carbon Super and unknown root tenants are prohibited',()=>{
  for(const t of ['carbon.super','aura.identity.test','/', 'BRISA.IDENTITY.TEST'])
    assert.throws(()=>rootTenant(t),/not_allowlisted/);
});
test('read-only plan does not write and binds to Aurora root',async()=>{
  const f=fixture(); const plan=await planPartner({client:f.client,base,tenant,name:'Verde Logistics',handle:'verde-logistics'});
  assert.equal(plan.decision,'CREATE_REQUIRES_APPROVAL');assert.equal(plan.parentId,rootId);
  assert.equal(plan.approval.length,64);assert.deepEqual(f.calls.map(x=>x.method),['GET','GET']);
});
test('create requires exact operator approval; creation has readback',async()=>{
  const f=fixture(); const args={client:f.client,base,tenant,name:'Verde Logistics',handle:'verde-logistics'};
  await assert.rejects(()=>applyPartner({...args,approval:'wrong'}),/approval_fingerprint/);
  assert.equal(f.calls.some(x=>x.method==='POST'),false);
  const p=await planPartner(args); const outcome=await applyPartner({...args,approval:p.approval});
  assert.equal(outcome.action,'CREATED');assert.equal(outcome.verified,true);
  assert.equal(outcome.parentId,rootId);assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
  const again=await applyPartner({...args,approval:p.approval});
  assert.equal(again.action,'NOOP');assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
});
test('unverified/foreign parent is rejected before and after mutation',async()=>{
  const f=fixture({existing:true,childParent:'123e4567-e89b-42d3-a456-426614174002'});
  await assert.rejects(()=>planPartner({client:f.client,base,tenant,name:'Verde Logistics',handle:'verde-logistics'}),/parent_or_identity/);
  const g=fixture({afterWriteMismatch:true});const args={client:g.client,base,tenant,name:'Verde Logistics',handle:'verde-logistics'};
  const plan=await planPartner(args);
  await assert.rejects(()=>applyPartner({...args,approval:plan.approval}),/post_write_readback_mismatch/);
  assert.equal(g.calls.filter(x=>x.method==='POST').length,1);
  const h=fixture({rootType:'ORGANIZATION'});
  await assert.rejects(()=>planPartner({...args,client:h.client}),/cannot_verify_root_organization/);
  const i=fixture({afterWriteStatus:'DISABLED'}); const q=await planPartner({...args,client:i.client});
  await assert.rejects(()=>applyPartner({...args,client:i.client,approval:q.approval}),/create_not_active/);
});
test('incomplete pagination blocks plans and mutations',async()=>{
  const f=fixture({nextPage:true});
  await assert.rejects(()=>planPartner({client:f.client,base,tenant,name:'Verde Logistics',handle:'verde-logistics'}),/inventory_incomplete/);
});
test('partner disable requires its own approval and cannot disable root',async()=>{
  const f=fixture({existing:true});const args={client:f.client,base,tenant,name:'Verde Logistics',handle:'verde-logistics'};
  const p=await planPartnerDeactivation(args);
  assert.equal(p.decision,'DISABLE_REQUIRES_APPROVAL');
  await assert.rejects(()=>deactivatePartner({...args,approval:p.approval}),/fingerprint/);
  assert.equal(f.calls.filter(x=>x.method==='PUT').length,0);
  const done=await deactivatePartner({...args,approval:p.disableApproval});
  assert.equal(done.status,'DISABLED');assert.equal(done.action,'DISABLED');
  const again=await deactivatePartner({...args,approval:p.disableApproval});
  assert.equal(again.action,'NOOP');assert.equal(f.calls.filter(x=>x.method==='PUT').length,1);
});

test('partner with child organizations cannot be disabled by operator CLI',async()=>{
  const f=fixture({existing:true,hasChildren:true});
  const args={client:f.client,base,tenant,name:'Verde Logistics',handle:'verde-logistics'};
  const plan=await planPartnerDeactivation(args);
  await assert.rejects(()=>deactivatePartner({...args,approval:plan.disableApproval}),/dependents_offboarding_blocked/);
  assert.equal(f.calls.some(x=>x.method==='PUT'),false);
});
