import test from 'node:test';
import assert from 'node:assert/strict';
import {planPartner, applyPartner} from '../../../scripts/p2-org-core.mjs';

const BASE='https://localhost:9444';
const PATH=BASE+'/t/aurora.identity.test/o/api/server/v1/organizations';
const ROOT='5252717e-1024-40f0-89ee-016b513d36f3';
const CHILD='22222222-2222-4222-8222-222222222222';
const ARG={base:BASE,tenant:'aurora.identity.test',name:'Verde Logistics',handle:'verde-logistics'};
function fixture({page={links:[]}, rootHasChildren=false, rootRecheckHasChildren=rootHasChildren,
  followupPage=null, rootIdOnRecheck=ROOT, afterWrite=true}={}){
  const calls=[];let roots=0, pages=0, created=false;
  const client=async (method,url,body)=>{
    calls.push({method,url});
    if(method==='GET' && url===PATH+'/self'){
      const n=roots++;
      return {id:n===0 ? ROOT : rootIdOnRecheck,type:'TENANT',
        ...( (n===0?rootHasChildren:rootRecheckHasChildren) !== 'MISSING' ?
          {hasChildren:n===0?rootHasChildren:rootRecheckHasChildren} : {} )};
    }
    if(method==='GET' && url.startsWith(PATH+'?')){
      return pages++===0 ? page : (followupPage || {organizations:[],links:[]});
    }
    if(method==='POST' && url===PATH) {created=true;return {id:CHILD};}
    if(method==='GET' && url===PATH+'/'+CHILD && created)
      return {id:CHILD,name:'Verde Logistics',orgHandle:'verde-logistics',status:'ACTIVE',parent:{id:ROOT}};
    throw new Error('unexpected_fixture_call:'+method);
  };
  return {client,calls,roots:()=>roots,pages:()=>pages};
}
function getCount(f,method){return f.calls.filter(x=>x.method===method).length;}

test('empty first-page omitted collection reconciles only with two root hasChildren=false reads',async()=>{
  const f=fixture({page:{links:[]}});
  const p=await planPartner({...ARG,client:f.client});
  assert.equal(p.existingId,null);
  assert.equal(p.parentId,ROOT);
  assert.equal(f.roots(),2);
  assert.equal(getCount(f,'POST'),0);
});
test('empty first-page null collection and explicit zero count reconciles with second root read',async()=>{
  const f=fixture({page:{organizations:null,links:[],count:0,totalResults:0}});
  assert.equal((await planPartner({...ARG,client:f.client})).decision,'CREATE_REQUIRES_APPROVAL');
  assert.equal(f.roots(),2);
});
test('empty first page with actual [] retains baseline behavior',async()=>{
  const f=fixture({page:{organizations:[],links:[]},rootHasChildren:'MISSING'});
  assert.equal((await planPartner({...ARG,client:f.client})).existingId,null);
  assert.equal(getCount(f,'POST'),0);
});
test('omitted collection cannot be inferred empty from unspecified root children',async()=>{
  const f=fixture({rootHasChildren:'MISSING'});
  await assert.rejects(planPartner({...ARG,client:f.client}),/ORGS_OMITTED_ROOT_CHILD_COUNT_UNKNOWN/);
  assert.equal(f.roots(),1);
});
test('root explicitly attesting children blocks omitted list even if response otherwise empty',async()=>{
  const f=fixture({rootHasChildren:true});
  await assert.rejects(planPartner({...ARG,client:f.client}),/ORGS_OMITTED_ROOT_HAS_CHILDREN/);
  assert.equal(f.roots(),1);
});
test('root explicitly attesting children blocks [] without next link',async()=>{
  const f=fixture({page:{organizations:[],links:[]},rootHasChildren:true});
  await assert.rejects(planPartner({...ARG,client:f.client}),/EMPTY_LIST_CONFLICTS_WITH_ROOT/);
});
test('root recheck disagreement refuses a create',async()=>{
  const f=fixture({rootHasChildren:false,rootRecheckHasChildren:true});
  await assert.rejects(planPartner({...ARG,client:f.client}),/EMPTY_ROOT_RECHECK_MISMATCH/);
  assert.equal(getCount(f,'POST'),0);
});
test('root identity mismatch on second root read is rejected',async()=>{
  const f=fixture({rootIdOnRecheck:'33333333-3333-4333-8333-333333333333'});
  await assert.rejects(planPartner({...ARG,client:f.client}),/EMPTY_ROOT_RECHECK_MISMATCH/);
});
test('empty collection with a next link cannot certify empty hierarchy',async()=>{
  const f=fixture({page:{links:[{rel:'next',href:'?after=something'}]}});
  await assert.rejects(planPartner({...ARG,client:f.client}),/ORGS_OMITTED_ROOT_NO_CHILDREN/);
  assert.equal(getCount(f,'POST'),0);
});
test('unrelated object cannot be mistaken for empty organization page',async()=>{
  for(const page of [{error:'Forbidden'},{links:[],error:{code:1}},{organizations:null,other:0},
    {organizations:null,links:[{rel:'previous',href:'?before=x'}]},
    {organizations:null,links:[],totalResults:1},
    {organizations:null,links:[],count:3}]){
    const f=fixture({page});
    await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
    assert.equal(getCount(f,'POST'),0);
  }
});
test('second page without collection never triggers empty-root exception',async()=>{
  const f=fixture({rootHasChildren:true,
    page:{organizations:[{id:CHILD,name:'Other Partner',orgHandle:'other'}],links:[{rel:'next',href:'?after=abc'}]},
    followupPage:{links:[]}});
  await assert.rejects(planPartner({...ARG,client:f.client}),/PAGE_1_ORGS_OMITTED/);
  assert.equal(f.pages(),2);
});
test('second page empty [] is independently identified and rejected',async()=>{
  const f=fixture({rootHasChildren:true,
    page:{organizations:[{id:CHILD,name:'Other Partner',orgHandle:'other'}],links:[{rel:'next',href:'?after=abc'}]},
    followupPage:{organizations:[],links:[]}});
  await assert.rejects(planPartner({...ARG,client:f.client}),/PAGE_1_EMPTY_AFTER_CURSOR/);
});
test('null response and wrong org shape remain blocked',async()=>{
  for(const page of [null,[],{organizations:{}},{organizations:'empty'}]){
    const f=fixture({page});
    await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
  }
});
test('an extra non-empty organization contradicts root no-children and blocks creation',async()=>{
  const f=fixture({page:{organizations:[{id:CHILD,name:'Other Partner'}],links:[]},rootHasChildren:false});
  await assert.rejects(planPartner({...ARG,client:f.client}),/LIST_CONFLICTS_WITH_ROOT/);
});
test('untrusted root hasChildren string is invalid',async()=>{
  const f=fixture({rootHasChildren:'false'});
  await assert.rejects(planPartner({...ARG,client:f.client}),/cannot_verify_root_organization/);
});
test('apply replans and reattests an omitted collection before POST',async()=>{
  const f=fixture({page:{organizations:null,links:[]}});
  const p=await planPartner({...ARG,client:f.client});
  // The mock deliberately keeps returning a root attesting no children. Actual
  // post-write readback must still have exact parent/name/handle before success.
  const r=await applyPartner({...ARG,client:f.client,approval:p.approval});
  assert.equal(r.verified,true);
  assert.equal(r.action,'CREATED');
  assert.equal(getCount(f,'POST'),1);
  assert.equal(getCount(f,'GET'),6);
});


test('GA empty-object serialization is accepted only with two authoritative root readbacks',async()=>{
  const f=fixture({page:{}});
  const p=await planPartner({...ARG,client:f.client});
  assert.equal(p.decision,'CREATE_REQUIRES_APPROVAL');
  assert.equal(f.roots(),2);
  assert.equal(getCount(f,'POST'),0);
});
test('GA count-only and null-links empty forms require the two root confirmations',async()=>{
  for (const page of [{count:0},{links:null},{organizations:null}]) {
    const f=fixture({page});
    assert.equal((await planPartner({...ARG,client:f.client})).existingId,null);
    assert.equal(f.roots(),2);
  }
});
test('empty self-link metadata is accepted only for tenant-pinned safe URLs',async()=>{
  for (const href of ['?limit=100&recursive=false',
    '/o/api/server/v1/organizations?limit=10',
    PATH+'?limit=100&recursive=false']) {
    const f=fixture({page:{links:[{rel:'self',href}]}});
    assert.equal((await planPartner({...ARG,client:f.client})).existingId,null);
    assert.equal(f.roots(),2);
  }
});
test('empty-object serialization never overrides contrary root attestation',async()=>{
  for (const rootHasChildren of [true,'MISSING']) {
    const f=fixture({page:{},rootHasChildren});
    await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
    assert.equal(getCount(f,'POST'),0);
  }
  const disagreement=fixture({page:{},rootHasChildren:false,rootRecheckHasChildren:true});
  await assert.rejects(planPartner({...ARG,client:disagreement.client}),/EMPTY_ROOT_RECHECK_MISMATCH/);
});
test('links next, foreign self, previous, unauthorized fields cannot attest empty',async()=>{
  const bad=[{links:[{rel:'next',href:'?after=x'}]},
    {links:[{rel:'self',href:'https://evil.test/o/api/server/v1/organizations'}]},
    {links:[{rel:'self',href:'/t/brisa.identity.test/o/api/server/v1/organizations'}]},
    {links:[{rel:'previous',href:'?before=x'}]},
    {links:[{rel:'self',href:'?limit=100&after=abc'}]},
    {links:[],error:'unexpected'},{count:1},{totalResults:2}];
  for (const page of bad) {
    const f=fixture({page});
    await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
    assert.equal(getCount(f,'POST'),0);
  }
});
test('unsupported response shape emits metadata categories but never raw untrusted data',async()=>{
  const f=fixture({page:{organizations:null, links:[{rel:'next',href:'https://do-not-print.example/?token=secret_value'}]}});
  await assert.rejects(planPartner({...ARG,client:f.client}),(err)=> {
    assert.match(err.message,/PAGE_0_ORGS_NULL_ROOT_NO_CHILDREN:KEYS_2_UNKNOWN_NO_LINKS_NEXT/);
    assert.doesNotMatch(err.message,/do-not-print|secret_value/);
    return true;
  });
});
