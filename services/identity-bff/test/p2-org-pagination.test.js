import test from 'node:test';
import assert from 'node:assert/strict';
import {planPartner, applyPartner} from '../../../scripts/p2-org-core.mjs';

const BASE='https://localhost:9444';
const PATH=BASE+'/t/aurora.identity.test/o/api/server/v1/organizations';
const ROOT='5252717e-1024-40f0-89ee-016b513d36f3';
const CHILD='22222222-2222-4222-8222-222222222222';
const OTHER='33333333-3333-4333-8333-333333333333';
const TENANT='aurora.identity.test';
const ARG={base:BASE,tenant:TENANT,name:'Verde Logistics',handle:'verde-logistics'};
const entry=(id,name='Verde Logistics',orgHandle='verde-logistics')=>({id,name,orgHandle});
const detail=(id=CHILD,name='Verde Logistics',orgHandle='verde-logistics')=>
  ({id,name,orgHandle,status:'ACTIVE',parent:{id:ROOT}});
function server({pages, details={}, createId=CHILD}={}) {
  let index=0, created=false;
  const calls=[];
  const client=async (method,url,body)=>{
    calls.push({method,url,body});
    if(method==='GET'&&url===PATH+'/self')return{id:ROOT,type:'TENANT'};
    if(method==='GET'&&url.startsWith(PATH+'?')){
      const expected=pages[index];
      if(!expected)throw Error('unexpected_extra_page');
      if (new URL(url).searchParams.has('after') || new URL(url).searchParams.has('next'))
        assert.match(url,/[?&](after|next)=/);
      index++;
      return expected;
    }
    if(method==='GET'&&url.startsWith(PATH+'/')) {
      const id=url.slice(PATH.length+1);
      if(created&&id===createId)return detail(createId);
      if(details[id])return details[id];
      throw Error('unexpected_detail_'+id);
    }
    if(method==='POST'&&url===PATH){created=true;return{id:createId};}
    throw Error('unexpected_network_'+method);
  };
  return {client,calls,pagesSeen:()=>index};
}
const next=(href)=>({links:[{rel:'next',href}]});
function list(organizations,href){return {organizations, ...(href?next(href):{links:[]})};}

test('first page with no next link remains read-only and complete',async()=>{
  const f=server({pages:[list([])]});
  const r=await planPartner({...ARG,client:f.client});
  assert.equal(r.existingId,null);
  assert.equal(f.pagesSeen(),1);
  assert.deepEqual(f.calls.map(c=>c.method),['GET','GET']);
});
test('two pages: documented tenantless next link is rebuilt on Aurora endpoint',async()=>{
  const f=server({pages:[
    list([entry(OTHER,'Other Partner','other-partner')],'/o/api/server/v1/organizations?limit=10&recursive=false&next=ABC123'),
    list([entry(CHILD)]),
  ],details:{[CHILD]:detail()}});
  const r=await planPartner({...ARG,client:f.client});
  assert.equal(r.existingId,CHILD);
  assert.equal(f.pagesSeen(),2);
  assert.equal(f.calls[2].url,PATH+'?limit=10&recursive=false&next=ABC123');
  assert.ok(f.calls.every(x=>x.url.startsWith(PATH)));
});
test('three pages: after cursor supported, later collisions detected before writes',async()=>{
  const f=server({pages:[
    list([entry(OTHER,'Other Partner','other-partner')],'?limit=50&recursive=false&after=c1'),
    list([entry(CHILD)],'/t/aurora.identity.test/o/api/server/v1/organizations?after=c2&limit=50'),
    list([entry('44444444-4444-4444-8444-444444444444','Verde Logistics','different-handle')]),
  ],details:{[CHILD]:detail(),['44444444-4444-4444-8444-444444444444']:detail('44444444-4444-4444-8444-444444444444','Verde Logistics','different-handle')}});
  await assert.rejects(planPartner({...ARG,client:f.client}),/partner_name_or_handle_collision/);
  assert.equal(f.pagesSeen(),3);
  assert.equal(f.calls.some(x=>x.method!=='GET'),false);
});
test('duplicate organization ID across pages blocks plan and write',async()=>{
  const f=server({pages:[list([entry(CHILD)],'?after=one'),list([entry(CHILD)])]});
  await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
  assert.equal(f.calls.some(x=>x.method==='POST'),false);
});
test('cursor loops are rejected even when pages have unique IDs',async()=>{
  const f=server({pages:[list([entry(OTHER,'Other','other')],'?after=loop'),list([entry(CHILD)],'?after=loop')]});
  await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
  assert.equal(f.pagesSeen(),2);
});
test('foreign tenant, foreign origin and wrong endpoint metadata blocked before next GET',async()=>{
  const unsafe=[
    'https://evil.invalid/o/api/server/v1/organizations?after=x',
    'https://localhost:9443/o/api/server/v1/organizations?after=x',
    '/t/brisa.identity.test/o/api/server/v1/organizations?after=x',
    '/api/server/v1/organizations?after=x',
    '//evil.invalid/o/api/server/v1/organizations?after=x',
    '/o/api/server/v1/organizations?recursive=true&after=x',
    '/o/api/server/v1/organizations?after=x&filter=name',
    '/o/api/server/v1/organizations?after=x&after=y',
    '/o/api/server/v1/organizations?next=x&after=y',
    '/o/api/server/v1/organizations?before=x',
    '/o/api/server/v1/organizations?next=x#fragment',
    'https://user:pass@localhost:9444/o/api/server/v1/organizations?after=x',
  ];
  for(const href of unsafe){
    const f=server({pages:[list([entry(OTHER,'Other','other')],href)]});
    await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/,href);
    assert.equal(f.pagesSeen(),1,href);
    assert.ok(f.calls.every(c=>c.method==='GET'),href);
  }
});
test('invalid/missing link cursor and duplicate next links block',async()=>{
  for(const links of [[{rel:'next'}],[{rel:'next',href:'?after='}],
    [{rel:'next',href:'?after=x'},{rel:'next',href:'?after=y'}],
    'not links',[{rel:'next',href:'?limit=0&after=x'}]]){
    const f=server({pages:[{organizations:[entry(OTHER,'Other','other')],links}]});
    await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
  }
});
test('missing organizations, oversize page and full page without a cursor are blocked',async()=>{
  const f1=server({pages:[{links:[]}]});
  await assert.rejects(planPartner({...ARG,client:f1.client}),/organization_inventory_incomplete/);
  const hundred=Array.from({length:100},(_,i)=>entry((i+1).toString(16).padStart(8,'0')+'-2222-4222-8222-222222222222',`Other ${i}`,`other-${i}`));
  const f2=server({pages:[list(hundred)]});
  await assert.rejects(planPartner({...ARG,client:f2.client}),/organization_inventory_incomplete/);
  const f3=server({pages:[list([...hundred,entry(CHILD)])]});
  await assert.rejects(planPartner({...ARG,client:f3.client}),/organization_inventory_incomplete/);
});
test('empty page after next cursor is not treated as successful completion',async()=>{
  const f=server({pages:[list([entry(OTHER,'Other','other')],'?after=x'),list([])]});
  await assert.rejects(planPartner({...ARG,client:f.client}),/organization_inventory_incomplete/);
});
test('orgHandle omitted in list triggers readback and detects cross-name handle collision',async()=>{
  const f=server({pages:[list([{id:CHILD,name:'Another Company'}])],details:{[CHILD]:detail(CHILD,'Another Company','verde-logistics')}});
  await assert.rejects(planPartner({...ARG,client:f.client}),/partner_name_or_handle_collision/);
  assert.equal(f.calls.some(x=>x.method==='POST'),false);
});
test('orgHandle omitted for matching partner is resolved with verified detail',async()=>{
  const f=server({pages:[list([{id:CHILD,name:'Verde Logistics'}])],details:{[CHILD]:detail()}});
  const r=await planPartner({...ARG,client:f.client});
  assert.equal(r.existingId,CHILD);
});
test('final page partner creates with approval, then replan reads all pages before writing',async()=>{
  const pages=[list([entry(OTHER,'Other','other')],'?after=x'),
    list([entry('44444444-4444-4444-8444-444444444444','Second','second')])];
  const f=server({pages:pages.concat(pages)});
  const p=await planPartner({...ARG,client:f.client});
  const applied=await applyPartner({...ARG,client:f.client,approval:p.approval});
  assert.equal(applied.action,'CREATED');
  assert.equal(f.pagesSeen(),4);
  assert.equal(f.calls.filter(x=>x.method==='POST').length,1);
});
test('stale paginated inventory collision discovered on replan prevents POST',async()=>{
  const f=server({pages:[list([]),list([entry(CHILD)])],details:{[CHILD]:detail()}});
  const p=await planPartner({...ARG,client:f.client});
  const applied=await applyPartner({...ARG,client:f.client,approval:p.approval});
  assert.equal(applied.action,'NOOP');
  assert.equal(f.calls.filter(x=>x.method==='POST').length,0);
});
