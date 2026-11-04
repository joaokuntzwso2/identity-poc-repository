import test from 'node:test';
import assert from 'node:assert/strict';
import { TENANT, PARTNER, planPartner, inspectPartnerInventory, organizationNextPath,
  makeTransport } from '../../scripts/p2/guarded-org.mjs';

const ROOT='11111111-1111-4111-8111-111111111111';
const CHILD='22222222-2222-4222-8222-222222222222';
const OTHER='33333333-3333-4333-8333-333333333333';
const P=`/t/${TENANT}/o/api/server/v1/organizations`;
const MATCH={id:CHILD,name:PARTNER.name,orgHandle:PARTNER.orgHandle};
const DETAIL={...MATCH,parent:{id:ROOT},status:'ACTIVE'};
const ROOT_GOOD={id:ROOT,type:'TENANT',orgHandle:TENANT,hasChildren:false};
const filtered = path => path.startsWith(P+'?') && new URL('https://localhost:9444'+path).searchParams.get('filter')===`name eq ${PARTNER.name}`;
function fake({root=ROOT_GOOD, pages=[{organizations:[]}], fallbackPages=[], detail=DETAIL, onCall=()=>{}}={}) {
  let nextPage=0;
  let nextFallback=0;
  let rootReads=0;
  const log=[];
  const call=async (method,path) => {
    log.push([method,path]); onCall(method,path);
    assert.equal(method,'GET','No management mutation permitted in this test fixture');
    if(path===P+'/metadata') { rootReads++;return {status:200,body:typeof root==='function'?root(rootReads):root}; }
    if(filtered(path)) {
      assert.ok(nextPage<pages.length,'Requested unexpected page');
      return {status:200,body:pages[nextPage++]};
    }
    if(path.startsWith(P+'?') && !filtered(path)) {
      assert.ok(nextFallback<fallbackPages.length,'Requested unexpected fallback page');
      return {status:200,body:fallbackPages[nextFallback++]};
    }
    if(path===P+'/'+CHILD) return {status:200,body:detail};
    throw new Error('Unexpected request');
  };
  return {call,log};
}
test('documented no-totalResults empty organization collection plans absent with GET only',async()=>{
  const f=fake({pages:[{organizations:[],links:[]}]});
  assert.equal((await planPartner(f.call,ROOT)).action,'CREATE');
  assert.deepEqual(f.log.map(x=>x[0]),['GET','GET']);
});
test('GA omitted empty collection requires two explicit root hasChildren=false attestations',async()=>{
  const f=fake({pages:[{links:[],totalResults:0}]});
  assert.equal((await planPartner(f.call,ROOT)).action,'CREATE');
  assert.deepEqual(f.log.map(x=>x[1]),[P+'/metadata',f.log[1][1],P+'/metadata']);
});
test('GA omitted collection with no count is only accepted with two tenant-root attestations',async()=>{
  const f=fake({pages:[{}]});
  assert.equal((await planPartner(f.call,ROOT)).action,'CREATE');
});
test('GA missing collection is not trusted if the root may have children',async()=>{
  const f=fake({root:{...ROOT_GOOD,hasChildren:true},pages:[{totalResults:0,links:[]}], fallbackPages:[{}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_FALLBACK_COLLECTION_INCOMPLETE/);
});
test('GA missing collection with nonzero total never implies absence',async()=>{
  const f=fake({pages:[{totalResults:1,links:[]}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_INVENTORY_INCOMPLETE/);
});
test('root disagreement on recheck refuses empty inventory',async()=>{
  const f=fake({root:n=> n===1?ROOT_GOOD:{...ROOT_GOOD,hasChildren:true},pages:[{}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_EMPTY_ROOT_RECHECK_DISAGREEMENT/);
});
test('cursor pagination accepts pinned tenantless next link, with exact verified detail',async()=>{
  const f=fake({pages:[
    {organizations:[{id:CHILD}],totalResults:1,links:[{rel:'next',href:`/o/api/server/v1/organizations?limit=100&after=cursor1`}]},
    {organizations:[],totalResults:1,links:[]}
  ]});
  assert.equal((await planPartner(f.call,ROOT)).action,'ALREADY_PRESENT');
  assert.equal(f.log.length,4);
  const next=f.log[2][1];
  assert.equal(new URLSearchParams(next.split('?')[1]).get('filter'),`name eq ${PARTNER.name}`);
  assert.ok(next.includes('after=cursor1'));
});
test('wrong parent in full detail blocks despite matching page',async()=>{
  const f=fake({pages:[{organizations:[{id:CHILD}]}],detail:{...DETAIL,parent:{id:OTHER}}});
  await assert.rejects(planPartner(f.call,ROOT),/PARTNER_ORGANIZATION_READBACK_MISMATCH/);
});
test('looped cursor denied without any POST',async()=>{
  const link={rel:'next',href:`/o/api/server/v1/organizations?after=cursor1`};
  const f=fake({pages:[{organizations:[MATCH],links:[link]},{organizations:[MATCH],links:[link]}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_DUPLICATE_ID_ACROSS_PAGES/);
});
test('next link cannot switch tenant, protocol, host, query filter or privilege context',()=>{
  const bad=[
    'https://evil.example/o/api/server/v1/organizations?after=X',
    '/t/brisa.identity.test/o/api/server/v1/organizations?after=X',
    'http://localhost:9444/o/api/server/v1/organizations?after=X',
    '/o/api/server/v1/organizations?after=X&filter=name%20eq%20Other',
    '/o/api/server/v1/organizations?after=X&recursive=true',
    '/o/api/server/v1/organizations?after=X&before=Y',
    '/o/api/server/v1/organizations?after=X&after=Y',
    '//localhost:9444/o/api/server/v1/organizations?after=X',
    '/o/api/server/v1/organizations?after=X&limit=1000'
  ];
  for(const href of bad) assert.throws(()=>organizationNextPath(href), /ORG_NEXT_/);
});
test('cursor loop is blocked even if all items are distinct',()=>{
  const seen=new Set();
  organizationNextPath('/o/api/server/v1/organizations?after=cursor1',seen);
  assert.throws(()=>organizationNextPath('/o/api/server/v1/organizations?after=cursor1',seen),/ORG_PAGINATION_LOOP/);
});
test('duplicate names and IDs are refused',async()=>{
  const f=fake({pages:[{organizations:[MATCH,{...MATCH,id:OTHER}]}]});
  await assert.rejects(planPartner(f.call,ROOT),/AMBIGUOUS_PARTNER_NAME/);
});
test('wrong or truncated count is refused',async()=>{
  const f=fake({pages:[{organizations:[],totalResults:2}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_LIST_TOTAL_INCONSISTENT/);
});
test('next link plus empty page cannot pass',async()=>{
  const f=fake({pages:[{organizations:[],links:[{rel:'next',href:'/o/api/server/v1/organizations?after=Z'}]}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_EMPTY_PAGE_WITH_NEXT_LINK/);
});
test('sanitized diagnostic reports structure and never names, IDs or tokens',async()=>{
  const f=fake({pages:[{totalResults:0,links:[]}]});
  const r=await inspectPartnerInventory(f.call,ROOT);
  assert.equal(r.collection,'omitted');
  assert.equal(r.managementWrites,0);
  assert.equal(r.firstPageCount,null);
  assert.ok(!JSON.stringify(r).includes(ROOT));
  assert.ok(!JSON.stringify(r).includes(PARTNER.name));
});
test('request transport rejects foreign organization path',async()=>{
  const call=makeTransport({origin:'https://localhost:9444/',bearer:'x'.repeat(35),fetcher:async()=>{throw Error('should not send');}});
  await assert.rejects(call('GET','/t/brisa.identity.test/o/api/server/v1/organizations'),/CROSS_TENANT_OR_PATH_DENIED/);
});

test('GA omitted filtered collection with other children uses complete unfiltered fallback', async()=>{
  const f=fake({root:{...ROOT_GOOD,hasChildren:true},pages:[{totalResults:0,links:[]}],
    fallbackPages:[{organizations:[{id:OTHER,name:'Other partner',orgHandle:'other'}],links:[],totalResults:1}]});
  assert.equal((await planPartner(f.call,ROOT)).action,'CREATE');
  assert.deepEqual(f.log.map(x=>x[0]),['GET','GET','GET']);
});
test('fallback inventory discovers target despite omitted filtered list, with exact readback', async()=>{
  const f=fake({root:{...ROOT_GOOD,hasChildren:true},pages:[{}],
    fallbackPages:[{organizations:[{id:OTHER,name:'Other partner'}],links:[{rel:'next',href:'/o/api/server/v1/organizations?after=abc'}],totalResults:2},
    {organizations:[{id:CHILD,name:PARTNER.name}],links:[],totalResults:2}]});
  assert.equal((await planPartner(f.call,ROOT)).action,'ALREADY_PRESENT');
});
test('fallback cannot silently ignore a missing unfiltered collection or unexpected count', async()=>{
  const f=fake({root:{...ROOT_GOOD,hasChildren:true},pages:[{}],
    fallbackPages:[{organizations:[],totalResults:2,links:[]}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_FALLBACK_TOTAL_INCONSISTENT/);
});
test('fallback cannot accept root-has-children with empty child listing', async()=>{
  const f=fake({root:{...ROOT_GOOD,hasChildren:true},pages:[{}],
    fallbackPages:[{organizations:[],links:[]}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_FALLBACK_ROOT_CHILDREN_CONTRADICTION/);
});
test('fallback refuses cursor with injected cross-tenant filter', async()=>{
  const f=fake({root:{...ROOT_GOOD,hasChildren:true},pages:[{}],
    fallbackPages:[{organizations:[{id:OTHER,name:'Other partner'}],links:[{rel:'next',href:'/o/api/server/v1/organizations?after=abc&filter=name+eq+Other'}]}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_NEXT_FILTER_CHANGED/);
});

test('next relation lacking href cannot imply complete inventory',async()=>{
  const f=fake({pages:[{organizations:[],links:[{rel:'next'}]}]});
  await assert.rejects(planPartner(f.call,ROOT),/ORG_NEXT_LINK_MISSING_HREF/);
});
