import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectPartner, planGroup, createGroup, endpoints } from '../../../scripts/p2-partner-core.mjs';
import { createPartnerClient } from '../../../scripts/p2-partner-transport.mjs';
import { reconcile, PARTNER_SCOPES, ROOT_SCOPES } from '../../../scripts/p2-bootstrap-core.mjs';

const ROOT='11111111-1111-4111-8111-111111111111';
const ORG='22222222-2222-4222-8222-222222222222';
const GROUP='33333333-3333-4333-8333-333333333333';
const config={rootTenant:'aurora.identity.test',rootId:ROOT,orgId:ORG};
const urls=endpoints(config);
const id=(n)=>`${n.toString(16).padStart(8,'0')}-2222-4222-8222-222222222222`;
const full=(rows, total=rows.length, startIndex=1, metadata=true)=>({
  schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
  totalResults:total,Resources:rows,
  ...(metadata?{startIndex,itemsPerPage:rows.length}:{})
});
function fixture({groupPages=[{totalResults:0}],userPages=[{totalResults:0}]}={}) {
  const requests=[];
  const client=async(method,url,body)=>{
    requests.push({method,url,body});
    if(method==='GET'&&url===urls.org)return {id:ORG,parent:{id:ROOT},status:'ACTIVE'};
    if(method==='GET' && url.startsWith(`${urls.groups}?startIndex=`)){
      const start=Number(new URL(url).searchParams.get('startIndex'));
      return start===1 ? groupPages[0] : groupPages[1];
    }
    if(method==='GET' && url.startsWith(`${urls.users}?startIndex=`)){
      const start=Number(new URL(url).searchParams.get('startIndex'));
      return start===1 ? userPages[0] : userPages[1];
    }
    if(method==='GET' && url===`${urls.groups}/${GROUP}`)return {id:GROUP,displayName:'PRIMARY/p2-partner-operations',members:[],roles:[]};
    if(method==='POST')return {id:GROUP};
    throw Error('unexpected_mock_request');
  };
  return {client,requests};
}

test('SCIM zero results allow omitted Resources when totalResults is zero',async()=>{
  const f=fixture();
  const x=await inspectPartner({client:f.client,config});
  assert.deepEqual([x.groupCount,x.userCount],[0,0]);
  const p=await planGroup({client:f.client,config,name:'p2-partner-operations'});
  assert.equal(p.decision,'CREATE_REQUIRES_APPROVAL');
  assert.equal(f.requests.some(x=>x.method!=='GET'),false);
});

test('SCIM pagination traverses all pages even though totalResults exceeds first page length',async()=>{
  const groups=Array.from({length:125},(_,i)=>({id:id(i+1),displayName:`PRIMARY/other-${i}`}));
  groups[124]={id:GROUP,displayName:'PRIMARY/p2-partner-operations'};
  const users=Array.from({length:101},(_,i)=>({id:id(i+1000)}));
  const f=fixture({groupPages:[full(groups.slice(0,100),125,1),full(groups.slice(100),125,101)],
    userPages:[full(users.slice(0,100),101,1),full(users.slice(100),101,101)]});
  const inspected=await inspectPartner({client:f.client,config});
  assert.equal(inspected.groupCount,125); assert.equal(inspected.userCount,101);
  const plan=await planGroup({client:f.client,config,name:'p2-partner-operations'});
  assert.equal(plan.decision,'ALREADY_EXISTS'); assert.equal(plan.existingId,GROUP);
  assert.ok(f.requests.some(r=>r.url===`${urls.groups}?startIndex=101&count=100`));
  assert.ok(f.requests.some(r=>r.url===`${urls.users}?startIndex=101&count=100`));
  assert.ok(f.requests.every(x=>x.method==='GET'));
});

test('partial SCIM page requires actual pagination metadata',async()=>{
  const f=fixture({groupPages:[full([{id:id(4)}],2,1,false)]});
  await assert.rejects(inspectPartner({client:f.client,config}),/GROUPS_PAGINATION_METADATA_MISSING/);
  assert.ok(f.requests.every(x=>x.method==='GET'));
});

test('missing totalResults is not silently treated as an empty inventory',async()=>{
  const f=fixture({groupPages:[{}]});
  await assert.rejects(inspectPartner({client:f.client,config}),/GROUPS_TOTAL_RESULTS_INVALID/);
});

test('nonzero total must include a nonempty Resources array',async()=>{
  for (const page of [{totalResults:1},{totalResults:1,Resources:[]},{totalResults:1,Resources:null}]) {
    const f=fixture({groupPages:[page]});
    await assert.rejects(inspectPartner({client:f.client,config}),/GROUPS_(EMPTY_NONZERO_PAGE|RESOURCES_MISSING_OR_INVALID)/);
  }
});

test('SCIM users failure has distinct error and never triggers group creation',async()=>{
  const f=fixture({userPages:[{}]});
  await assert.rejects(inspectPartner({client:f.client,config}),/USERS_TOTAL_RESULTS_INVALID/);
  assert.ok(f.requests.every(x=>x.method==='GET'));
});

test('SCIM pagination rejects duplicate IDs, count changes and invalid offsets',async()=>{
  const a={id:id(10),displayName:'PRIMARY/a'}, b={id:id(11),displayName:'PRIMARY/b'};
  const duplicate=fixture({groupPages:[full([a],2,1),full([a],2,2)]});
  await assert.rejects(inspectPartner({client:duplicate.client,config}),/GROUPS_DUPLICATE_RESOURCE_ID/);
  const changing=fixture({groupPages:[full([a],2,1),full([b],3,2)]});
  await assert.rejects(inspectPartner({client:changing.client,config}),/GROUPS_TOTAL_RESULTS_CHANGED/);
  const wrongOffset=fixture({groupPages:[full([a],2,1),full([b],2,4)]});
  await assert.rejects(inspectPartner({client:wrongOffset.client,config}),/GROUPS_START_INDEX_MISMATCH/);
});

test('partial final page cannot be empty or lack expected Resources',async()=>{
  const f=fixture({groupPages:[full([{id:id(3)}],2,1),full([],2,2)]});
  await assert.rejects(inspectPartner({client:f.client,config}),/GROUPS_EMPTY_NONZERO_PAGE/);
});

test('group creation remains blocked on an incomplete inventory, with zero writes',async()=>{
  const f=fixture({groupPages:[{totalResults:10,Resources:[],startIndex:1,itemsPerPage:0}]});
  await assert.rejects(createGroup({client:f.client,config,name:'p2-partner-operations',approval:'abc'}),/scim_inventory_not_complete/);
  assert.equal(f.requests.some(x=>x.method!=='GET'),false);
});

test('SCIM transport accepts only canonical bounded pagination on the pinned endpoint',async()=>{
  let hits=0;
  const transport=createPartnerClient({config,token:'t'.repeat(40),request:async()=>{
    hits++; return {ok:true,status:200,text:async()=>'{"totalResults":0}'};
  }});
  await transport('GET',`${urls.groups}?startIndex=101&count=100`);
  await transport('GET',`${urls.users}?startIndex=201&count=100`);
  assert.equal(hits,2);
  for(const url of [
    `${urls.groups}?startIndex=0&count=100`,
    `${urls.groups}?startIndex=3001&count=100`,
    `${urls.groups}?startIndex=2&count=101`,
    `${urls.groups}?count=100&startIndex=2`,
    `${urls.groups}?startIndex=2&count=100&filter=x`,
    `https://localhost:9444/t/brisa.identity.test/o/scim2/Groups?startIndex=2&count=100`,
    `https://attacker.test/t/aurora.identity.test/o/scim2/Groups?startIndex=2&count=100`
  ]) await assert.rejects(transport('GET',url),/unapproved_scim_query|request_outside_pinned/);
  assert.equal(hits,2);
});

test('read-only bootstrap check verifies partner SCIM and group plan once sharing verified',async()=>{
  const calls=[];
  const orgBase='https://localhost:9444/t/aurora.identity.test/o/api/server/v1/organizations';
  const rpc=async(method,url)=>{
    calls.push({method,url});
    if(url===`${orgBase}/self`) return {id:ROOT,type:'TENANT'};
    if(url.startsWith(`${orgBase}?`))return {organizations:[{id:ORG,name:'Verde Logistics',orgHandle:'verde-logistics'}]};
    if(url===`${orgBase}/${ORG}`)return {id:ORG,parent:{id:ROOT},name:'Verde Logistics',orgHandle:'verde-logistics',status:'ACTIVE'};
    throw Error('unexpected_root_request');
  };
  const ppc=async(method,url)=>{
    calls.push({method,url});
    if(url===urls.org)return {id:ORG,parent:{id:ROOT},status:'ACTIVE'};
    if(url.startsWith(`${urls.groups}?`))return {totalResults:0};
    if(url.startsWith(`${urls.users}?`))return {totalResults:0};
    throw Error('unexpected_partner_request');
  };
  const tokenProvider={
    root:async()=>({scope:ROOT_SCOPES.join(' '),access_token:'a'.repeat(40)}),
    partner:async()=>({scope:PARTNER_SCOPES.join(' '),access_token:'b'.repeat(40)})
  };
  const r=await reconcile({write:false,tokenProvider,rootClientFactory:()=>rpc,
    partnerClientFactory:()=>ppc,shareApplication:async()=>({state:'VERIFIED',remoteReadback:'VERIFIED'})});
  assert.equal(r.scimInventory,'VERIFIED');
  assert.equal(r.groupDecision,'CREATE_REQUIRES_APPROVAL');
  assert.deepEqual(r.counts,{users:0,groups:0});
  assert.equal(r.liveEvidence,'PENDING');
  assert.ok(calls.every(x=>x.method==='GET'));
});
