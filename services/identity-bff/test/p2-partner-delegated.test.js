import test from 'node:test';
import assert from 'node:assert/strict';
import {endpoints,inspectPartner,planGroup,createGroup,planMembership,changeMembership} from '../../../scripts/p2-partner-core.mjs';

const ROOT='11111111-1111-4111-8111-111111111111';
const ORG='22222222-2222-4222-8222-222222222222';
const GROUP='33333333-3333-4333-8333-333333333333';
const USER='44444444-4444-4444-8444-444444444444';
const config={rootTenant:'aurora.identity.test',rootId:ROOT,orgId:ORG,allowedGroupId:GROUP};
const urls=endpoints(config);
function fixture(opts={}) {
  let group={id:GROUP,displayName:'PRIMARY/p2-partner-operations',members:[],roles:[]};
  let self={id:ORG,parent:{id:ROOT},status:'ACTIVE'};
  let user={id:USER,userName:'PRIMARY/partner.user',active:true};
  const calls=[];
  const client=async (method,url,body)=>{
    calls.push({method,url,body});
    if (method==='GET' && url===urls.org)return {...self};
    if (method==='GET' && url===urls.users+'/'+USER)return {...user};
    if (method==='GET' && url===urls.groups+'/'+GROUP)return structuredClone(group);
    if (method==='GET' && url===urls.users+'?startIndex=1&count=100')return {Resources:[user],totalResults:1};
    if (method==='GET' && url===urls.groups+'?startIndex=1&count=100')return {Resources:opts.noGroup?[]:[group],totalResults:opts.noGroup?0:1};
    if (method==='POST' && url===urls.groups) {
      group={id:GROUP,displayName:'PRIMARY/'+body.displayName,members:[],roles:[]};
      return structuredClone(group);
    }
    if (method==='PATCH' && url===urls.groups+'/'+GROUP) {
      const change=body.Operations[0];
      if(change.op==='add')group.members.push({value:USER});
      if(change.op==='remove')group.members=group.members.filter(m=>m.value!==USER);
      return structuredClone(group);
    }
    throw Error('unexpected_test_call:'+method+':'+url);
  };
  return {client,calls,setOrg:x=>{self=x;},setGroup:x=>{group=x;},setUser:x=>{user=x;},getGroup:()=>group};
}
test('tenant and root identity are pinned to Aurora or Brisa, not Carbon Super',()=>{
  assert.throws(()=>endpoints({...config,rootTenant:'carbon.super'}),/root_tenant_not_allowlisted/);
  assert.throws(()=>endpoints({...config,rootTenant:'brisa.identity.test',orgId:ROOT}),/partner_cannot_be_root/);
  assert.throws(()=>endpoints({...config,base:'http://localhost:9444'}),/only_existing_local_https/);
  assert.throws(()=>endpoints({...config,base:'https://evil.example'}),/only_existing_local_https/);
});
test('inspect reads only current partner context and returns counts, not users',async()=>{
  const f=fixture();const r=await inspectPartner({client:f.client,config});
  assert.equal(r.source,'WSO2_SCIM2_LIVE_READ');assert.equal(r.userCount,1);
  assert.equal(JSON.stringify(r).includes('partner.user'),false);
  assert.ok(f.calls.every(x=>x.method==='GET'));
});
test('root token or foreign partner token cannot access delegated operations',async()=>{
  for(const wrong of [
    {id:ROOT,status:'ACTIVE'},
    {id:ORG,parent:{id:'55555555-5555-4555-8555-555555555555'},status:'ACTIVE'},
    {id:ORG,parent:{id:ROOT},status:'DISABLED'},
    {id:'66666666-6666-4666-8666-666666666666',parent:{id:ROOT},status:'ACTIVE'}]) {
    const f=fixture();f.setOrg(wrong);
    await assert.rejects(inspectPartner({client:f.client,config}),/token_organization_context_or_status_mismatch/);
    assert.equal(f.calls.filter(c=>c.url.includes('scim2')).length,0);
  }
});
test('group create requires approval and validates its actual readback',async()=>{
  const f=fixture({noGroup:true}); const p=await planGroup({client:f.client,config,name:'p2-partner-operations'});
  assert.equal(p.decision,'CREATE_REQUIRES_APPROVAL');assert.equal(f.calls.some(x=>x.method!=='GET'),false);
  await assert.rejects(createGroup({client:f.client,config,name:'p2-partner-operations',approval:'wrong'}),/fingerprint/);
  assert.equal(f.calls.some(x=>x.method==='POST'),false);
  const r=await createGroup({client:f.client,config,name:'p2-partner-operations',approval:p.approval});
  assert.equal(r.action,'CREATED');assert.equal(r.verified,true);
  assert.equal(f.getGroup().members.length,0);
});
test('cannot create privileged or arbitrary-named groups',async()=>{
  const f=fixture();
  for(const name of ['admin','PRIMARY/admin','b2b-admin','p2-partner-admin!', 'p2-partner-a'])
    await assert.rejects(planGroup({client:f.client,config,name}),/group_name_not_allowlisted/);
});
test('membership grants need explicit approvals and strong readback',async()=>{
  const f=fixture(); const p=await planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD'});
  assert.equal(p.decision,'REQUIRES_APPROVAL');
  await assert.rejects(changeMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD',approval:'not-approved'}),/fingerprint/);
  assert.equal(f.getGroup().members.length,0);
  const r=await changeMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD',approval:p.approval});
  assert.equal(r.action,'MEMBER_ADDED');assert.equal(r.verified,true);
  assert.equal(f.getGroup().members.length,1);
  const rp=await planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD'});
  assert.equal(rp.decision,'ALREADY_DESIRED');
  const n=await changeMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD',approval:rp.approval});
  assert.equal(n.action,'NOOP');assert.equal(f.calls.filter(x=>x.method==='PATCH').length,1);
});
test('group removal requires separate approval and verifies membership disappeared',async()=>{
  const f=fixture();f.setGroup({id:GROUP,displayName:'PRIMARY/p2-partner-operations',roles:[],members:[{value:USER}]});
  const p=await planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'REMOVE'});
  const r=await changeMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'REMOVE',approval:p.approval});
  assert.equal(r.action,'MEMBER_REMOVED');
  assert.deepEqual(f.getGroup().members,[]);
  assert.equal(f.calls.find(x=>x.method==='PATCH').body.Operations[0].path,`members[value eq ${USER}]`);
});
test('stale approval blocks concurrent membership changes without writes',async()=>{
  const f=fixture();const p=await planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD'});
  f.setGroup({id:GROUP,displayName:'PRIMARY/p2-partner-operations',roles:[],members:[{value:'77777777-7777-4777-8777-777777777777'}]});
  await assert.rejects(changeMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD',approval:p.approval}),/fingerprint/);
  assert.equal(f.calls.filter(x=>x.method==='PATCH').length,0);
});
test('cross-partner group ID cannot be used, even if token can read it',async()=>{
  const f=fixture();
  await assert.rejects(planMembership({client:f.client,config,groupId:'88888888-8888-4888-8888-888888888888',userId:USER,op:'ADD'}),/group_id_not_in_operator_allowlist/);
  assert.equal(f.calls.length,0);
});
test('privileged groups and inactive users fail closed',async()=>{
  const f=fixture();f.setGroup({id:GROUP,displayName:'PRIMARY/p2-partner-operations',members:[],roles:[{display:'Administrator'}]});
  await assert.rejects(planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD'}),/group_has_role_assignments_prohibited/);
  f.setGroup({id:GROUP,displayName:'PRIMARY/p2-partner-operations',members:[],roles:[]});
  f.setUser({id:USER,userName:'user',active:false});
  await assert.rejects(planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD'}),/user_missing_inactive/);
});
test('readback mismatch is a failure, never success',async()=>{
  const f=fixture(); const p=await planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD'});
  const client=async (method,url,body)=> {
    if(method==='PATCH')return {}; // API claims success but no actual mutation
    return f.client(method,url,body);
  };
  await assert.rejects(changeMembership({client,config,groupId:GROUP,userId:USER,op:'ADD',approval:p.approval}),/membership_write_not_verified/);
});
test('no mutation when organization scope readback or group inventory is incomplete',async()=>{
  const f=fixture({noGroup:true});
  const client=async (method,url,body)=>{
    if(url===urls.groups+'?startIndex=1&count=100')return {Resources:[],totalResults:101};
    return f.client(method,url,body);
  };
  await assert.rejects(planGroup({client,config,name:'p2-partner-operations'}),/scim_inventory_not_complete/);
  assert.equal(f.calls.some(x=>x.method!=='GET'),false);
});

test('HTTP transport blocks external, cross-tenant and unauthorized methods before fetch',async()=>{
  const {createPartnerClient}=await import('../../../scripts/p2-partner-transport.mjs');
  let hits=0;
  const request=async (_url,init)=>{hits++;return {ok:true,status:200,text:async()=>JSON.stringify({good:true})};};
  const c=createPartnerClient({config,token:'a'.repeat(40),request});
  for(const [method,url] of [
    ['GET','https://evil.example/o/scim2/Users'],
    ['GET','https://localhost:9444/t/brisa.identity.test/o/scim2/Users'],
    ['PATCH',urls.users+'/'+USER],
    ['DELETE',urls.groups+'/'+GROUP],
    ['POST',urls.users],
    ['GET',urls.groups+'?count=1000'],
    ['GET',urls.groups+'/'+GROUP+'/members']
  ]) await assert.rejects(c(method,url),/request_outside|unapproved_scim_query/);
  assert.equal(hits,0);
  const okay=await c('GET',urls.org);
  assert.equal(okay.good,true);assert.equal(hits,1);
});
test('HTTP transport refuses redirects and surfaces sanitized status only',async()=>{
  const {createPartnerClient}=await import('../../../scripts/p2-partner-transport.mjs');
  const c=createPartnerClient({config,token:'a'.repeat(40),request:async()=>({ok:false,status:302})});
  await assert.rejects(c('GET',urls.org),/wso2_http_302_do_not_retry/);
});
test('SCIM may omit empty members attribute on new groups',async()=>{
  const f=fixture({noGroup:true});
  const p=await planGroup({client:f.client,config,name:'p2-partner-operations'});
  const client=async(method,url,body)=>{
    const r=await f.client(method,url,body);
    if(method==='GET' && url===urls.groups+'/'+GROUP)delete r.members;
    return r;
  };
  const a=await createGroup({client,config,name:'p2-partner-operations',approval:p.approval});
  assert.equal(a.verified,true);
});
test('group changed between approval replan and PATCH is rejected',async()=>{
  const f=fixture();
  const p=await planMembership({client:f.client,config,groupId:GROUP,userId:USER,op:'ADD'});
  let groupReads=0;
  const client=async(method,url,body)=>{
    if(method==='GET'&&url===urls.groups+'/'+GROUP) {
      groupReads++;
      if(groupReads===2)f.setGroup({id:GROUP,displayName:'PRIMARY/p2-partner-operations',roles:[],members:[{value:'77777777-7777-4777-8777-777777777777'}]});
    }
    return f.client(method,url,body);
  };
  await assert.rejects(changeMembership({client,config,groupId:GROUP,userId:USER,op:'ADD',approval:p.approval}),/group_changed_before_write/);
  assert.equal(f.calls.filter(x=>x.method==='PATCH').length,0);
});
