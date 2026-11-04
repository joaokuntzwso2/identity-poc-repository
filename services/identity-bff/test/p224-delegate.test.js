import test from 'node:test';
import assert from 'node:assert/strict';
import {reconcileDelegate,verifyRole,verifyUser,pinned,ROOT,PARTNER,GROUP,ROLE,USERNAME,PERMISSIONS} from '../../../scripts/p224-delegate-core.mjs';
import {delegateClient} from '../../../scripts/p224-delegate-transport.mjs';
const config={rootTenant:'aurora.identity.test',rootId:ROOT,orgId:PARTNER,allowedGroupId:GROUP};
const org='https://localhost:9444/t/aurora.identity.test/o';
const uid='c8f645a4-d06b-40cc-bb42-7577fb80df0e';
const rid='b3c32a52-d224-49ba-b15a-ff0049049156';
const ep=pinned(config);
const journal=()=>{let data=null;return {load:()=>structuredClone(data),save:x=>{data=structuredClone(x);}}};
const list=(arr)=>({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
  totalResults:arr.length,startIndex:1,itemsPerPage:arr.length,Resources:arr});
function fake(opts={}){
  const writes=[];
  let user=null,role=null;
  const group={id:GROUP,displayName:'PRIMARY/p2-partner-operations',members:[],roles:[]};
  if(opts.preexistingUser)user={id:uid,userName:USERNAME,active:true};
  if(opts.preexistingRole)role={id:rid,displayName:ROLE,
    audience:{type:'organization',value:PARTNER},permissions:PERMISSIONS.map(value=>({value})),users:[]};
  if(opts.foreignRoleAudience&&role)role.audience.value=ROOT;
  const client=async(method,url,body)=>{
    if(method!=='GET')writes.push({method,url,body});
    if(method==='GET'&&url===ep.org)return {id:PARTNER,parent:{id:ROOT},status:'ACTIVE'};
    if(method==='GET'&&url.startsWith(ep.groups+'?'))return list([group]);
    if(method==='GET'&&url.startsWith(ep.users+'?'))return list(user?[user]:[]);
    if(method==='GET'&&url.startsWith(ep.roles+'?'))return list(role?[role]:[]);
    if(method==='GET'&&url===ep.groups+'/'+GROUP)return structuredClone(group);
    if(method==='GET'&&url===ep.users+'/'+uid)return structuredClone(user);
    if(method==='GET'&&url===ep.roles+'/'+rid)return structuredClone(role);
    if(method==='POST'&&url===ep.roles){
      if(opts.failRolePost)throw Error('network_lost');
      role={...structuredClone(body),id:rid,users:[]};
      return {id:rid};
    }
    if(method==='POST'&&url===ep.users){
      assert.equal(body.userName,USERNAME);
      assert.ok(body.password.length>=32);
      if(opts.failUserPost){user={id:uid,userName:USERNAME,active:true};throw Error('network_lost');}
      user={id:uid,userName:USERNAME,active:true};return {id:uid};
    }
    if(method==='PATCH'&&url===ep.groups+'/'+GROUP){
      const op=body.Operations[0];
      if(op.op==='add')group.members.push({value:uid});
      return null;
    }
    if(method==='PATCH'&&url===ep.roles+'/'+rid){role.users.push({value:uid});return null;}
    throw Error(`unexpected mock request ${method} ${url}`);
  };
  return {client,writes,getRole:()=>role,getUser:()=>user,group};
}
test('read-only check does not create user, role, group membership, or journal',async()=>{
  const f=fake(),j=journal();
  const result=await reconcileDelegate({client:f.client,config,journal:j});
  assert.equal(result.mode,'CHECK');assert.equal(result.userTokenAcceptance,'NOT_EXECUTED');
  assert.equal(j.load(),null);assert.deepEqual(f.writes,[]);
});
test('automated role, user, group membership and direct role assignment have independent readback',async()=>{
  const f=fake(),j=journal();
  const result=await reconcileDelegate({client:f.client,config,journal:j,write:true,
    makePassword:()=>('P'.repeat(40))});
  assert.equal(result.userRoleAssignment,'WSO2_READBACK_VERIFIED');
  assert.equal(result.userTokenAcceptance,'NOT_EXECUTED');
  assert.equal(f.writes.filter(x=>x.method==='POST').length,2);
  assert.equal(f.writes.filter(x=>x.method==='PATCH').length,2);
  assert.equal(j.load().user.password,'P'.repeat(40));
  assert.equal(f.group.roles.length,0);
  const originalWrites=f.writes.length;
  const repeated=await reconcileDelegate({client:f.client,config,journal:j,write:true});
  assert.equal(repeated.userId,uid);assert.equal(repeated.roleId,rid);
  assert.equal(f.writes.length,originalWrites);
  const preflight=await reconcileDelegate({client:f.client,config,journal:j});
  assert.equal(preflight.roleAssignment,'VERIFIED');
  assert.equal(preflight.membership,'VERIFIED');
});
test('existing foreign user or role cannot be adopted without a matching journal',async()=>{
  for(const options of [{preexistingUser:true},{preexistingRole:true}]){
    const f=fake(options),j=journal();
    await assert.rejects(reconcileDelegate({client:f.client,config,journal:j,write:true}),
      /P224_UNOWNED_DELEGATE_RESOURCE_COLLISION/);
    assert.equal(f.writes.length,0);
  }
});
test('wrong role audience blocks before any write',async()=>{
  const f=fake({preexistingRole:true,foreignRoleAudience:true});
  await assert.rejects(reconcileDelegate({client:f.client,config,journal:journal(),write:true}),
    /P224_ROLE_AUDIENCE_NOT_PARTNER/);
  assert.equal(f.writes.length,0);
});
test('a failed user POST is never blindly retried on the same journal',async()=>{
  const f=fake({failUserPost:true}),j=journal();
  await assert.rejects(reconcileDelegate({client:f.client,config,journal:j,write:true}),/network_lost/);
  assert.equal(j.load().user.phase,'started');
  const priorPosts=f.writes.filter(x=>x.method==='POST'&&x.url===ep.users).length;
  // Readback recovers the existing exact-named user and proceeds safely.
  const recovered=await reconcileDelegate({client:f.client,config,journal:j,write:true});
  assert.equal(recovered.userId,uid);
  assert.equal(f.writes.filter(x=>x.method==='POST'&&x.url===ep.users).length,priorPosts);
});
test('uncertain role creation without remote resource blocks repeat POST',async()=>{
  const f=fake({failRolePost:true}),j=journal();
  await assert.rejects(reconcileDelegate({client:f.client,config,journal:j,write:true}),/network_lost/);
  await assert.rejects(reconcileDelegate({client:f.client,config,journal:j,write:true}),
    /P224_ROLE_WRITE_OUTCOME_UNCERTAIN_NO_RETRY/);
  assert.equal(f.writes.filter(x=>x.method==='POST'&&x.url===ep.roles).length,1);
});
test('foreign roles, broad permissions, and wrong group ID blocked',()=>{
  assert.throws(()=>pinned({...config,rootTenant:'brisa.identity.test'}),/TARGET_CONTEXT/);
  assert.throws(()=>pinned({...config,allowedGroupId:ROOT}),/TARGET_CONTEXT/);
  assert.throws(()=>verifyRole({id:rid,displayName:ROLE,
    audience:{type:'organization',value:PARTNER},permissions:[{value:'admin'}]}),/PERMISSIONS_NOT_EXACT/);
  assert.throws(()=>verifyUser({id:uid,userName:'attacker',active:true}),/NAME_OR_STATE/);
});
test('transport rejects Brisa, root paths, foreign role IDs and unsafe methods before network',async()=>{
  let hits=0;
  const client=delegateClient({config,token:'t'.repeat(40),request:async()=>{
    hits++;return {ok:true,status:200,text:async()=>'{"totalResults":0}'};
  }});
  const bad=[['GET',`https://localhost:9444/t/brisa.identity.test/o/scim2/Users`],
    ['GET',`https://localhost:9444/t/aurora.identity.test/scim2/Users`],
    ['POST',`${ep.org}`],['DELETE',`${ep.users}/${uid}`],
    ['PATCH',`${ep.users}/${uid}`],['GET',`${ep.roles}?foo=bar`],
    ['GET',`https://evil.test/t/aurora.identity.test/o/scim2/v2/Roles`]];
  for(const [m,url] of bad)await assert.rejects(client(m,url),/DENIED|ORIGIN|QUERY/);
  assert.equal(hits,0);
  await client('GET',`${ep.roles}?startIndex=1&count=100`);
  assert.equal(hits,1);
});
