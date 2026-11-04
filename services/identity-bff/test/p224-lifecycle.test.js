import test from 'node:test';
import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import http from 'node:http';
const scripts=resolve(dirname(fileURLToPath(import.meta.url)),'../../../scripts');
const c=await import('file://'+scripts+'/p224-lifecycle-core.mjs');
const s=await import('file://'+scripts+'/p224-lifecycle-service.mjs');
const m=await import('file://'+scripts+'/p224-delegated-write-core.mjs');
const myUser='c16b076f-74a3-43cc-a79e-8650c6b0c061';
const groupId='f75f73e5-8d10-42a2-9b2c-1d23af7ddfef';
const j={...c.plan(),userId:myUser,groupId,groupPhase:'verified',phase:'active',membershipPhase:'none'};
const doc={id:myUser,userName:'PRIMARY/'+j.username,active:true,emails:[{value:j.email}],roles:[],groups:[]};
const group={id:groupId,displayName:'PRIMARY/'+j.businessGroupName,members:[]};
test('dedicated actor, partner and parent stay pinned',()=>{
 assert.equal(c.validateContext({id:c.PARTNER,parent:{id:c.ROOT},status:'ACTIVE'}),true);
 for(const bad of [{id:c.ROOT,parent:{id:c.ROOT},status:'ACTIVE'},
   {id:c.PARTNER,parent:{id:c.PARTNER},status:'ACTIVE'},
   {id:c.PARTNER,parent:{id:c.ROOT},status:'DISABLED'}])assert.throws(()=>c.validateContext(bad));
});
test('only one ordinary non-admin member is ever accepted',()=>{
 assert.equal(c.validateMember(doc,j),true);
 for(const bad of [{id:c.USER},{active:false},{roles:[{value:c.ROLE}]},
   {groups:[{value:c.ADMIN_GROUP}]},{emails:[]},{userName:'PRIMARY/intruder'}])
   assert.throws(()=>c.validateMember({...doc,...bad},j));
 assert.equal(c.validateMember({...doc,active:false},{...j,phase:'disabled'},{disabled:true}),true);
});
test('business group distinct from privileged admin group, no foreign memberships',()=>{
 assert.equal(c.validateBusinessGroup(group,j),false);
 assert.equal(c.validateBusinessGroup({...group,members:[{value:j.userId}]},j),true);
 for(const bad of [{id:c.ADMIN_GROUP},{displayName:'PRIMARY/p2-partner-operations'},
   {members:[{value:c.USER}]},{members:[{value:j.userId},{value:j.userId}]},
   {members:'invalid'}])assert.throws(()=>c.validateBusinessGroup({...group,...bad},j));
});
test('readback-bound payloads have no role or admin-group assignment',()=>{
 const u=c.memberCreateBody(j);
 assert.equal(u.active,true);assert.equal(u.userName,j.username);
 assert.equal(u.roles,undefined);assert.equal(u.groups,undefined);
 assert.deepEqual(c.businessGroupCreateBody(j),{
   schemas:[c.GROUP_SCHEMA],displayName:j.businessGroupName,members:[]});
 assert.equal(c.memberAddBody(j,doc).Operations[0].value.members[0].value,j.userId);
 assert.equal(c.memberAddBody(j,doc).Operations[0].value.members[0].display,doc.userName);
 assert.throws(()=>c.memberAddBody(j),/P224L_MEMBER_ID_MISMATCH/);
 assert.match(c.memberRemoveBody(j).Operations[0].path,/^members\[value eq [0-9a-f-]+\]$/);
 assert.equal(c.deactivateBody(j).Operations[0].path,'active');
 assert.equal(c.deactivateBody(j).Operations[0].value,false);
});
test('journal shape rejects wrong tenant, unknown phases, admin takeover',()=>{
 assert.equal(c.assertJournal(j),true);
 for(const delta of [{partnerId:c.ROOT},{phase:'success'},{userId:c.USER},
   {groupId:c.ADMIN_GROUP},{businessGroupName:'p2-partner-operations'},
   {evidence:[{event:'FALSE_SUCCESS',source:'SYNTHETIC',at:new Date().toISOString()}]}])
   assert.throws(()=>c.assertJournal({...j,...delta}));
 const proof=c.addProof({...j,evidence:[]},'BUSINESS_MEMBERSHIP_REMOVED');
 assert.equal(proof.evidence[0].source,'WSO2_SCIM_READBACK');
 assert.equal(c.safeStatus(proof).tokenRevocationAfterDeactivation,'NOT_TESTED');
});
test('HTTP boundary excludes root, Brisa, unauthorized methods and unrelated users',()=>{
 const g='https://localhost:9444/t/aurora.identity.test/o/scim2/Groups';
 assert.equal(s.allowedRemote('GET',g,null),g);
 assert.equal(s.allowedRemote('PATCH',g+'/'+groupId,groupId),g+'/'+groupId);
 for(const [method,url,id] of [['PATCH',g+'/'+c.ADMIN_GROUP,groupId],
  ['POST',g+'/'+groupId,groupId],['DELETE',g+'/'+groupId,groupId],
  ['POST','https://localhost:9444/t/brisa.identity.test/o/scim2/Users',null],
  ['PATCH','https://localhost:9444/t/aurora.identity.test/scim2/Users/'+myUser,myUser],
  ['GET',g+'?unexpected=1',null]])assert.throws(()=>s.allowedRemote(method,url,id));
});
test('owner-only requester is exact-path and blocks wrong methods before network',async()=>{
 let count=0;
 const req=s.ownerRequest('safe-test-bearer-abcdefghijklmn',groupId,async()=>{
   count++;return {status:200,text:async()=>JSON.stringify(group)};
 });
 assert.deepEqual(await req('GET','https://localhost:9444/t/aurora.identity.test/o/scim2/Groups/'+groupId),group);
 await assert.rejects(req('PATCH','https://localhost:9444/t/aurora.identity.test/o/scim2/Groups/'+c.ADMIN_GROUP,
    c.memberAddBody(j,doc)));
 assert.equal(count,1);
});
const request=(port,path,method='GET',headers={},data)=>new Promise((resolve,reject)=>{
 const req=http.request({hostname:'127.0.0.1',port,path,method,headers:{Host:'127.0.0.1:4472',...headers}},res=>{
  let text='';res.on('data',x=>text+=x);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,
    json:()=>JSON.parse(text)}));});req.on('error',reject);if(data!==undefined)req.write(JSON.stringify(data));req.end();
});
test('local portal requires PIN, cookie, CSRF, same origin and exact confirm phrase',async t=>{
 const code='this-is-a-test-only-code-4321';let calls=[];
 const server=s.createPortal({pin:code,page:'<html>TEST</html>',js:'/*TEST*/',css:'body{}',
   executeAction:async action=>{calls.push(action);return {state:'LIVE_MOCK_ONLY_FOR_OFFLINE_TEST'};}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 t.after(()=>new Promise(r=>server.close(r)));
 const port=server.address().port;
 const json={'Content-Type':'application/json',Origin:'http://127.0.0.1:4472'};
 assert.equal((await request(port,'/api/state')).status,401);
 assert.equal((await request(port,'/api/login','POST',{...json,Origin:'https://attacker.example'},
    {code})).status,403);
 const wrong=await request(port,'/api/login','POST',json,{code:'wrong'});
 assert.equal(wrong.status,403);
 const login=await request(port,'/api/login','POST',json,{code});
 assert.equal(login.status,200);
 const cookie=login.headers['set-cookie'][0].split(';')[0];
 assert.match(login.headers['set-cookie'][0],/HttpOnly; SameSite=Strict/);
 const csrf=login.json().csrf;
 assert.equal((await request(port,'/api/action','POST',{...json,Cookie:cookie},
   {action:'create',confirm:'VERDE'})).status,403);
 assert.equal((await request(port,'/api/action','POST',{...json,Cookie:cookie,'X-CSRF-Token':csrf},
   {action:'deactivate',confirm:'VERDE'})).status,403);
 assert.equal((await request(port,'/api/action','POST',{...json,Cookie:cookie,'X-CSRF-Token':csrf},
   {action:'create',confirm:'VERDE'})).status,200);
 assert.equal((await request(port,'/api/state','GET',{Cookie:cookie})).status,200);
 assert.deepEqual(calls,['create','status']);
});
