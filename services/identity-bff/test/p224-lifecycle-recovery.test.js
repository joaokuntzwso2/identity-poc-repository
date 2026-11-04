import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
const scripts=resolve(dirname(fileURLToPath(import.meta.url)),'../../../scripts');
const c=await import('file://'+scripts+'/p224-lifecycle-core.mjs');
const userId='c16b076f-74a3-43cc-a79e-8650c6b0c061';
const oldName='p2-verde-business-members-123456abcdef';
const newName='p2-verde-biz-123456abcdef';
const j={...c.plan(),userId,phase:'active',groupPhase:'create-started',
  businessGroupName:oldName,groupId:undefined,membershipPhase:'none'};
const remoteGroup={id:'bd57a261-f6a3-4533-9dfb-cfe997b51211',displayName:'PRIMARY/another-group'};

test('new business-group names fit documented default WSO2 user-store role policy',()=>{
 const next=c.plan();assert.match(next.businessGroupName,/^p2-verde-biz-[a-f0-9]{12}$/);
 assert.ok(next.businessGroupName.length<=30);
 assert.equal(c.assertJournal(next),true);
 assert.ok(c.businessGroupCreateBody(next).displayName.length<=30);
});
test('legacy 38-character name can be inspected without assuming successful creation',()=>{
 assert.equal(c.assertJournal(j),true);
 assert.equal(oldName.length,38);
 const after=c.planLegacyGroupRecovery(j,[remoteGroup]);
 assert.equal(after.businessGroupName,newName);
 assert.equal(after.groupPhase,'none');
 assert.equal(after.groupId,undefined);
 assert.equal(after.membershipPhase,'none');
 assert.equal(after.userId,userId);
 assert.equal(after.evidence.at(-1).event,'GROUP_NAME_REPLANNED');
 assert.equal(after.evidence.at(-1).source,'LOCAL_PREPARED');
 assert.equal(c.assertJournal(after),true);
 assert.equal(c.assertJournal(j),true);
 assert.equal(j.groupPhase,'create-started');
});
test('cannot replan if either old or replacement name exists in WSO2',()=>{
 for(const name of [oldName,newName]){
  assert.throws(()=>c.planLegacyGroupRecovery(j,[{
   ...remoteGroup,displayName:'PRIMARY/'+name
  }]),/P224L_RECOVERY_GROUP_EXISTS_NO_REPLAN/);
 }
});
test('cannot replan when old write may have succeeded or membership has started',()=>{
 for(const change of [
  {groupPhase:'verified'}, {groupId:remoteGroup.id}, {membershipPhase:'add-started'},
  {phase:'disabled'},{phase:'deactivate-started'},{businessGroupName:newName},
  {businessGroupName:'p2-partner-operations'}, {partnerId:c.ROOT}
 ]) assert.throws(()=>c.planLegacyGroupRecovery({...j,...change},[]));
});
test('incomplete, duplicate or malformed inventory prevents replan',()=>{
 for(const groups of [null,{},[{}],[remoteGroup,remoteGroup],
  [{...remoteGroup,id:'not-a-uuid'}],
  [{...remoteGroup,displayName:null}]]) assert.throws(()=>c.planLegacyGroupRecovery(j,groups));
});
test('source has explicit approval and distinct read-only recovery path',()=>{
 const service=readFileSync(resolve(scripts,'p224-lifecycle-service.mjs'),'utf8');
 const sh=readFileSync(resolve(scripts,'p224-lifecycle.sh'),'utf8');
 assert.match(service,/P224L_APPROVE_GROUP_REPLAN==='YES'/);
 assert.match(service,/action==='recover-group-check'/);
 assert.match(service,/journal\.save\(next\)/);
 assert.match(service,/await allGroups\(ownerRequest\(token,null\)\)/);
 assert.match(service,/await owner\(\['internal_org_organization_view','internal_org_group_mgt_view'\]\)/);
 assert.match(service,/await readBoundMember\(j,user\)/);
 assert.match(sh,/recover-group-check/);
 assert.match(sh,/recover-group/);
});
