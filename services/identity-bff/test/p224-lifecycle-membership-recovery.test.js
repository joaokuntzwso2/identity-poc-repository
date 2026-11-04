import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const REPO=resolve(dirname(fileURLToPath(import.meta.url)),'../../..');
const core=await import('file://'+REPO+'/scripts/p224-lifecycle-core.mjs');
const service=await import('file://'+REPO+'/scripts/p224-lifecycle-service.mjs');
const id='521ee475-9735-48b6-9caa-9619b62f81e3';
const groupID='186af26d-1221-416c-b311-82ceb129de4f';
const old={...core.plan(),phase:'active',groupPhase:'verified',membershipPhase:'add-started',
  userId:id,groupId:groupID};
core.addProof(old,'LIFECYCLE_USER_CREATED');
core.addProof(old,'BUSINESS_GROUP_CREATED');
const member={id,userName:'PRIMARY/'+old.username,active:true,
  emails:[{value:old.email}],groups:[],roles:[]};
const group={id:groupID,displayName:'PRIMARY/'+old.businessGroupName,members:[]};

test('WSO2 group member add PATCH uses WSO2-read-back display and immutable ID',()=>{
  const op=core.memberAddBody(old,member).Operations[0];
  assert.deepEqual(op,{op:'add',value:{members:[{display:member.userName,value:id}]}});
  assert.equal('path' in op,false);
  assert.throws(()=>core.memberAddBody(old),/P224L_MEMBER_ID_MISMATCH/);
  assert.throws(()=>core.memberAddBody(old,{...member,id:core.USER}),/P224L_MEMBER_ID_MISMATCH/);
  assert.throws(()=>core.memberAddBody(old,{...member,userName:'OTHER/attacker'}),/P224L_MEMBER_ID_MISMATCH/);
  assert.throws(()=>core.memberAddBody(old,{...member,roles:[{value:core.ROLE}]}),/P224L_MEMBER_HAS_ADMIN_ROLE/);
  assert.throws(()=>core.memberAddBody(old,{...member,groups:[{value:core.ADMIN_GROUP}]}),/P224L_MEMBER_HAS_ADMIN_GROUP/);
});

test('failed add with no live membership permits only a local prepared replan',()=>{
  const next=core.planFailedMembershipRecovery(old,group,member);
  assert.equal(core.assertJournal(next),true);
  assert.equal(next.membershipPhase,'none');
  assert.equal(next.userId,id);
  assert.equal(next.groupId,groupID);
  assert.equal(next.businessGroupName,old.businessGroupName);
  assert.equal(next.evidence.at(-1).event,'MEMBERSHIP_ADD_REPLANNED');
  assert.equal(next.evidence.at(-1).source,'LOCAL_PREPARED');
  assert.equal(next.evidence.some(e=>e.event==='BUSINESS_MEMBERSHIP_ADDED'),false);
  assert.throws(()=>core.planFailedMembershipRecovery(next,group,member),/P224L_MEMBERSHIP_RECOVERY_JOURNAL_DENIED/);
  assert.throws(()=>core.planFailedMembershipRecovery({...old,membershipPhase:'added'},group,member));
});

test('recovery refuses live membership, contradictions, privileged and foreign group',()=>{
  const bads=[
    [old,{...group,members:[{value:id}]},member],
    [old,{...group,members:[{value:core.USER}]},member],
    [old,{...group,id:core.ADMIN_GROUP},member],
    [old,group,{...member,groups:[{value:groupID}]}],
    [old,group,{...member,active:false}],
    [old,group,{...member,id:core.USER}],
    [old,group,{...member,roles:[{value:core.ROLE}]}],
    [{...old,partnerId:core.ROOT},group,member],
    [{...old,evidence:[...old.evidence,{event:'MEMBERSHIP_ADD_REPLANNED',source:'LOCAL_PREPARED',at:new Date().toISOString()}]},group,member],
    [{...old,evidence:[]},group,member]
  ];
  for(const [j,g,m] of bads)assert.throws(()=>core.planFailedMembershipRecovery(j,g,m));
});

test('group PATCH may target only the journal-owned Verde group and no other tenant',()=>{
  const api='https://localhost:9444/t/aurora.identity.test/o/scim2/Groups/'+groupID;
  assert.equal(service.allowedRemote('PATCH',api,groupID),api);
  const bad=[api.replace('aurora.identity.test','brisa.identity.test'),
    api.replace(groupID,core.ADMIN_GROUP),
    api.replace('https://localhost:9444','https://foreign.example'),
    api.replace('/o/scim2/','/scim2/')];
  for(const url of bad)assert.throws(()=>service.allowedRemote('PATCH',url,groupID));
});

test('launcher and runtime admit only view-only recovery check and explicitly approved journal replan',()=>{
  const serviceSource=readFileSync(REPO+'/scripts/p224-lifecycle-service.mjs','utf8');
  const shell=readFileSync(REPO+'/scripts/p224-lifecycle.sh','utf8');
  assert.match(shell,/recover-membership-check/);
  assert.match(shell,/recover-membership/);
  assert.match(serviceSource,/P224L_APPROVE_MEMBERSHIP_REPLAN==='HTTP_400_CONFIRMED'/);
  assert.match(serviceSource,/planFailedMembershipRecovery\(j,group,member\)/);
  assert.match(serviceSource,/MEMBERSHIP_REPLANNED_NO_REMOTE_PATCH/);
  assert.match(serviceSource,/P224L_REMOVE_NO_MEMBERSHIP_TO_REVOKE/);
  assert.match(serviceSource,/j\.membershipPhase==='removed'/);
  assert.match(serviceSource,/BUSINESS_MEMBERSHIP_ADDED'&&e\.source==='WSO2_SCIM_READBACK'/);
  assert.match(serviceSource,/BUSINESS_MEMBERSHIP_REMOVED'&&e\.source==='WSO2_SCIM_READBACK'/);
});
