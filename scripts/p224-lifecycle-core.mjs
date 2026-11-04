/** P2.24 + P2.29: one ordinary, journal-owned Verde account and one business group.
 * No browser-provided target identifiers or WSO2 credentials. */
import {randomBytes} from 'node:crypto';
import {lstatSync,openSync,closeSync,readFileSync,writeFileSync,renameSync,unlinkSync,fsyncSync,constants} from 'node:fs';
import {join} from 'node:path';
import {PARTNER,ROOT,USER,ROLE,uuid,newPlan,safeUser,userPayload,exactUserName} from './p224-delegated-write-core.mjs';
export {PARTNER,ROOT,USER,ROLE};
export const BUSINESS_GROUP='p2-verde-biz';
const LEGACY_BUSINESS_GROUP='p2-verde-business-members';
const legacyBusinessName=/^p2-verde-business-members-([a-f0-9]{12})$/;
const shortBusinessName=/^p2-verde-biz-[a-f0-9]{12}$/;
const validBusinessName=name=>shortBusinessName.test(name)||legacyBusinessName.test(name);
export const ADMIN_GROUP='f43022fa-cb55-4b19-bb6c-23bba8f2d322';
export const PATCH='urn:ietf:params:scim:api:messages:2.0:PatchOp';
export const GROUP_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:Group';
export const USER_SCHEMA='urn:ietf:params:scim:schemas:core:2.0:User';
export const PHASES=['prepared','create-started','active','deactivate-started','disabled'];
const must=(valid,code)=>{if(!valid)throw Error(code);};
const unprefix=x=>typeof x==='string' && x.startsWith('PRIMARY/')?x.slice(8):x;
export function validateContext(org){
  must(org?.id===PARTNER && org?.parent?.id===ROOT && org?.status==='ACTIVE', 'P224L_WRONG_ORGANIZATION');
  return true;
}
export function validateMember(doc,j,{disabled=false}={}){
  must(j && uuid.test(j.userId) && j.userId!==USER, 'P224L_MEMBER_NOT_JOURNALED');
  must(doc?.id===j.userId && exactUserName(doc.userName,j.username), 'P224L_MEMBER_ID_MISMATCH');
  must(Array.isArray(doc?.emails)&&doc.emails.some(x=>(typeof x==='string'?x:x?.value)===j.email),
    'P224L_MEMBER_EMAIL_MISMATCH');
  must(doc.active===(disabled?false:true), 'P224L_MEMBER_ACTIVE_READBACK_MISMATCH');
  must(!Array.isArray(doc.roles)||!doc.roles.some(x=>x.value===ROLE), 'P224L_MEMBER_HAS_ADMIN_ROLE');
  must(!Array.isArray(doc.groups)||!doc.groups.some(x=>x.value===ADMIN_GROUP),
    'P224L_MEMBER_HAS_ADMIN_GROUP');
  return true;
}
export function validateBusinessGroup(g,j){
  must(uuid.test(j?.groupId) && j.groupId!==ADMIN_GROUP && g?.id===j.groupId,
    'P224L_GROUP_ID_MISMATCH');
  must(unprefix(g.displayName)===j.businessGroupName, 'P224L_GROUP_NAME_MISMATCH');
  must(g.members===undefined || Array.isArray(g.members), 'P224L_GROUP_MEMBERS_SHAPE');
  const members=g.members??[];
  must(members.every(x=>uuid.test(x?.value)), 'P224L_GROUP_MEMBER_ID_INVALID');
  must(new Set(members.map(x=>x.value.toLowerCase())).size===members.length,
    'P224L_GROUP_DUPLICATE_MEMBERS');
  must(members.every(x=>x.value===j.userId), 'P224L_GROUP_FOREIGN_MEMBER_DENIED');
  return members.some(x=>x.value===j.userId);
}
export function assertJournal(j){
  must(j?.schema==='identity.wso2.p224.lifecycle.v1' && j.partnerId===PARTNER &&
    validBusinessName(j.businessGroupName) &&
    PHASES.includes(j.phase) && ['none','create-started','verified'].includes(j.groupPhase) &&
    ['none','add-started','added','remove-started','removed'].includes(j.membershipPhase),
    'P224L_JOURNAL_CONTEXT_INVALID');
  userPayload(j);
  must(!j.userId || (uuid.test(j.userId) && j.userId!==USER), 'P224L_JOURNAL_USER_ID_INVALID');
  must(!j.groupId || (uuid.test(j.groupId) && j.groupId!==ADMIN_GROUP),
    'P224L_JOURNAL_GROUP_ID_INVALID');
  must(Array.isArray(j.evidence) && j.evidence.length<=40 && j.evidence.every(e=>
    e && typeof e.event==='string' && /^[A-Z_]{4,50}$/.test(e.event) &&
    typeof e.at==='string' && Number.isFinite(Date.parse(e.at)) &&
    ['WSO2_SCIM_READBACK','LOCAL_PREPARED'].includes(e.source)), 'P224L_EVIDENCE_INVALID');
  return true;
}
export function plan(){
  const item=newPlan();
  return {schema:'identity.wso2.p224.lifecycle.v1',partnerId:PARTNER,
    ...item,businessGroupName:BUSINESS_GROUP+'-'+randomBytes(6).toString('hex'),
    phase:'prepared',groupPhase:'none',membershipPhase:'none',evidence:[]};
}
export function addProof(j,event){
  must(j.evidence.length<40,'P224L_EVIDENCE_FULL');
  j.evidence.push({event,at:new Date().toISOString(),source:'WSO2_SCIM_READBACK'});
  return j;
}
/** Only a journaled legacy group POST that returned a terminal HTTP 400 may be
 * intentionally re-planned. Network inventory is obtained separately under the
 * owner token; this pure function verifies both exact names are unused. */
export function planLegacyGroupRecovery(j,groups){
  assertJournal(j);
  must(j.phase==='active'&&uuid.test(j.userId) &&
    j.groupPhase==='create-started' && j.groupId==null &&
    j.membershipPhase==='none', 'P224L_RECOVERY_JOURNAL_PHASE_DENIED');
  const match=legacyBusinessName.exec(j.businessGroupName);
  must(match!==null && j.businessGroupName.length===38,
    'P224L_RECOVERY_NOT_LEGACY_LONG_NAME');
  must(Array.isArray(groups)&&groups.length<=100 &&
    groups.every(g=>uuid.test(g?.id) && typeof g.displayName==='string') &&
    new Set(groups.map(g=>g.id)).size===groups.length,
    'P224L_RECOVERY_INVENTORY_UNVERIFIED');
  const replacement=BUSINESS_GROUP+'-'+match[1];
  const names=new Set([j.businessGroupName,replacement]);
  must(!groups.some(g=>names.has(unprefix(g.displayName))),
    'P224L_RECOVERY_GROUP_EXISTS_NO_REPLAN');
  const updated={...j,businessGroupName:replacement,groupPhase:'none',
    evidence:[...j.evidence,{event:'GROUP_NAME_REPLANNED',at:new Date().toISOString(),
      source:'LOCAL_PREPARED'}]};
  assertJournal(updated);
  return updated;
}
export function memberCreateBody(j){return userPayload(j);}
export function businessGroupCreateBody(j){
  must(validBusinessName(j?.businessGroupName),
    'P224L_GROUP_NAME_INVALID');
  return {schemas:[GROUP_SCHEMA],displayName:j.businessGroupName,members:[]};
}
/** WSO2 SCIM group PATCH requires a real, WSO2-read-back username as display.
 * This must not be guessed from a browser field or user-controlled journal. */
export function memberAddBody(j,member){
  must(uuid.test(j?.userId)&&j.userId!==USER,'P224L_TARGET_USER_NOT_VERIFIED');
  validateMember(member,j,{disabled:false});
  must(typeof member.userName==='string'&&member.userName.length>0&&member.userName.length<=256,
    'P224L_MEMBER_DISPLAY_UNVERIFIED');
  return {schemas:[PATCH],Operations:[{op:'add',value:{members:[
    {display:member.userName,value:j.userId}]}}]};
}
/** A failed add remains unproven. Only explicitly acknowledged HTTP 400 plus
 * independently verified absent membership permits a new prepared attempt.
 * This NEVER creates or removes WSO2 membership. */
export function planFailedMembershipRecovery(j,group,member){
  assertJournal(j);
  must(j.phase==='active'&&j.groupPhase==='verified'&&
    uuid.test(j.userId)&&uuid.test(j.groupId)&&
    j.membershipPhase==='add-started', 'P224L_MEMBERSHIP_RECOVERY_JOURNAL_DENIED');
  must(j.evidence.some(e=>e.event==='LIFECYCLE_USER_CREATED'&&e.source==='WSO2_SCIM_READBACK')&&
    j.evidence.some(e=>e.event==='BUSINESS_GROUP_CREATED'&&e.source==='WSO2_SCIM_READBACK')&&
    !j.evidence.some(e=>['BUSINESS_MEMBERSHIP_ADDED','MEMBERSHIP_ADD_REPLANNED'].includes(e.event)),
    'P224L_MEMBERSHIP_RECOVERY_EVIDENCE_DENIED');
  validateMember(member,j,{disabled:false});
  must(validateBusinessGroup(group,j)===false,'P224L_MEMBERSHIP_RECOVERY_MEMBER_PRESENT');
  must(!Array.isArray(member.groups)||!member.groups.some(x=>x?.value===j.groupId),
    'P224L_MEMBERSHIP_RECOVERY_CONTRADICTED');
  must(j.evidence.length<40,'P224L_EVIDENCE_FULL');
  const updated={...j,membershipPhase:'none',evidence:[...j.evidence,
    {event:'MEMBERSHIP_ADD_REPLANNED',at:new Date().toISOString(),source:'LOCAL_PREPARED'}]};
  assertJournal(updated);
  return updated;
}
export function memberRemoveBody(j){
  must(uuid.test(j?.userId)&&j.userId!==USER,'P224L_TARGET_USER_NOT_VERIFIED');
  return {schemas:[PATCH],Operations:[{op:'remove',path:`members[value eq ${j.userId}]`}]};
}
export function deactivateBody(j){
  must(uuid.test(j?.userId)&&j.userId!==USER,'P224L_TARGET_USER_NOT_VERIFIED');
  return {schemas:[PATCH],Operations:[{op:'replace',path:'active',value:false}]};
}
export function journalAt(dir){
  const d=lstatSync(dir);
  must(d.isDirectory()&&!d.isSymbolicLink()&&(d.mode&0o022)===0&&
    (!process.getuid||d.uid===process.getuid()),'P224L_PRIVATE_DIRECTORY_UNSAFE');
  const path=join(dir,'p224-verde-lifecycle.private.json');
  const lock=join(dir,'p224-verde-lifecycle.lock');
  return {
    load(){let s;try{s=lstatSync(path);}catch(e){if(e.code==='ENOENT')return null;throw e;}
      must(s.isFile()&&!s.isSymbolicLink()&&(s.mode&0o077)===0 &&s.size<=32768 &&
        (!process.getuid||s.uid===process.getuid()),'P224L_PRIVATE_JOURNAL_UNSAFE');
      const j=JSON.parse(readFileSync(path,'utf8'));assertJournal(j);return j;
    },
    save(j){assertJournal(j);
      const name=join(dir,`.p224-lifecycle-${process.pid}-${randomBytes(8).toString('hex')}`);
      const fd=openSync(name,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);
      try{writeFileSync(fd,JSON.stringify(j)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
      try{renameSync(name,path);}catch(e){unlinkSync(name);throw e;}
    },
    lock(){try{return openSync(lock,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);}
      catch{throw Error('P224L_CONCURRENT_OR_STALE_LOCK');}},
    unlock(fd){closeSync(fd);unlinkSync(lock);}
  };
}
export function safeStatus(j,{groupAssigned=null,memberActive=null}={}){
  return {phase:'P2.24+P2.29',partner:'Verde Logistics',partnerId:PARTNER,
    lifecycleUser:j?{id:j.userId??null,phase:j.phase,active:memberActive}:null,
    businessGroup:j?{id:j.groupId??null,phase:j.groupPhase,memberAssigned:groupAssigned}:null,
    membershipPhase:j?.membershipPhase??'none',
    eventEvidence:j?.evidence?.map(({event,at,source})=>({event,at,source}))??[],
    delegatedActions:'USER_LIST_AND_CREATE',
    ownerApprovedActions:'BUSINESS_GROUP_AND_DEACTIVATION',
    userTokenProtocol:'LAB_ONLY_PASSWORD_GRANT',
    tokenRevocationAfterDeactivation:'NOT_TESTED',
    otherPartnerWriteDenial:'NOT_EXECUTED_NO_SECOND_VERIFIED_PARTNER',
    privateCredentialsExposed:false};
}
