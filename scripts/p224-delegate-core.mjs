/** P2.24 delegated user and limited operator-role reconciliation.
 * Real WSO2 organization-scoped SCIM only. No client-controlled target.
 * Never claim user-token authorization without a WSO2-issued user token.
 */
import {randomBytes} from 'node:crypto';
import {readFileSync, writeFileSync, renameSync, lstatSync, mkdirSync, openSync, closeSync, fsyncSync, unlinkSync, constants} from 'node:fs';
import {join} from 'node:path';
import {UUID, endpoints, planGroup, planMembership, changeMembership} from './p2-partner-core.mjs';

export const TENANT='aurora.identity.test';
export const ROOT='5252717e-1024-40f0-89ee-016b513d36f3';
export const PARTNER='629e590a-9072-406d-95a8-71f0cfc52cbe';
export const GROUP='f43022fa-cb55-4b19-bb6c-23bba8f2d322';
export const USERNAME='p2-verde-operator';
export const ROLE='p2-verde-user-operator';
export const PERMISSIONS=Object.freeze([
  'internal_org_user_mgt_list','internal_org_user_mgt_view','internal_org_user_mgt_create',
  'internal_org_group_mgt_view','internal_org_group_mgt_update'
]);
const ROLE_SCHEMA='urn:ietf:params:scim:schemas:extension:2.0:Role';
const PATCH_SCHEMA='urn:ietf:params:scim:api:messages:2.0:PatchOp';
const LIST_SCHEMA='urn:ietf:params:scim:api:messages:2.0:ListResponse';
const exact=(condition,message)=>{if(!condition)throw Error(message);};
const norm=x=>x?.startsWith('PRIMARY/')?x.slice(8):x;
const id=x=>{exact(typeof x==='string' && UUID.test(x),'P224_RESOURCE_ID_INVALID');return x;};
export function pinned(config) {
  exact(config?.rootTenant===TENANT && config.rootId===ROOT && config.orgId===PARTNER &&
    config.allowedGroupId===GROUP,'P224_DELEGATE_TARGET_CONTEXT_BLOCKED');
  const ep=endpoints(config);
  return {...ep,roles:`${new URL(ep.users).origin}/t/${TENANT}/o/scim2/v2/Roles`};
}
export function verifyRole(role,roleId=null) {
  exact(role && (!roleId || role.id===roleId) && UUID.test(role.id), 'P224_ROLE_ID_MISMATCH');
  exact(role.displayName===ROLE,'P224_ROLE_NAME_MISMATCH');
  exact(role.audience?.type==='organization' && role.audience?.value===PARTNER,
    'P224_ROLE_AUDIENCE_NOT_PARTNER');
  const perms=role.permissions;
  exact(Array.isArray(perms) && perms.every(x=>typeof x?.value==='string'),
    'P224_ROLE_PERMISSION_READBACK_MISSING');
  const actual=perms.map(x=>x.value);
  exact(actual.length===new Set(actual).size && actual.length===PERMISSIONS.length &&
    PERMISSIONS.every(x=>actual.includes(x)),'P224_ROLE_PERMISSIONS_NOT_EXACT');
  exact(!role.groups || (Array.isArray(role.groups) && !role.groups.length),
    'P224_ROLE_HAS_UNEXPECTED_GROUP_ASSIGNMENTS');
  exact(!role.users || (Array.isArray(role.users) && role.users.every(x=>UUID.test(x?.value))),
    'P224_ROLE_USER_ASSIGNMENTS_INVALID');
  return {id:role.id,users:(role.users||[]).map(x=>x.value.toLowerCase())};
}
export function verifyUser(user,expectedId=null) {
  exact(user && (!expectedId || user.id===expectedId) && UUID.test(user.id),
    'P224_USER_ID_MISMATCH');
  exact(norm(user.userName)===USERNAME && user.active!==false,
    'P224_USER_NAME_OR_STATE_MISMATCH');
  exact(!user.roles || (Array.isArray(user.roles) &&
    user.roles.every(x=>typeof x?.value==='string')),'P224_USER_ROLE_SHAPE_INVALID');
  return {id:user.id};
}
function listPage(page,total,index) {
  exact(page && typeof page==='object' && !Array.isArray(page),'P224_SCIM_PAGE_INVALID');
  const n=page.totalResults;
  exact(Number.isSafeInteger(n) && n>=0 && n<=3000 && (total===null || n===total),
    'P224_SCIM_TOTAL_INVALID');
  exact(page.schemas===undefined ||
    (Array.isArray(page.schemas) && page.schemas.includes(LIST_SCHEMA)),'P224_SCIM_SCHEMA_INVALID');
  const rows=n===0 && page.Resources===undefined?[]:page.Resources;
  exact(Array.isArray(rows) && rows.length<=100 && rows.length<=n,'P224_SCIM_RESOURCE_PAGE_INVALID');
  exact(n===0 || rows.length>0,'P224_SCIM_EMPTY_NONZERO_PAGE');
  if(index!==1 || n>rows.length){
    exact(page.startIndex===index && page.itemsPerPage===rows.length,
      'P224_SCIM_PAGINATION_METADATA_MISSING');
  }
  if(page.startIndex!==undefined)exact(page.startIndex===index,'P224_SCIM_OFFSET_INVALID');
  if(page.itemsPerPage!==undefined)exact(page.itemsPerPage===rows.length,'P224_SCIM_PAGE_COUNT_INVALID');
  return {rows,n};
}
export async function inventory(client,url) {
  let index=1,total=null;const all=[],seen=new Set();
  for(let i=0;i<30;i++){
    const page=listPage(await client('GET',`${url}?startIndex=${index}&count=100`),total,index);
    if(total===null)total=page.n;
    for(const item of page.rows){
      exact(item && UUID.test(item.id) && !seen.has(item.id.toLowerCase()),
        'P224_SCIM_DUPLICATE_OR_INVALID_ID');
      seen.add(item.id.toLowerCase());all.push(item);
    }
    if(all.length===total)return all;
    index=all.length+1;
  }
  throw Error('P224_SCIM_PAGE_LIMIT_REACHED');
}
async function verifyContext(client,ep) {
  const s=await client('GET',ep.org);
  exact(s?.id===PARTNER && s.parent?.id===ROOT && s.status==='ACTIVE',
    'P224_DELEGATE_ORGANIZATION_CONTEXT_BLOCKED');
}
async function remote(client,ep) {
  await verifyContext(client,ep);
  const groups=await inventory(client,ep.groups);
  exact(groups.filter(g=>g.id===GROUP).length===1 &&
    groups.some(g=>g.id===GROUP && norm(g.displayName)==='p2-partner-operations'),
    'P224_VERIFIED_GROUP_MISSING_OR_MISMATCH');
  const users=await inventory(client,ep.users);
  const roles=await inventory(client,ep.roles);
  const foundUsers=users.filter(x=>norm(x.userName)===USERNAME);
  const foundRoles=roles.filter(x=>x.displayName===ROLE);
  exact(foundUsers.length<=1 && foundRoles.length<=1,'P224_DELEGATE_NAME_COLLISION');
  const user=foundUsers.length?verifyUser(await client('GET',`${ep.users}/${id(foundUsers[0].id)}`)):null;
  const role=foundRoles.length?verifyRole(await client('GET',`${ep.roles}/${id(foundRoles[0].id)}`)):null;
  if(role && role.users.some(x=>x!==user?.id.toLowerCase()))
    throw Error('P224_ROLE_ASSIGNED_TO_FOREIGN_USER');
  return {user,role};
}
export function createJournalStore(folder) {
  // Private files are never printed, and stale symlink links are refused.
  exact(typeof folder==='string' && folder.startsWith('/') && !folder.includes('..'),
    'P224_PRIVATE_HOME_INVALID');
  const base=folder;let st=lstatSync(base);
  exact(st.isDirectory() && !st.isSymbolicLink() && (st.mode&0o022)===0 &&
    (!process.getuid || st.uid===process.getuid()),'P224_PRIVATE_HOME_INSECURE');
  const path=join(base,'p224-verde-delegation.private.json');
  function load(){
    try{
      const s=lstatSync(path);
      exact(s.isFile()&&!s.isSymbolicLink()&&(s.mode&0o077)===0&&s.size<=16384&&
        (!process.getuid||s.uid===process.getuid()),'P224_JOURNAL_INSECURE');
      const value=JSON.parse(readFileSync(path,'utf8'));
      exact(value.schema==='identity.wso2.p224.delegation.v1' &&
        value.partnerId===PARTNER && value.rootId===ROOT &&
        value.groupId===GROUP && value.tenant===TENANT,
        'P224_JOURNAL_TARGET_MISMATCH');
      return value;
    }catch(e){if(e.code==='ENOENT')return null;throw e;}
  }
  function save(value){
    const tmp=join(base,`.p224-delegation-${process.pid}-${randomBytes(5).toString('hex')}`);
    const fd=openSync(tmp,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);
    try {writeFileSync(fd,JSON.stringify(value)+'\n');fsyncSync(fd);} finally{closeSync(fd);}
    try{renameSync(tmp,path);}catch(e){unlinkSync(tmp);throw e;}
  }
  const lockPath=join(base,'p224-verde-delegation.lock');
  return {load,save,acquire(){
    try{return openSync(lockPath,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);}
    catch{throw Error('P224_DELEGATION_CONCURRENT_OR_STALE_LOCK');}
  },release(fd){closeSync(fd);unlinkSync(lockPath);}};
}
function baseJournal(){return {schema:'identity.wso2.p224.delegation.v1',
  tenant:TENANT,rootId:ROOT,partnerId:PARTNER,groupId:GROUP,
  user:{phase:'none'},role:{phase:'none'},membership:{phase:'none'},assignment:{phase:'none'}};}
function checkIdentity(j,type,seen){
  const record=j[type];
  if(!record)return;
  if(record.id && seen && record.id!==seen.id)throw Error(`P224_${type.toUpperCase()}_JOURNAL_ID_DRIFT`);
  if(record.phase==='started' && !seen)throw Error(`P224_${type.toUpperCase()}_WRITE_OUTCOME_UNCERTAIN_NO_RETRY`);
  if(record.phase==='verified' && !seen)throw Error(`P224_${type.toUpperCase()}_DISAPPEARED_REMOTE`);
}
export async function reconcileDelegate({client,config,journal,write=false,makePassword=()=>('P2!aA9'+randomBytes(36).toString('base64url'))}) {
  exact(typeof client==='function' && journal?.load && journal?.save,
    'P224_DELEGATE_DEPENDENCIES_MISSING');
  const ep=pinned(config);
  const existing=await remote(client,ep);
  let j=journal.load();
  if(!j && !write){
    exact(!existing.user && !existing.role,'P224_UNOWNED_DELEGATE_RESOURCE_COLLISION');
    return {phase:'P2.24-DELEGATE',mode:'CHECK',user:'MISSING',role:'MISSING',
    group:'EXISTS_READBACK_VERIFIED',managementWrites:0,userTokenAcceptance:'NOT_EXECUTED'};
  }
  if(!j)j=baseJournal();
  checkIdentity(j,'user',existing.user); checkIdentity(j,'role',existing.role);
  // A matching name without a prior journal is never silently adopted.
  if((existing.user && j.user.phase==='none') || (existing.role && j.role.phase==='none'))
    throw Error('P224_UNOWNED_DELEGATE_RESOURCE_COLLISION');
  if(!write){
    let membership='MISSING',assignment='MISSING';
    if(existing.user && existing.role){
      const membershipPlan=await planMembership({client,config,groupId:GROUP,userId:existing.user.id,op:'ADD'});
      membership=membershipPlan.decision==='ALREADY_DESIRED'?'VERIFIED':'MISSING';
      assignment=existing.role.users.length===1 &&
        existing.role.users[0]===existing.user.id.toLowerCase()?'VERIFIED':'MISSING';
    }
    return {phase:'P2.24-DELEGATE',mode:'CHECK',partnerId:PARTNER,groupId:GROUP,
      role:existing.role?'VERIFIED':'MISSING',user:existing.user?'VERIFIED':'MISSING',
      membership,roleAssignment:assignment,managementWrites:0,
      userTokenAcceptance:'NOT_EXECUTED'};
  }
  // No role/user POST is retried after an uncertain result. A new run may
  // adopt only the exact existing resource whose prepared journal owns it.
  if(!existing.role){
    exact(j.role.phase==='none','P224_ROLE_POST_OUTCOME_UNCERTAIN_NO_RETRY');
    j.role={phase:'started'};journal.save(j);
    const data=await client('POST',ep.roles,{schemas:[ROLE_SCHEMA],displayName:ROLE,
      audience:{type:'organization',value:PARTNER},
      permissions:PERMISSIONS.map(value=>({value}))});
    const roleId=id(data?.id);
    j.role={phase:'started',id:roleId};journal.save(j);
    verifyRole(await client('GET',`${ep.roles}/${roleId}`),roleId);
    j.role.phase='verified';journal.save(j);
  }else if(j.role.phase!=='verified'){j.role={phase:'verified',id:existing.role.id};journal.save(j);}
  // Create one dedicated, randomly generated private test-user password.
  if(!existing.user){
    exact(j.user.phase==='none','P224_USER_POST_OUTCOME_UNCERTAIN_NO_RETRY');
    const password=makePassword();
    exact(typeof password==='string' && password.length>=32 && password.length<=128,
      'P224_PASSWORD_GENERATOR_INVALID');
    j.user={phase:'started',password};journal.save(j);
    const data=await client('POST',ep.users,{schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName:USERNAME,password,active:true,
      name:{givenName:'P2',familyName:'Verde Operator'},
      emails:[{value:'p2-verde-operator@aurora.identity.test',primary:true}]});
    const userId=id(data?.id);
    j.user={phase:'started',id:userId,password};journal.save(j);
    verifyUser(await client('GET',`${ep.users}/${userId}`),userId);
    j.user.phase='verified';journal.save(j);
  }else if(j.user.phase!=='verified'){
    j.user={...j.user,phase:'verified',id:existing.user.id};journal.save(j);
  }
  // Readback after each potentially asynchronous WSO2 write.
  const current=await remote(client,ep);
  exact(current.role?.id===j.role.id && current.user?.id===j.user.id,
    'P224_CREATED_RESOURCES_NOT_VISIBLE');
  const p=await planMembership({client,config,groupId:GROUP,userId:current.user.id,op:'ADD'});
  if(p.decision!=='ALREADY_DESIRED'){
    exact(j.membership.phase==='none','P224_MEMBERSHIP_OUTCOME_UNCERTAIN_NO_RETRY');
    j.membership={phase:'started'};journal.save(j);
    await changeMembership({client,config,groupId:GROUP,userId:current.user.id,
      op:'ADD',approval:p.approval});
    j.membership={phase:'verified'};journal.save(j);
  }else if(j.membership.phase==='started'){
    j.membership={phase:'verified'};journal.save(j);
  }
  const role=verifyRole(await client('GET',`${ep.roles}/${j.role.id}`),j.role.id);
  if(!role.users.includes(j.user.id.toLowerCase())){
    exact(j.assignment.phase==='none','P224_ROLE_ASSIGNMENT_UNCERTAIN_NO_RETRY');
    exact(role.users.length===0,'P224_ROLE_HAS_FOREIGN_USER');
    j.assignment={phase:'started'};journal.save(j);
    await client('PATCH',`${ep.roles}/${j.role.id}`,{schemas:[PATCH_SCHEMA],
      Operations:[{op:'add',path:'users',value:[{value:j.user.id}]}]});
    const after=verifyRole(await client('GET',`${ep.roles}/${j.role.id}`),j.role.id);
    exact(after.users.length===1 && after.users[0]===j.user.id.toLowerCase(),
      'P224_ROLE_ASSIGNMENT_NOT_VERIFIED');
    j.assignment={phase:'verified'};journal.save(j);
  }else if(j.assignment.phase==='started'){
    j.assignment={phase:'verified'};journal.save(j);
  }
  // Strong final readbacks. Existing P2 group is never repurposed as a role.
  await verifyContext(client,ep);
  const again=verifyRole(await client('GET',`${ep.roles}/${j.role.id}`),j.role.id);
  verifyUser(await client('GET',`${ep.users}/${j.user.id}`),j.user.id);
  exact(again.users.length===1 && again.users[0]===j.user.id.toLowerCase(),
    'P224_FINAL_ROLE_ASSIGNMENT_MISMATCH');
  const membership=await planMembership({client,config,groupId:GROUP,userId:j.user.id,op:'ADD'});
  exact(membership.decision==='ALREADY_DESIRED','P224_FINAL_MEMBERSHIP_MISSING');
  return {phase:'P2.24-DELEGATE',mode:'APPLY',partnerId:PARTNER,groupId:GROUP,
    userId:j.user.id,roleId:j.role.id,rolePermissions:'EXACT_READBACK_VERIFIED',
    userRoleAssignment:'WSO2_READBACK_VERIFIED',groupMembership:'WSO2_READBACK_VERIFIED',
    userCredentials:'PRIVATE_OWNER_ONLY',userTokenAcceptance:'NOT_EXECUTED',
    crossTenantUserDenial:'NOT_EXECUTED'};
}
