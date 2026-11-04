/** P2.24: narrow, journaled ordinary-user creation by the WSO2-issued Verde user token. */
import {randomBytes} from 'node:crypto';
import {lstatSync,openSync,readFileSync,writeFileSync,fsyncSync,closeSync,renameSync,unlinkSync,constants} from 'node:fs';
import {join} from 'node:path';
import {TENANT,ROOT,PARTNER,USER,ROLE,CLIENT_NAME,SCOPE,verifyAuthorizedApi,verifyApp,verifyAppProtocol,verifyIntrospection,verifyOAuthToken,privateRead} from './p224-user-token-core.mjs';
export {TENANT,ROOT,PARTNER,USER,ROLE};
export const VIEW='internal_org_user_mgt_view';
export const CREATE='internal_org_user_mgt_create';
export const REQUIRED=Object.freeze([SCOPE,VIEW,CREATE]);
export const BASE='https://localhost:9444';
export const API='/o/scim2/Users';
export const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
export const apiBase=`${BASE}/t/${TENANT}/o/scim2/Users`;
export const appBase=`${BASE}/t/${TENANT}/o/api/server/v1/applications`;
export const orgSelf=`${BASE}/t/${TENANT}/o/api/server/v1/organizations/self`;
const ownName=/^p2-verde-member-[a-f0-9]{16}$/;
const fail=(ok,code)=>{if(!ok)throw Error(code);};
export function checkPermissions(record,resourceId){
  fail(record?.id===resourceId && uuid.test(resourceId) &&
    (record.policyIdentifier??record.policyId??'RBAC')==='RBAC','P224W_APP_AUTH_ID_OR_POLICY_WRONG');
  const s=record.authorizedScopes??record.scopes;
  fail(Array.isArray(s),'P224W_APP_AUTH_SCOPES_MISSING');
  const names=s.map(x=>typeof x==='string'?x:x?.name);
  fail(names.every(x=>typeof x==='string')&&new Set(names).size===names.length,
    'P224W_APP_AUTH_SCOPE_DUPLICATE');
  if(names.length===1 && names[0]===SCOPE)return 'BASE';
  fail(names.length===REQUIRED.length && REQUIRED.every(x=>names.includes(x)),
    'P224W_APP_AUTH_FOREIGN_SCOPE');
  return 'EXTENDED';
}
export function exactUserName(candidate,name){
  if(typeof candidate!=='string')return false;
  let n=candidate.startsWith('PRIMARY/')?candidate.slice(8):candidate;
  return n===name || n===`${name}@${PARTNER}` || n===`${name}@${TENANT}`;
}
export function safeUser(user,plan){
  fail(uuid.test(user?.id)&&user.id!==USER,'P224W_USER_ID_NOT_VERIFIED');
  fail(exactUserName(user.userName,plan.username),'P224W_USER_NAME_NOT_VERIFIED');
  fail(user.active===true,'P224W_USER_NOT_ACTIVE');
  fail(Array.isArray(user.emails)&&user.emails.some(e=>
    (typeof e==='string'?e:e?.value)===plan.email),'P224W_USER_EMAIL_NOT_VERIFIED');
  fail(!Array.isArray(user.roles) || !user.roles.some(x=>x.value===ROLE),
    'P224W_USER_ACCIDENTALLY_GRANTED_ADMIN_ROLE');
  fail(!Array.isArray(user.groups) || !user.groups.some(x=>x.value==='f43022fa-cb55-4b19-bb6c-23bba8f2d322'),
    'P224W_USER_ACCIDENTALLY_IN_ADMIN_GROUP');
  return user.id;
}
export function newPlan(){
  const suffix=randomBytes(8).toString('hex');
  return {username:`p2-verde-member-${suffix}`,
    email:`p2-verde-member-${suffix}@aurora.identity.test`,
    password:randomBytes(42).toString('base64url')+'Aa9!'};
}
export function userPayload(plan){
  fail(ownName.test(plan?.username)&&plan.email===`${plan.username}@aurora.identity.test`&&
    typeof plan.password==='string'&&plan.password.length>=40&&plan.password.length<=128,
    'P224W_USER_PLAN_INVALID');
  return {schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName:plan.username,password:plan.password,active:true,
    name:{givenName:'Verde',familyName:'Lab Member'},
    emails:[{value:plan.email,primary:true}]};
}
export function store(dir){
  const parent=lstatSync(dir);
  fail(parent.isDirectory()&&!parent.isSymbolicLink()&&(parent.mode&0o022)===0&&
    (!process.getuid||parent.uid===process.getuid()),'P224W_JOURNAL_DIR_INSECURE');
  const file=join(dir,'p224-verde-member.private.json');
  const lock=join(dir,'p224-verde-member.lock');
  const load=()=>{const d=privateRead(file,true);
    if(d)fail(d.schema==='identity.wso2.p224.member.v1'&&d.partnerId===PARTNER&&
      d.userId!==USER&& (!d.userId || uuid.test(d.userId)) &&
      ['prepared','post-started','verified'].includes(d.phase)&&
      ['none','started','verified'].includes(d.authPhase), 'P224W_JOURNAL_DRIFT');
    if(d)userPayload(d);
    return d;};
  const save=(doc)=>{
    const tmp=join(dir,'.p224w-'+process.pid+'-'+randomBytes(8).toString('hex'));
    const fd=openSync(tmp,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);
    try{writeFileSync(fd,JSON.stringify(doc)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
    try{renameSync(tmp,file);}catch(e){unlinkSync(tmp);throw e;}
  };
  return {load,save,acquire(){try{return openSync(lock,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);}catch{throw Error('P224W_CONCURRENT_OR_STALE_LOCK');}},release(fd){closeSync(fd);unlinkSync(lock);}};
}
export function validateApp({app,protocol,appId,marker}){
  verifyApp(app,appId,marker);
  const creds=verifyAppProtocol(protocol);
  fail(app?.associatedRoles?.allowedAudience==='ORGANIZATION','P224W_APP_ROLE_AUDIENCE');
  return creds;
}
export async function remoteAuthorization({request,appId,resourceId,journal,apply}){
  fail(uuid.test(appId)&&uuid.test(resourceId),'P224W_API_IDS_INVALID');
  const url=`${appBase}/${appId}/authorized-apis`;
  const read=async()=>{
    const data=await request('GET',url);
    const rows=Array.isArray(data)?data:(data?.authorizedAPIs??data?.authorizedApis);
    fail(Array.isArray(rows)&&rows.length===1,'P224W_EXTRA_API_AUTHORIZED');
    return checkPermissions(rows[0],resourceId);
  };
  const current=await read();
  let j=journal.load();
  if(current==='EXTENDED'){
    fail(j?.authPhase==='started'||j?.authPhase==='verified',
      'P224W_EXISTING_SCOPE_CHANGE_UNOWNED');
    if(apply && j.authPhase==='started'){j.authPhase='verified';journal.save(j);}
    return 'EXTENDED';
  }
  fail(!j || j.authPhase==='none','P224W_AUTH_UPDATE_OUTCOME_UNCERTAIN_NO_RETRY');
  if(!apply)return 'AUTHORIZATION_REQUIRED';
  if(!j){j={schema:'identity.wso2.p224.member.v1',partnerId:PARTNER,
    ...newPlan(),phase:'prepared',authPhase:'none'};journal.save(j);}
  j.authPhase='started';journal.save(j);
  await request('PATCH',`${url}/${resourceId}`,
    {addedScopes:[VIEW,CREATE],removedScopes:[]});
  fail(await read()==='EXTENDED','P224W_AUTH_UPDATE_READBACK_FAILED');
  j.authPhase='verified';journal.save(j);
  return 'EXTENDED';
}
export function validateToken(tokenResponse,introspection,clientId,now=Math.floor(Date.now()/1000)){
  const access=verifyOAuthToken(tokenResponse);
  fail(typeof tokenResponse.scope==='string'&&REQUIRED.every(s=>
    tokenResponse.scope.split(/\s+/).includes(s)),'P224W_DELEGATED_SCOPES_NOT_GRANTED');
  verifyIntrospection(introspection,clientId,now);
  if(introspection.scope!==undefined)fail(REQUIRED.every(s=>
    introspection.scope.split(/\s+/).includes(s)),'P224W_INTROSPECT_SCOPE_CONTRADICTION');
  return access;
}
export async function inventory(read){
  let index=1,total=null,all=[];const seen=new Set();
  for(let pages=0;pages<30;pages++){
    const data=await read('GET',`${apiBase}?startIndex=${index}&count=100`);
    fail(data && Number.isSafeInteger(data.totalResults)&&data.totalResults>=0&&
      data.totalResults<=3000 &&(total===null||total===data.totalResults), 'P224W_SCIM_TOTAL_INVALID');
    if(total===null)total=data.totalResults;
    const rows=data.totalResults===0 && data.Resources===undefined?[]:data.Resources;
    fail(Array.isArray(rows)&&rows.length<=100&&rows.length<=total-all.length&&
      (total===0||rows.length>0),'P224W_SCIM_PAGE_INCOMPLETE');
    if(index!==1 || rows.length<total){
      fail(data.startIndex===index&&data.itemsPerPage===rows.length,
        'P224W_SCIM_PAGE_METADATA_INVALID');
    }
    for(const item of rows){
      fail(uuid.test(item?.id)&&!seen.has(item.id.toLowerCase()),
        'P224W_SCIM_DUPLICATE_OR_INVALID_ID');
      seen.add(item.id.toLowerCase());all.push(item);
    }
    if(all.length===total)return all;
    index=all.length+1;
  }
  throw Error('P224W_SCIM_PAGINATION_EXCEEDED');
}
export async function reconcileMember({read,write,journal,apply}){
  fail(typeof read==='function'&&typeof write==='function','P224W_DEPENDENCIES_INVALID');
  let j=journal.load();
  const rows=await inventory(read);
  const matched=j?rows.filter(x=>exactUserName(x.userName,j.username)):[];
  fail(matched.length<=1,'P224W_MEMBER_NAME_AMBIGUOUS');
  if(!j){
    if(!apply)return {phase:'P2.24-DELEGATED-WRITE',state:'CREATE_REQUIRED',remoteWrites:0};
    j={schema:'identity.wso2.p224.member.v1',partnerId:PARTNER,
      ...newPlan(),phase:'prepared',authPhase:'verified'};journal.save(j);
  }
  if(j.userId && matched.length)fail(j.userId===matched[0].id,
    'P224W_MEMBER_JOURNAL_ID_MISMATCH');
  if(!matched.length && j.phase==='post-started')throw Error('P224W_CREATE_OUTCOME_UNCERTAIN_NO_RETRY');
  if(!matched.length && j.userId)throw Error('P224W_MEMBER_DISAPPEARED_NO_RECREATE');
  if(matched.length){
    fail(j.phase!=='prepared','P224W_PREEXISTING_UNOWNED_MEMBER');
    j.userId=matched[0].id;
    const doc=await read('GET',`${apiBase}/${j.userId}`);
    safeUser(doc,j);
    if(apply && j.phase!=='verified'){j.phase='verified';journal.save(j);}
    return {phase:'P2.24-DELEGATED-WRITE',state:'WSO2_DELEGATED_USER_CREATE_VERIFIED',
      userId:j.userId,partnerId:PARTNER,readback:'VERIFIED',remoteWrites:0};
  }
  if(!apply)return {phase:'P2.24-DELEGATED-WRITE',state:'CREATE_REQUIRED',remoteWrites:0};
  fail(j.phase==='prepared'&&j.authPhase==='verified','P224W_WRITE_NOT_AUTHORIZED');
  j.phase='post-started';journal.save(j);
  const body=userPayload(j);
  const created=await write('POST',apiBase,body);
  fail(uuid.test(created?.id),'P224W_CREATE_ID_UNCERTAIN_NO_RETRY');
  j.userId=created.id;journal.save(j);
  const doc=await read('GET',`${apiBase}/${j.userId}`);
  safeUser(doc,j);
  j.phase='verified';journal.save(j);
  return {phase:'P2.24-DELEGATED-WRITE',state:'WSO2_DELEGATED_USER_CREATE_VERIFIED',
    userId:j.userId,partnerId:PARTNER,readback:'VERIFIED',remoteWrites:1};
}
export function verifyContext(s){
  fail(s?.id===PARTNER&&s.parent?.id===ROOT&&s.status==='ACTIVE',
    'P224W_ORGANIZATION_CONTEXT_NOT_VERIFIED');
  return true;
}
