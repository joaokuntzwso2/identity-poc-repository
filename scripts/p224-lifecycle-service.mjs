#!/usr/bin/env node
/** Loopback-only lab partner journey. Delegated user creates/lists; owner performs
 * explicitly labelled group/offboarding operations. No public BFF route. */
import http from 'node:http';
import {randomBytes,timingSafeEqual,X509Certificate} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadAuthority,verifyRuntimeImage,createOAuthProvider} from './p2-bootstrap-auto.mjs';
import {ROOT_SCOPES} from './p2-bootstrap-core.mjs';
import {verifyDelegateJournal,userAppJournal,privateRead,SCOPE} from './p224-user-token-core.mjs';
import {BASE,TENANT,ROOT,PARTNER,USER,REQUIRED,apiBase,apiBase as users,orgSelf,validateToken,
  inventory,uuid} from './p224-delegated-write-core.mjs';
import {jsonClient} from './p224-delegated-write.mjs';
import {plan,addProof,assertJournal,journalAt,safeStatus,validateContext,validateMember,
  validateBusinessGroup,memberCreateBody,businessGroupCreateBody,memberAddBody,memberRemoveBody,
  deactivateBody,planLegacyGroupRecovery,planFailedMembershipRecovery,ADMIN_GROUP} from './p224-lifecycle-core.mjs';
const REPO=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const GROUPS=`${BASE}/t/${TENANT}/o/scim2/Groups`;
const PORT=4472;
const ORIGIN=`http://127.0.0.1:${PORT}`;
const must=(ok,code)=>{if(!ok)throw Error(code);};
const safeError=e=>{const s=String(e?.message||'');return /^[A-Z0-9_:.-]{4,120}$/.test(s)?s:'P224L_UNEXPECTED_BLOCKED';};
const checkTLS=()=>{
  must(process.env.NODE_ENV!=='production' && process.env.NODE_TLS_REJECT_UNAUTHORIZED!=='0',
    'P224L_PRODUCTION_OR_TLS_BYPASS_DENIED');
  const cert=resolve(REPO,'var/wso2/tls/wso2-local.pem');
  const st=lstatSync(cert);
  must(st.isFile()&&!st.isSymbolicLink() &&
    resolve(process.env.NODE_EXTRA_CA_CERTS||'/')===cert,'P224L_TLS_CA_NOT_PINNED');
  const expected='2B:A3:61:A0:32:FF:D4:B3:4F:7D:F0:66:DE:72:B6:1C:5E:83:6A:09:F7:A7:BD:71:05:EB:87:B4:09:4D:97:12';
  must(new X509Certificate(readFileSync(cert)).fingerprint256.toUpperCase()===expected,
    'P224L_TLS_CERT_CHANGED');
  verifyRuntimeImage();
};
const privateHome=()=>{
  const base=process.env.CIAM_V10_HOME||join(process.env.HOME||'','wso2-ciam-v10');
  must(base.startsWith('/')&&!base.includes('..'),'P224L_PRIVATE_HOME_INVALID');
  return join(base,'private');
};
function context(){
  const dir=privateHome();
  const auth=privateRead(join(dir,'p2-bootstrap-authority.private.json'));
  must(auth?.domain===TENANT&&auth?.rootOrganizationId===ROOT&&
    auth?.state==='verified'&&uuid.test(auth?.resources?.['/o/scim2/Users'])&&
    uuid.test(auth?.resources?.['/o/scim2/Groups']), 'P224L_AUTHORITY_NOT_VERIFIED');
  const delegated=verifyDelegateJournal(privateRead(join(dir,'p224-verde-delegation.private.json')));
  const app=userAppJournal(dir).load();
  must(app?.phase==='verified'&&app.partnerId===PARTNER&&
    typeof app.clientId==='string'&&app.clientId.length>=8&&
    typeof app.clientSecret==='string'&&app.clientSecret.length>=8,
    'P224L_DELEGATED_APP_NOT_VERIFIED');
  return {dir,delegated,app,auth};
}
async function oauth(credentials,kind,form){
  must(['token','introspect'].includes(kind),'P224L_OAUTH_ENDPOINT_DENIED');
  const href=`${BASE}/t/${TENANT}/o/${PARTNER}/oauth2/${kind}`;
  let res;
  try{res=await fetch(href,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(12000),
    headers:{Authorization:'Basic '+Buffer.from(credentials.clientId+':'+credentials.clientSecret).toString('base64'),
      'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},
    body:new URLSearchParams(form)});}
  catch{throw Error('P224L_OAUTH_TRANSPORT_UNAVAILABLE');}
  must(res.status===200,`P224L_OAUTH_${kind.toUpperCase()}_HTTP_${res.status}`);
  const body=await res.text();must(body.length<=32768,'P224L_OAUTH_RESPONSE_OVERSIZE');
  try{return JSON.parse(body);}catch{throw Error('P224L_OAUTH_RESPONSE_MALFORMED');}
}
async function delegatedUser(c){
  const token=await oauth(c.app,'token',{grant_type:'password',username:c.delegated.username,
    password:c.delegated.password,scope:REQUIRED.join(' ')});
  const claims=await oauth(c.app,'introspect',{token:token.access_token});
  const bearer=validateToken(token,claims,c.app.clientId);
  return jsonClient(bearer,'user');
}
async function owner(scopes){
  const provider=createOAuthProvider({credentials:loadAuthority(REPO)});
  const root=await provider.root(TENANT,ROOT_SCOPES);
  const switched=await provider.partner(TENANT,PARTNER,scopes,root.access_token);
  must(typeof switched.access_token==='string'&&switched.access_token.length>16,
    'P224L_OWNER_TOKEN_MISSING');
  const granted=(switched.scope??'').split(/\s+/);
  must(scopes.every(s=>granted.includes(s)), 'P224L_OWNER_SCOPE_NOT_GRANTED');
  return switched.access_token;
}
export function allowedRemote(method,url,targetId){
  const u=new URL(url);
  must(u.origin===BASE&&!u.search&&!u.hash&&!u.username&&!u.password,
    'P224L_REMOTE_ORIGIN_DENIED');
  const p=u.pathname;
  const good=(method==='GET'&&p===new URL(orgSelf).pathname) ||
    (method==='GET'&&p===new URL(GROUPS).pathname) ||
    (method==='POST'&&p===new URL(GROUPS).pathname) ||
    (['GET','PATCH'].includes(method)&&uuid.test(targetId)&&p===new URL(GROUPS).pathname+'/'+targetId) ||
    (['GET','PATCH'].includes(method)&&uuid.test(targetId)&&p===new URL(users).pathname+'/'+targetId);
  must(good,'P224L_REMOTE_PATH_OR_METHOD_DENIED');
  return u.href;
}
export function ownerRequest(token,targetId,transport=fetch){
  return async(method,url,body)=>{
    const href=allowedRemote(method,url,targetId);
    must(body===undefined ? method==='GET' : ['POST','PATCH'].includes(method),
      'P224L_REQUEST_SHAPE_DENIED');
    let res;
    try{res=await transport(href,{method,redirect:'manual',signal:AbortSignal.timeout(12000),
      headers:{Authorization:'Bearer '+token,Accept:'application/json, application/scim+json',
        ...(body===undefined?{}:{'Content-Type':'application/scim+json'})},
      ...(body===undefined?{}:{body:JSON.stringify(body)})});}
    catch{throw Error('P224L_REMOTE_WRITE_OUTCOME_UNCERTAIN');}
    must(res.status>=200&&res.status<300,`P224L_REMOTE_HTTP_${res.status}_NO_RETRY`);
    const content=await res.text();must(content.length<=262144,'P224L_RESPONSE_TOO_LARGE');
    if(!content)return {};
    try{return JSON.parse(content);}catch{throw Error('P224L_RESPONSE_NOT_JSON');}
  };
}
async function allGroups(request){
  // Scope-safe bounded group inventory. A list can never be assumed complete
  // from an unverified partial page; for this lab stop if >100 groups.
  const p=await request('GET',GROUPS);
  must(Number.isSafeInteger(p?.totalResults)&&p.totalResults>=0&&p.totalResults<=100,
    'P224L_GROUP_LIST_NOT_BOUNDED');
  const rows=p.totalResults===0&&p.Resources===undefined?[]:p.Resources;
  must(Array.isArray(rows)&&rows.length===p.totalResults,'P224L_GROUP_LIST_INCOMPLETE');
  must(rows.every(g=>uuid.test(g.id))&&new Set(rows.map(g=>g.id)).size===rows.length,
    'P224L_GROUP_LIST_INVALID');
  return rows;
}
function lockAndSave(journal){const lock=journal.lock();return {lock,done:()=>journal.unlock(lock)};}
const memberUrl=id=>users+'/'+id;
const groupUrl=id=>GROUPS+'/'+id;
async function readBoundMember(j,user){
  const v=await user('GET',memberUrl(j.userId));
  validateMember(v,j,{disabled:j.phase==='disabled'});return v;
}
async function prepareMember(c,journal){
  let j=journal.load();if(j)return j;
  j=plan();journal.save(j);return j;
}
async function createMember(c,journal){
  const user=await delegatedUser(c);
  let j=await prepareMember(c,journal);
  if(j.phase==='active'||j.phase==='disabled'||j.phase==='deactivate-started'){
    await readBoundMember(j,user);return safeStatus(j,{memberActive:j.phase==='active'});
  }
  const rows=await inventory(user);
  const found=rows.filter(x=>x.userName && x.userName.replace(/^PRIMARY\//,'').split('@')[0]===j.username);
  must(found.length<=1,'P224L_USER_COLLISION');
  if(found.length){
    must(j.phase==='create-started','P224L_UNOWNED_USER_COLLISION');
    j.userId=found[0].id;
    await readBoundMember(j,user);j.phase='active';addProof(j,'LIFECYCLE_USER_CREATED');journal.save(j);
    return safeStatus(j,{memberActive:true});
  }
  must(j.phase==='prepared','P224L_USER_POST_OUTCOME_UNCERTAIN_NO_RETRY');
  j.phase='create-started';journal.save(j);
  const posted=await user('POST',users,memberCreateBody(j));
  must(uuid.test(posted?.id)&&posted.id!==USER,'P224L_USER_CREATE_OUTCOME_UNCERTAIN');
  j.userId=posted.id;journal.save(j);
  await readBoundMember(j,user);
  j.phase='active';addProof(j,'LIFECYCLE_USER_CREATED');journal.save(j);
  return safeStatus(j,{memberActive:true});
}
async function groupClient(requireCreate=false){
  const scopes=['internal_org_organization_view','internal_org_group_mgt_view',
    ...(requireCreate?['internal_org_group_mgt_create','internal_org_group_mgt_update']:
      ['internal_org_group_mgt_update'])];
  const token=await owner(scopes);
  const r=ownerRequest(token,null);
  validateContext(await r('GET',orgSelf));
  return token;
}
async function createGroup(c,journal){
  let j=journal.load();must(j?.phase==='active'&&uuid.test(j.userId),
    'P224L_MEMBER_MUST_BE_ACTIVE_FIRST');
  const token=await groupClient(true);
  const r=ownerRequest(token,null);
  const rows=await allGroups(r);
  const found=rows.filter(x=>x.displayName?.replace(/^PRIMARY\//,'')===j.businessGroupName);
  must(found.length<=1,'P224L_GROUP_COLLISION');
  if(j.groupPhase==='verified'){
    must(found.length===1&&found[0].id===j.groupId,'P224L_GROUP_DISAPPEARED_OR_CHANGED');
    validateBusinessGroup(await ownerRequest(token,j.groupId)('GET',groupUrl(j.groupId)),j);
    return safeStatus(j);
  }
  if(found.length){
    must(j.groupPhase==='create-started'&&uuid.test(found[0].id),
      'P224L_UNOWNED_GROUP_COLLISION');
    j.groupId=found[0].id;
    validateBusinessGroup(await ownerRequest(token,j.groupId)('GET',groupUrl(j.groupId)),j);
    j.groupPhase='verified';addProof(j,'BUSINESS_GROUP_CREATED');journal.save(j);
    return safeStatus(j);
  }
  must(j.groupPhase==='none','P224L_GROUP_POST_OUTCOME_UNCERTAIN_NO_RETRY');
  j.groupPhase='create-started';journal.save(j);
  const result=await r('POST',GROUPS,businessGroupCreateBody(j));
  must(uuid.test(result?.id)&&result.id!==ADMIN_GROUP,'P224L_GROUP_CREATE_OUTCOME_UNCERTAIN');
  j.groupId=result.id;journal.save(j);
  validateBusinessGroup(await ownerRequest(token,j.groupId)('GET',groupUrl(j.groupId)),j);
  j.groupPhase='verified';addProof(j,'BUSINESS_GROUP_CREATED');journal.save(j);
  return safeStatus(j);
}
/** Explicit local re-plan after a WSO2 400, never a remote create retry.
 * A distinct, short group name replaces the original only after scoped GET
 * confirms absence of both names. The portal requires another confirmation
 * for its subsequent first POST of that changed payload. */
async function recovery(action){
  const c=context();const journal=journalAt(c.dir);
  const lock=journal.lock();
  try{
    const j=journal.load();
    must(j?.groupPhase==='create-started'&&j?.groupId==null,
      'P224L_RECOVERY_NOT_REQUIRED');
    const user=await delegatedUser(c);
    await readBoundMember(j,user);
    // Re-plan is read-only: request view scopes, never create/update scopes.
    const token=await owner(['internal_org_organization_view','internal_org_group_mgt_view']);
    validateContext(await ownerRequest(token,null)('GET',orgSelf));
    const groups=await allGroups(ownerRequest(token,null));
    const next=planLegacyGroupRecovery(j,groups);
    if(action==='recover-group-check'){
      return {phase:'P2.24+P2.29',mode:'READ_ONLY',state:'SAFE_REPLAN_AVAILABLE',
        oldGroupNameLength:j.businessGroupName.length,
        replacementGroupNameLength:next.businessGroupName.length,
        oldAndNewGroupAbsent:true,remoteWrites:0,journalWrites:0};
    }
    must(action==='recover-group' && process.env.P224L_APPROVE_GROUP_REPLAN==='YES',
      'P224L_REPLAN_APPROVAL_MISSING');
    journal.save(next);
    return {phase:'P2.24+P2.29',mode:'LOCAL_JOURNAL_REPLAN',
      state:'GROUP_REPLANNED_NO_REMOTE_POST',
      replacementGroupNameLength:next.businessGroupName.length,
      oldAndNewGroupAbsent:true,remoteWrites:0,journalWrites:1,
      nextStep:'RESTART_PORTAL_AND_CONFIRM_GROUP_ACTION'};
  }finally{journal.unlock(lock);}
}
/** Read-only replan evidence is separated from any new WSO2 PATCH. */
async function membershipRecovery(action){
  const c=context();const journal=journalAt(c.dir);
  const lock=journal.lock();
  try{
    const j=journal.load();
    must(j?.membershipPhase==='add-started'&&j.groupPhase==='verified',
      'P224L_MEMBERSHIP_RECOVERY_NOT_REQUIRED');
    // The same organization-local owner authority performs strictly GETs.
    const token=await owner(['internal_org_organization_view',
      'internal_org_group_mgt_view','internal_org_user_mgt_view']);
    const org=ownerRequest(token,null);
    validateContext(await org('GET',orgSelf));
    const group=await ownerRequest(token,j.groupId)('GET',groupUrl(j.groupId));
    const member=await ownerRequest(token,j.userId)('GET',memberUrl(j.userId));
    const next=planFailedMembershipRecovery(j,group,member);
    if(action==='recover-membership-check'){
      return {phase:'P2.24+P2.29',mode:'READ_ONLY',
        state:'SAFE_MEMBERSHIP_REPLAN_AVAILABLE',
        memberActive:true,groupAssigned:false,originalAttempt:'UNVERIFIED_HTTP_400_REPORTED',
        remoteWrites:0,journalWrites:0};
    }
    must(action==='recover-membership' &&
      process.env.P224L_APPROVE_MEMBERSHIP_REPLAN==='HTTP_400_CONFIRMED',
      'P224L_MEMBERSHIP_RECOVERY_APPROVAL_REQUIRED');
    journal.save(next);
    return {phase:'P2.24+P2.29',mode:'LOCAL_JOURNAL_REPLAN',
      state:'MEMBERSHIP_REPLANNED_NO_REMOTE_PATCH',
      groupAssigned:false,remoteWrites:0,journalWrites:1,
      nextStep:'RESTART_PORTAL_AND_CONFIRM_ADD_MEMBERSHIP'};
  }finally{journal.unlock(lock);}
}
async function membership(c,journal,which){
  let j=journal.load();must(j?.groupPhase==='verified'&&j.phase==='active'&&uuid.test(j.userId),
    'P224L_GROUP_AND_MEMBER_NOT_VERIFIED');
  const token=await groupClient(true);
  const r=ownerRequest(token,j.groupId);
  const remote=await r('GET',groupUrl(j.groupId));
  const assigned=validateBusinessGroup(remote,j);
  if(which==='add'&&assigned){
    if(j.membershipPhase==='add-started'){
      j.membershipPhase='added';addProof(j,'BUSINESS_MEMBERSHIP_ADDED');journal.save(j);
    }
    must(j.membershipPhase==='added','P224L_MEMBERSHIP_ALREADY_EXISTS_UNOWNED');
    return safeStatus(j,{groupAssigned:true});
  }
  if(which==='remove'&&!assigned){
    // Adopt only an already journaled removal whose effects are verified.
    if(j.membershipPhase==='remove-started'){
      j.membershipPhase='removed';addProof(j,'BUSINESS_MEMBERSHIP_REMOVED');journal.save(j);
    }
    // A nonexistent membership after add-started is NOT a successful removal.
    must(j.membershipPhase==='removed','P224L_REMOVE_NO_MEMBERSHIP_TO_REVOKE');
    return safeStatus(j,{groupAssigned:false});
  }
  if(which==='remove')must(j.membershipPhase==='added',
    'P224L_REMOVE_REQUIRES_VERIFIED_ADD');
  must(!['add-started','remove-started'].includes(j.membershipPhase),
    'P224L_MEMBERSHIP_PATCH_OUTCOME_UNCERTAIN_NO_RETRY');
  let body;
  if(which==='add'){
    const delegate=await delegatedUser(c);
    const member=await readBoundMember(j,delegate);
    body=memberAddBody(j,member);
  }else body=memberRemoveBody(j);
  j.membershipPhase=which==='add'?'add-started':'remove-started';journal.save(j);
  await r('PATCH',groupUrl(j.groupId),body);
  const after=validateBusinessGroup(await r('GET',groupUrl(j.groupId)),j);
  must(after===(which==='add'),'P224L_MEMBERSHIP_PATCH_UNVERIFIED');
  j.membershipPhase=which==='add'?'added':'removed';
  addProof(j,which==='add'?'BUSINESS_MEMBERSHIP_ADDED':'BUSINESS_MEMBERSHIP_REMOVED');journal.save(j);
  return safeStatus(j,{groupAssigned:after});
}
async function deactivate(c,journal){
  let j=journal.load();must(j&&uuid.test(j.userId)&&j.groupPhase==='verified'&&
    j.membershipPhase==='removed'&&
    j.evidence.some(e=>e.event==='BUSINESS_MEMBERSHIP_ADDED'&&e.source==='WSO2_SCIM_READBACK')&&
    j.evidence.some(e=>e.event==='BUSINESS_MEMBERSHIP_REMOVED'&&e.source==='WSO2_SCIM_READBACK'),
    'P224L_MEMBERSHIP_MUST_BE_REMOVED_FIRST');
  // Independently prove business access has been removed, not merely that
  // a local journal says it should have been removed.
  const membershipToken=await groupClient();
  const actualGroup=await ownerRequest(membershipToken,j.groupId)('GET',groupUrl(j.groupId));
  must(validateBusinessGroup(actualGroup,j)===false,
    'P224L_DEACTIVATION_GROUP_STILL_ASSIGNED');
  const delegated=await delegatedUser(c);
  if(j.phase==='disabled'){
    await readBoundMember(j,delegated);return safeStatus(j,{memberActive:false});
  }
  must(['active','deactivate-started'].includes(j.phase),'P224L_MEMBER_NOT_ACTIVE');
  // Owner update is a separately authorized capability; the delegated user
  // intentionally does NOT receive user-update permission.
  const token=await owner(['internal_org_organization_view','internal_org_user_mgt_view',
    'internal_org_user_mgt_update']);
  const r=ownerRequest(token,j.userId);
  validateContext(await ownerRequest(token,null)('GET',orgSelf));
  const current=await r('GET',memberUrl(j.userId));
  must(current.id===j.userId && current.userName?.startsWith(j.username),
    'P224L_MEMBER_IDENTITY_UNVERIFIED');
  if(current.active===false){
    must(j.phase==='deactivate-started','P224L_UNOWNED_DEACTIVATION');
    j.phase='disabled';addProof(j,'LIFECYCLE_USER_DISABLED');journal.save(j);
    return safeStatus(j,{memberActive:false});
  }
  validateMember(current,j,{disabled:false});
  must(j.phase==='active','P224L_DEACTIVATION_OUTCOME_UNCERTAIN_NO_RETRY');
  j.phase='deactivate-started';journal.save(j);
  await r('PATCH',memberUrl(j.userId),deactivateBody(j));
  const after=await r('GET',memberUrl(j.userId));
  validateMember(after,j,{disabled:true});
  j.phase='disabled';addProof(j,'LIFECYCLE_USER_DISABLED');journal.save(j);
  return safeStatus(j,{memberActive:false});
}
async function status(c,journal){
  const j=journal.load();
  const user=await delegatedUser(c);
  const rows=await inventory(user);
  let memberActive=null,groupAssigned=null;
  if(j?.userId){const m=await user('GET',memberUrl(j.userId));
    validateMember(m,j,{disabled:j.phase==='disabled'});memberActive=m.active;}
  if(j?.groupId){const token=await groupClient();const r=ownerRequest(token,j.groupId);
    groupAssigned=validateBusinessGroup(await r('GET',groupUrl(j.groupId)),j);}
  return {...safeStatus(j,{memberActive,groupAssigned}),
    observedUsers:rows.map(x=>({id:x.id,username:typeof x.userName==='string'?x.userName.slice(0,100):'UNKNOWN',
      active:x.active===true})).slice(0,100),observedUserCount:rows.length};
}
export async function execute(action){
  const c=context();const journal=journalAt(c.dir);
  const lock=journal.lock();
  try{
    if(action==='status')return await status(c,journal);
    if(action==='create')return await createMember(c,journal);
    if(action==='group')return await createGroup(c,journal);
    if(action==='add')return await membership(c,journal,'add');
    if(action==='remove')return await membership(c,journal,'remove');
    if(action==='deactivate')return await deactivate(c,journal);
    throw Error('P224L_ACTION_DENIED');
  }finally{journal.unlock(lock);}
}
const headers={
  'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'",
  'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
  'Cache-Control':'no-store, no-cache, must-revalidate',
  'X-Frame-Options':'DENY','Cross-Origin-Resource-Policy':'same-origin',
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()'};
const reply=(res,status,obj)=>{res.writeHead(status,{...headers,'Content-Type':'application/json; charset=utf-8'});
  res.end(JSON.stringify(obj));};
const html=(res,body,ctype)=>{res.writeHead(200,{...headers,'Content-Type':ctype});res.end(body);};
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&
  timingSafeEqual(Buffer.from(a),Buffer.from(b));
function body(req){return new Promise((resolve,reject)=>{
  let raw='',n=0;req.on('data',x=>{n+=x.length;if(n>2048){reject(Error('P224L_BODY_TOO_LARGE'));req.destroy();}
    else raw+=x;});req.on('end',()=>{try{resolve(JSON.parse(raw));}catch{reject(Error('P224L_JSON_INVALID'));}});
    req.on('error',()=>reject(Error('P224L_CLIENT_BODY_FAILED')));
  });}
export function createPortal({pin,now=()=>Date.now(),executeAction=execute,
    page=readFileSync(join(REPO,'services/identity-bff/src/p224-lifecycle.html'),'utf8'),
    js=readFileSync(join(REPO,'services/identity-bff/src/p224-lifecycle.js'),'utf8'),
    css=readFileSync(join(REPO,'services/identity-bff/src/p224-lifecycle.css'),'utf8')}={}){
  must(typeof pin==='string'&&pin.length>=12,'P224L_OPERATOR_PIN_INVALID');
  let session=null,attempts=0,pinUntil=now()+5*60_000;
  return http.createServer(async(req,res)=>{
    try{
      must(req.socket.remoteAddress==='127.0.0.1'||req.socket.remoteAddress==='::ffff:127.0.0.1',
        'P224L_NON_LOOPBACK_DENIED');
      must(req.headers.host===`127.0.0.1:${PORT}`,'P224L_HOST_DENIED');
      const url=new URL(req.url,ORIGIN);
      must(url.origin===ORIGIN&&!url.search&&!url.hash,'P224L_URL_DENIED');
      if(req.method==='GET'&&url.pathname==='/'){html(res,page,'text/html; charset=utf-8');return;}
      if(req.method==='GET'&&url.pathname==='/p224-lifecycle.js'){
        html(res,js,'text/javascript; charset=utf-8');return;}
      if(req.method==='GET'&&url.pathname==='/p224-lifecycle.css'){
        html(res,css,'text/css; charset=utf-8');return;}
      if(req.method==='POST'){
        must(req.headers.origin===ORIGIN,'P224L_ORIGIN_DENIED');
        must(req.headers['content-type']==='application/json','P224L_CONTENT_TYPE_DENIED');
      }
      if(req.method==='POST'&&url.pathname==='/api/login'){
        must(attempts<4&&now()<pinUntil,'P224L_LOGIN_EXPIRED_OR_LOCKED');
        const incoming=await body(req);attempts++;
        must(same(incoming?.code,pin),'P224L_INVALID_OPERATOR_CODE');
        session={id:randomBytes(32).toString('base64url'),csrf:randomBytes(32).toString('base64url'),
          until:now()+45*60_000};
        pinUntil=0;
        res.setHeader('Set-Cookie',`p224l=${session.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2700`);
        reply(res,200,{status:'AUTHENTICATED',csrf:session.csrf});return;
      }
      const cookie=String(req.headers.cookie||'').split(';').map(x=>x.trim())
        .filter(x=>x.startsWith('p224l='));
      must(session&&session.until>now()&&cookie.length===1&&same(cookie[0].slice(6),session.id),
        'P224L_SESSION_REQUIRED');
      if(req.method==='GET'&&url.pathname==='/api/state'){
        const data=await executeAction('status');reply(res,200,{...data,csrf:session.csrf});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/action'){
        must(same(req.headers['x-csrf-token'],session.csrf),'P224L_CSRF_DENIED');
        const incoming=await body(req);
        must(['create','group','add','remove','deactivate'].includes(incoming?.action),
          'P224L_ACTION_DENIED');
        const phrase=incoming.action==='deactivate'?'DEACTIVATE':'VERDE';
        must(incoming.confirm===phrase,'P224L_EXPLICIT_CONFIRMATION_REQUIRED');
        const value=await executeAction(incoming.action);
        reply(res,200,{status:'WSO2_READBACK_VERIFIED',result:value});return;
      }
      reply(res,404,{status:'DENIED'});
    }catch(error){const code=safeError(error);
      reply(res,code.includes('SESSION')?401:403,{status:'BLOCKED',code});}
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{checkTLS();
    if(process.argv[2]==='check'){
      execute('status').then(x=>console.log(JSON.stringify({stage:'P224_LIFECYCLE',mode:'CHECK',
        state:'REMOTE_READBACK_VERIFIED',...x,remoteWrites:0}))).catch(e=>{
        console.error(JSON.stringify({stage:'P224_LIFECYCLE',mode:'CHECK',status:'BLOCKED',
          reason:safeError(e),remoteWrites:0}));process.exitCode=1;});
    }else if(['recover-group-check','recover-group'].includes(process.argv[2])){
      recovery(process.argv[2]).then(x=>console.log(JSON.stringify(x))).catch(e=>{
        console.error(JSON.stringify({stage:'P224_LIFECYCLE_RECOVERY',status:'BLOCKED',
          reason:safeError(e),remoteWrites:0}));process.exitCode=1;});
    }else if(['recover-membership-check','recover-membership'].includes(process.argv[2])){
      membershipRecovery(process.argv[2]).then(x=>console.log(JSON.stringify(x))).catch(e=>{
        console.error(JSON.stringify({stage:'P224_LIFECYCLE_MEMBERSHIP_RECOVERY',status:'BLOCKED',
          reason:safeError(e),remoteWrites:0}));process.exitCode=1;});
    }else if(process.argv[2]==='serve'){
      const pin=randomBytes(12).toString('base64url');
      const app=createPortal({pin});
      app.listen(PORT,'127.0.0.1',()=>{
        console.log('P224_LIFECYCLE_LOCAL_PORTAL_READY http://127.0.0.1:'+PORT+'/');
        console.log('P224_LOCAL_OPERATOR_LOGIN_CODE '+pin);
        console.log('Code expires after five minutes; WSO2 passwords and tokens are never displayed.');
      });
    }else throw Error('P224L_MODE_DENIED');
  }catch(e){console.error(JSON.stringify({stage:'P224_LIFECYCLE',status:'BLOCKED',
    reason:safeError(e),remoteWrites:0}));process.exitCode=1;}
}
