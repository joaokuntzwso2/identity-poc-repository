/**
 * WSO2 IS 7.3 CIAM lab bootstrap. Non-destructive, bounded, journaled.
 * This is a local-lab bootstrap, NEVER a database-reset utility.
 * No secrets are printed. No remote DELETE. On uncertain writes, stop.
 */
import {randomBytes} from 'node:crypto';
import {existsSync, lstatSync, readFileSync, mkdirSync, writeFileSync, renameSync, chmodSync, openSync, closeSync, unlinkSync} from 'node:fs';
import {resolve, dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

const BRANDS=['aurora','brisa'];
const DOMAINS={aurora:'aurora.identity.test',brisa:'brisa.identity.test'};
const USERS={aurora:'ciam_aurora',brisa:'ciam_brisa'};
const ID=/^[a-zA-Z0-9-]{5,128}$/;
const SCIM='/scim2/Users';
const SCOPES=['internal_user_mgt_list','internal_user_mgt_view','internal_user_mgt_create'];
const ROOT=resolve('var/wso2/tenant-brand.private.json');
const MANAGEMENT=resolve('var/wso2/tenant-management.private.json');
const STATE=resolve('var/wso2/ciam-bootstrap-v8.private.json');
const PIDLOCK=resolve('var/wso2/ciam-bootstrap-v8.lock');

export function labOrigin(env=process.env) {
  const u=new URL(env.WSO2_BASE_URL||'');
  if(u.protocol!=='https:' || u.port!=='9443' || !['localhost','127.0.0.1'].includes(u.hostname) || u.pathname!=='/' || u.username || u.password || u.search || u.hash)
    throw Error('LOCAL_HTTPS_9443_ONLY');
  if(env.WSO2_AURORA_ROOT_TENANT && env.WSO2_AURORA_ROOT_TENANT!==DOMAINS.aurora)throw Error('AURORA_DOMAIN_CHANGE_REFUSED');
  if(env.WSO2_BRISA_ROOT_TENANT && env.WSO2_BRISA_ROOT_TENANT!==DOMAINS.brisa)throw Error('BRISA_DOMAIN_CHANGE_REFUSED');
  return u.origin;
}
export function privateRead(path, optional=false) {
  if(!existsSync(path)){if(optional)return null;throw Error('PRIVATE_FILE_MISSING_'+path.split('/').pop());}
  const s=lstatSync(path);
  if(!s.isFile() || s.isSymbolicLink() || (s.mode&0o777)!==0o600 || (typeof process.getuid==='function'&&s.uid!==process.getuid()))
    throw Error('UNSAFE_PRIVATE_FILE_'+path.split('/').pop());
  return JSON.parse(readFileSync(path,'utf8'));
}
function atomicPrivate(path,value) {
  mkdirSync(dirname(path),{recursive:true,mode:0o700});
  const tmp=path+'.'+process.pid+'.'+randomBytes(5).toString('hex')+'.tmp';
  try{writeFileSync(tmp,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});chmodSync(tmp,0o600);renameSync(tmp,path)}
  catch(e){try{unlinkSync(tmp)}catch{}throw e}
}
export function newPassword(){return randomBytes(27).toString('base64url')+'!aA9';}
export function userPayload(brand,password,externalId){
  if(!BRANDS.includes(brand)||typeof password!=='string'||password.length<28 || !/^[A-Za-z0-9_-]{18,70}$/.test(externalId))throw Error('SCIM_USER_PAYLOAD_REFUSED');
  return {schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],externalId,userName:USERS[brand],password,
    name:{givenName:'CIAM',familyName:brand==='aurora'?'Aurora':'Brisa'},
    emails:[{value:`ciam-${brand}@example.invalid`,primary:true}],active:true};
}
export function parseScimList(body,username){
  if(!Array.isArray(body?.Resources)||!Number.isInteger(body.totalResults) || body.totalResults<0)throw Error('SCIM_LIST_UNRECOGNIZED');
  const matches=body.Resources.filter(x=>String(x?.userName||'').replace(/^PRIMARY\//,'').toLowerCase()===username.toLowerCase());
  if(matches.length>1 || body.totalResults>body.Resources.length)throw Error('SCIM_PAGINATION_OR_DUPLICATE_AMBIGUITY');
  return matches[0]||null;
}
function assertOwner(brand,root){
  const item=root?.tenants?.[brand],domain=DOMAINS[brand];
  if(item?.owned!==true || item?.state!=='created' || item?.domain!==domain || item.owner?.username!=='labtenantadmin'||!ID.test(item.tenantId||'')||!ID.test(item.ownerId||''))
    throw Error('OWNER_JOURNAL_IDENTITY_UNSAFE_'+brand);
  return item;
}
function assertManagement(brand,state){
  const m=state?.management?.[brand];
  if(m?.domain!==DOMAINS[brand] || m?.state!=='verified' || !ID.test(m?.id||'') || !m.clientId || !m.clientSecret)
    throw Error('MANAGEMENT_JOURNAL_MISSING_'+brand);
  return m;
}
function stateFor(base){return {schema:'identity.wso2.ciam.v8',base,tenants:{},acceptance:'NOT_VERIFIED'};}
function validateState(s,base){
  if(s.schema!=='identity.wso2.ciam.v8'||s.base!==base||!s.tenants||Array.isArray(s.tenants))throw Error('CIAM_V8_JOURNAL_CONTEXT_REFUSED');
  return s;
}
function pathFor(brand,rest){return `/t/${DOMAINS[brand]}${rest}`;}
function basic(username,password){return 'Basic '+Buffer.from(username+':'+password).toString('base64');}

export async function httpCall({base,path,method='GET',auth,payload,form,fetchImpl=fetch}){
  if(!path.startsWith('/')||path.startsWith('//')||path.includes('..')||path.includes('\\'))throw Error('UNSAFE_REQUEST_PATH');
  if(!['GET','POST','PUT','PATCH'].includes(method))throw Error('UNSAFE_REQUEST_METHOD');
  const url=new URL(path,base);if(url.origin!==base)throw Error('CROSS_ORIGIN_REFUSED');
  const headers={Accept:'application/json',Authorization:auth};
  const opts={method,redirect:'error',signal:AbortSignal.timeout(15000),headers};
  if(payload){headers['Content-Type']=path.includes('/scim2/')?'application/scim+json':'application/json';opts.body=JSON.stringify(payload)}
  if(form){headers['Content-Type']='application/x-www-form-urlencoded';opts.body=new URLSearchParams(form).toString()}
  let response;try{response=await fetchImpl(url.href,opts)}catch{throw Error('WSO2_NETWORK_OUTCOME_UNKNOWN_'+method)}
  let data=null;
  const raw=await response.text();if(raw.length>200000)throw Error('WSO2_RESPONSE_TOO_LARGE');
  if(raw.trim())try{data=JSON.parse(raw)}catch{if(response.ok)throw Error('WSO2_NON_JSON_SUCCESS')}
  return {status:response.status,data};
}
function expect(res,expected,name){if(res.status!==expected)throw Error(name+'_HTTP_'+res.status);return res.data}
function expectOwnerResponse(owner,res,brand){
  const d=expect(res,200,'OWNER_READBACK_'+brand);
  if(d?.id!==owner.ownerId || d?.username!=='labtenantadmin'||d?.firstname!==owner.owner.firstname||d?.lastname!==owner.owner.lastname||d?.email!==owner.owner.email)throw Error('OWNER_READBACK_MISMATCH_'+brand);
  return d;
}
async function rootOwner(base,brand,owner,rootAuth,fetchImpl){
  const path=`/api/server/v1/tenants/${owner.tenantId}/owners/${owner.ownerId}`;
  const res=await httpCall({base,path,auth:rootAuth,fetchImpl});
  return expectOwnerResponse(owner,res,brand);
}
async function basicProbe(base,brand,password,fetchImpl){
  for(const username of [`labtenantadmin@${DOMAINS[brand]}`,'labtenantadmin']){
    const r=await httpCall({base,path:pathFor(brand,'/api/server/v1/applications?limit=1'),auth:basic(username,password),fetchImpl});
    if(r.status===200)return {username,auth:basic(username,password)};
    if(r.status!==401)throw Error('TENANT_OWNER_API_AUTH_HTTP_'+brand+'_'+r.status);
  }
  throw Error('TENANT_OWNER_PASSWORD_NOT_ACCEPTED_FOR_API_'+brand);
}
async function managedToken(base,brand,m,scopes,fetchImpl){
  const result=await httpCall({base,path:pathFor(brand,'/oauth2/token'),method:'POST',auth:basic(m.clientId,m.clientSecret),form:{grant_type:'client_credentials',scope:scopes.join(' ')},fetchImpl});
  const data=expect(result,200,'TENANT_TOKEN_'+brand);
  const got=new Set(String(data?.scope||'').split(/\s+/).filter(Boolean));
  if(!scopes.every(s=>got.has(s))||typeof data?.access_token!=='string'||String(data.token_type||'').toLowerCase()!=='bearer')
    throw Error('TENANT_MANAGEMENT_SCOPES_MISSING_'+brand);
  return 'Bearer '+data.access_token;
}
async function discoverScimResource(base,brand,ownerAuth,fetchImpl){
  const query=new URLSearchParams({filter:`identifier eq ${SCIM}`,limit:'100'});
  const r=await httpCall({base,path:pathFor(brand,`/api/server/v1/api-resources?${query}`),auth:ownerAuth,fetchImpl});
  const d=expect(r,200,'SCIM_RESOURCE_LIST_'+brand);
  const list=Array.isArray(d?.APIResources)?d.APIResources:Array.isArray(d?.apiResources)?d.apiResources:Array.isArray(d?.resources)?d.resources:Array.isArray(d?.list)?d.list:[];
  const found=list.filter(x=>x.identifier===SCIM);
  if(found.length!==1 || !ID.test(found[0].id||''))throw Error('SCIM_API_RESOURCE_NOT_UNIQUE_'+brand);
  return found[0].id;
}
function scopeNames(entry){return new Set((entry?.authorizedScopes||entry?.scopes||[]).map(s=>typeof s==='string'?s:s?.name).filter(Boolean));}
function authEntries(data){if(Array.isArray(data))return data;for(const k of ['authorizedAPIs','authorizedApis','apis','resources'])if(Array.isArray(data?.[k]))return data[k];throw Error('APP_AUTH_RESPONSE_UNKNOWN');}
async function authorizeScim({base,brand,m,ownerAuth,state,save,fetchImpl}){
  const resourceId=await discoverScimResource(base,brand,ownerAuth,fetchImpl);
  const path=pathFor(brand,`/api/server/v1/applications/${m.id}/authorized-apis`);
  const get=()=>httpCall({base,path,auth:ownerAuth,fetchImpl});
  const read=async()=>{
    const entries=authEntries(expect(await get(),200,'APP_AUTH_READ_'+brand));
    const matches=entries.filter(x=>x.id===resourceId);
    if(matches.length>1)throw Error('SCIM_AUTH_DUPLICATE_'+brand);
    return matches[0]||null;
  };
  const current=await read();const missing=SCOPES.filter(s=>!scopeNames(current).has(s));
  const authState=state.tenants[brand].scopeWrite;
  if(authState?.resourceId && authState.resourceId!==resourceId)throw Error('SCIM_RESOURCE_CHANGED_'+brand);
  if(!missing.length){state.tenants[brand].scopeWrite={state:'verified',resourceId};save();return;}
  if(authState?.state==='started')throw Error('SCIM_AUTH_PREVIOUS_WRITE_UNCERTAIN_'+brand);
  if(authState?.state==='verified')throw Error('SCIM_AUTH_SCOPES_REVOKED_'+brand);
  state.tenants[brand].scopeWrite={state:'started',resourceId,missing};save();
  const result=await httpCall({base,path:current?path+'/'+resourceId:path,method:current?'PATCH':'POST',auth:ownerAuth,
    payload:current?{addedScopes:missing,removedScopes:[]}:{id:resourceId,policyIdentifier:'RBAC',scopes:SCOPES},fetchImpl});
  if(result.status!==(current?200:201))throw Error('SCIM_AUTH_WRITE_HTTP_'+brand+'_'+result.status+'_DO_NOT_RETRY');
  const confirmed=await read();
  if(!SCOPES.every(s=>scopeNames(confirmed).has(s)))throw Error('SCIM_AUTH_READBACK_MISSING_'+brand);
  state.tenants[brand].scopeWrite={state:'verified',resourceId};save();
}
async function ensureUser({base,brand,bearer,state,save,fetchImpl}){
  const own=state.tenants[brand];
  if(!own.user){own.user={state:'prepared',username:USERS[brand],externalId:'ciamv8_'+randomBytes(16).toString('hex'),password:newPassword()};save()}
  const user=own.user;
  if(user.username!==USERS[brand]||!user.externalId||!user.password)throw Error('USER_JOURNAL_INVALID_'+brand);
  const suffix=pathFor(brand,`/scim2/Users?${new URLSearchParams({filter:`userName eq "${user.username}"`,count:'10',startIndex:'1'})}`);
  const list=expect(await httpCall({base,path:suffix,auth:bearer,fetchImpl}),200,'SCIM_LIST_'+brand);
  const match=parseScimList(list,user.username);
  if(match){
    if(match.externalId!==user.externalId||!ID.test(match.id||''))throw Error('UNOWNED_USER_COLLISION_'+brand);
    if(user.id && user.id!==match.id)throw Error('USER_ID_DRIFT_'+brand);
    user.id=match.id;
  }else {
    if(user.state!=='prepared')throw Error('SCIM_USER_CREATE_PREVIOUSLY_STARTED_'+brand+'_MANUAL_RECONCILIATION');
    user.state='create-started';save();
    const result=await httpCall({base,path:pathFor(brand,SCIM),method:'POST',auth:bearer,payload:userPayload(brand,user.password,user.externalId),fetchImpl});
    if(result.status!==201)throw Error('SCIM_CREATE_HTTP_'+brand+'_'+result.status+'_DO_NOT_RETRY');
    if(!ID.test(result.data?.id||'') || result.data.externalId!==user.externalId)throw Error('SCIM_CREATE_RESPONSE_UNVERIFIED_'+brand);
    user.id=result.data.id;
    user.state='created';save();
  }
  const detail=expect(await httpCall({base,path:pathFor(brand,SCIM+'/'+user.id),auth:bearer,fetchImpl}),200,'SCIM_USER_READBACK_'+brand);
  if(detail?.id!==user.id || detail?.externalId!==user.externalId || String(detail.userName||'').replace(/^PRIMARY\//,'')!==user.username)
    throw Error('SCIM_USER_READBACK_MISMATCH_'+brand);
  if(detail.active===false)throw Error('SCIM_USER_INACTIVE_'+brand);
  user.state='verified-password-not-browser-tested';save();
  return {username:user.username,readback:'VERIFIED',browserAuthentication:'NOT_VERIFIED'};
}
function safetyConsent(env,mode){
  if(env.WSO2_LAB_CONFIRM!=='CREATE_SYNTHETIC_RESOURCES' || env.WSO2_CIAM_V8_CONFIRM!=='ROTATE_LAB_OWNERS_AND_PROVISION_USERS')
    throw Error('EXPLICIT_V8_WRITE_APPROVAL_REQUIRED');
  if(!['fresh','existing'].includes(mode))throw Error('FRESH_OR_EXISTING_MODE_REQUIRED');
}
function validateFourClients(root){
  for(const brand of BRANDS)for(const channel of ['WEB','MOBILE']){
    const key=brand.toUpperCase()+'_'+channel;
    const item=root?.clients?.[key];
    if(item?.tenant!==DOMAINS[brand] || item?.state!=='verified'||!ID.test(item?.id||'') || !item?.clientId || !item?.clientSecret)
      throw Error('OIDC_CLIENT_NOT_VERIFIED_'+key);
  }
}
async function verifiedClients(base,root,tokens,fetchImpl){
  for(const brand of BRANDS)for(const channel of ['WEB','MOBILE']){
    const key=brand.toUpperCase()+'_'+channel;const item=root.clients[key];
    const r=await httpCall({base,path:pathFor(brand,`/api/server/v1/applications/${item.id}`),auth:tokens[brand],fetchImpl});
    const data=expect(r,200,'OIDC_CLIENT_REMOTE_'+key);
    if(data?.id!==item.id||data?.applicationEnabled===false||!data?.inboundProtocolConfiguration?.oidc && !data?.authenticationSequence)
      throw Error('OIDC_CLIENT_READBACK_MISMATCH_'+key);
  }
}
function openLock(lockPath=PIDLOCK){
  mkdirSync(dirname(lockPath),{recursive:true,mode:0o700});
  // Never remove stale locks automatically: a concurrent process might still run.
  return openSync(lockPath,'wx',0o600);
}
function releaseLock(fd,lockPath=PIDLOCK){closeSync(fd);unlinkSync(lockPath)}
export async function apply(mode,{env=process.env,fetchImpl=fetch,bootstrapFresh,paths={}}={}){
  const rootFile=paths.root||ROOT,managementFile=paths.management||MANAGEMENT,stateFile=paths.state||STATE,lockPath=paths.lock||PIDLOCK;
  safetyConsent(env,mode);
  const base=labOrigin(env);
  if(!env.WSO2_ADMIN_USER || !env.WSO2_ADMIN_PASSWORD)throw Error('ROOT_ADMIN_ENV_MISSING');
  if(!env.NODE_EXTRA_CA_CERTS)throw Error('PINNED_WSO2_CERT_REQUIRED');
  let lock;
  try{
    lock=openLock(lockPath);
    if(mode==='fresh'){
      if(existsSync(rootFile)||existsSync(managementFile)||existsSync(stateFile))throw Error('FRESH_MODE_REQUIRES_UNJOURNALED_NEW_LAB');
      const inventory=await httpCall({base,path:'/api/server/v1/tenants?limit=100&offset=0',auth:basic(env.WSO2_ADMIN_USER,env.WSO2_ADMIN_PASSWORD),fetchImpl});
      const data=expect(inventory,200,'FRESH_INVENTORY');
      const entries=Array.isArray(data?.tenants)?data.tenants:[];
      if(entries.some(x=>Object.values(DOMAINS).includes(x.domain)))throw Error('FRESH_TENANT_ALREADY_EXISTS_REFUSED');
      if(!bootstrapFresh)throw Error('FRESH_BOOTSTRAP_MODULE_NOT_AVAILABLE');
      await bootstrapFresh();
    }
    const root=privateRead(rootFile),management=privateRead(managementFile);
    validateFourClients(root);
    for(const brand of BRANDS){assertOwner(brand,root);assertManagement(brand,management)}
    const rootAuth=basic(env.WSO2_ADMIN_USER,env.WSO2_ADMIN_PASSWORD);
    for(const brand of BRANDS)await rootOwner(base,brand,assertOwner(brand,root),rootAuth,fetchImpl);
    const s=validateState(privateRead(stateFile,true)||stateFor(base),base);
    const save=()=>atomicPrivate(stateFile,s);
    const ownerBasic={};
    // Refresh both owners' credentials once, with durable intent per tenant.
    for(const brand of BRANDS){
      const original=assertOwner(brand,root);
      s.tenants[brand]??={};
      const item=s.tenants[brand];
      if(!item.owner){item.owner={state:'prepared',tenantId:original.tenantId,ownerId:original.ownerId,password:newPassword()};save()}
      const o=item.owner;
      if(o.tenantId!==original.tenantId||o.ownerId!==original.ownerId||!o.password)throw Error('V8_OWNER_CONTEXT_MISMATCH_'+brand);
      if(o.state==='prepared'){
        o.state='update-started';save();
        const res=await httpCall({base,path:`/api/server/v1/tenants/${o.tenantId}/owners/${o.ownerId}`,method:'PUT',auth:rootAuth,
          payload:{email:original.owner.email,firstname:original.owner.firstname,lastname:original.owner.lastname,password:o.password},fetchImpl});
        if(res.status!==200)throw Error('OWNER_UPDATE_HTTP_'+brand+'_'+res.status+'_DO_NOT_RETRY');
        o.state='api-acknowledged';save();
      }
      await rootOwner(base,brand,original,rootAuth,fetchImpl);
      // A successful authenticated management GET verifies the new password as
      // an API credential, but DOES NOT prove browser or Console login.
      const probe=await basicProbe(base,brand,o.password,fetchImpl);
      ownerBasic[brand]=probe.auth;
      if(o.state==='update-started'||o.state==='api-acknowledged') {o.state='tenant-api-authenticated';save()}
      if(o.state!=='tenant-api-authenticated')throw Error('V8_OWNER_STATE_NOT_VERIFIED_'+brand);
    }
    // Authorize user API via each tenant admin; no manual Console steps.
    for(const brand of BRANDS){
      await authorizeScim({base,brand,m:assertManagement(brand,management),ownerAuth:ownerBasic[brand],state:s,save,fetchImpl});
    }
    const readTokens={};const userTokens={};
    for(const brand of BRANDS){
      const m=assertManagement(brand,management);
      const token=await managedToken(base,brand,m,['internal_application_mgt_view',...SCOPES],fetchImpl);
      readTokens[brand]=token;userTokens[brand]=token;
    }
    await verifiedClients(base,root,readTokens,fetchImpl);
    const users={};
    for(const brand of BRANDS)users[brand]=await ensureUser({base,brand,bearer:userTokens[brand],state:s,save,fetchImpl});
    s.acceptance='RESOURCES_VERIFIED_BROWSER_IDENTITY_UNVERIFIED';save();
    return {mode,tenants:'2_VERIFIED',managementClients:'2_VERIFIED',oidcClients:'4_VERIFIED',users,ownerCredentials:'ROTATED_AND_TENANT_API_VERIFIED',
      login:'BROWSER_CALLBACK_NOT_VERIFIED',bff:'RUNTIME_CHECK_REQUIRED',secretFile:'var/wso2/ciam-bootstrap-v8.private.json'};
  }finally{if(lock!==undefined)releaseLock(lock,lockPath)}
}
export function status(){
  const s=privateRead(STATE,true);
  if(!s)return {status:'NOT_STARTED'};
  return {schema:s.schema,acceptance:s.acceptance,tenants:Object.fromEntries(BRANDS.map(b=>[b,{ownerState:s.tenants?.[b]?.owner?.state||'NOT_STARTED',
    scimAuthorization:s.tenants?.[b]?.scopeWrite?.state||'NOT_STARTED',userState:s.tenants?.[b]?.user?.state||'NOT_STARTED',
    browserLogin:'NOT_VERIFIED'}]))};
}
export function clipboard(brand,kind='user'){
  if(!BRANDS.includes(brand)||!['user','owner'].includes(kind))throw Error('INVALID_CLIPBOARD_TARGET');
  const s=privateRead(STATE);const object=kind==='user'?s?.tenants?.[brand]?.user:s?.tenants?.[brand]?.owner;
  if(!object?.password)throw Error('PASSWORD_NOT_IN_V8_JOURNAL');
  const result=spawnSync('pbcopy',{input:object.password,encoding:'utf8',stdio:['pipe','ignore','ignore']});
  if(result.status!==0)throw Error('MACOS_CLIPBOARD_UNAVAILABLE');
  return {brand,kind,clipboard:'SET',printed:false};
}
async function main(){
  const cmd=process.argv[2]||'plan';
  if(cmd==='plan'){
    const base=labOrigin();
    console.log(JSON.stringify({bootstrap:'CIAM_V8',mode:'PLAN_ONLY',base,existingTenants:'PRESERVE',newPasswords:'ON_APPROVED_APPLY',
      userNames:USERS,managementApps:'REUSE_OR_CREATE_BY_EXISTING_BOOTSTRAP',oidcClients:'REUSE_OR_CREATE_BY_EXISTING_BOOTSTRAP',
      additionalUsers:2,dockerOperations:0,dbReset:false,browserLogin:'REQUIRES_RUNTIME_VERIFICATION'},null,2));return;
  }
  if(cmd==='status'){console.log(JSON.stringify(status(),null,2));return}
  if(cmd==='clipboard') {console.log(JSON.stringify(clipboard(process.argv[3],process.argv[4]||'user')));return}
  if(cmd==='apply'){
    const mode=process.argv[3];
    const fresh=mode==='fresh'?async()=>{
      const {execute}=await import('./bootstrap-tenant-control-plane.mjs');
      await execute('all');
    }:undefined;
    const result=await apply(mode,{bootstrapFresh:fresh});
    console.log(JSON.stringify(result,null,2));return;
  }
  throw Error('USAGE_plan_status_apply_fresh_apply_existing_clipboard_brand');
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(e=>{console.error('CIAM_V8_ERROR:',e.message);process.exitCode=1});
}
