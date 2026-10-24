/**
 * Lab-only automatic root tenant and brand OIDC registration.
 * Each tenant is genuinely isolated. Cross-tenant federation, human SSO,
 * and actual signed pairwise ID-token evidence remain independent gates.
 * No root tenant deletion/adoption is performed by this utility.
 */
import {randomBytes,createHash} from 'node:crypto';
import {readFileSync,existsSync,mkdirSync,writeFileSync,renameSync,chmodSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {root,assertUpdatedBuild,config,deploymentPlan} from './domain.mjs';
import {origin} from './api.mjs';
import {documents,assertSectorDocuments,sectorUris} from './sector.mjs';

const stateDir=resolve(root,'var/wso2');
const statePath=join(stateDir,'tenant-brand.private.json');
// Tenant-management REST is a super-tenant API; /t/carbon.super/ is restricted.
const ROOT_TENANT_LIST='/api/server/v1/tenants';
const DOM=/^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$/;
const ID=/^[a-zA-Z0-9-]{5,128}$/;
const BRANDS=['aurora','brisa'];

function requireLab(env){
 if(env.WSO2_LAB_CONFIRM!=='CREATE_SYNTHETIC_RESOURCES')throw Error('EXPLICIT_APPLY_ACK_REQUIRED');
 assertUpdatedBuild(env);
 const base=origin(env.WSO2_BASE_URL||'');
 const url=new URL(base);
 if(!['localhost','127.0.0.1'].includes(url.hostname))throw Error('TENANT_AUTOCREATE_LOCAL_ONLY');
 if(!env.WSO2_ADMIN_USER||!env.WSO2_ADMIN_PASSWORD)throw Error('ADMIN_CREDENTIALS_REQUIRED');
 const domains={aurora:env.WSO2_AURORA_ROOT_TENANT||'aurora.identity.test',brisa:env.WSO2_BRISA_ROOT_TENANT||'brisa.identity.test'};
 if(domains.aurora===domains.brisa||Object.values(domains).some(x=>!DOM.test(x)||x==='carbon.super'))throw Error('TWO_DISTINCT_VALID_TENANT_DOMAINS_REQUIRED');
 return {base,domains};
}
function privateWrite(file,obj){
 mkdirSync(resolve(file,'..'),{recursive:true,mode:0o700});
 const tmp=`${file}.${process.pid}.tmp`;
 writeFileSync(tmp,JSON.stringify(obj,null,2)+'\n',{mode:0o600,flag:'wx'});
 chmodSync(tmp,0o600);renameSync(tmp,file);
}
function readState(path,base,domains){
 const hash=createHash('sha256').update(base).digest('hex').slice(0,20);
 const s=existsSync(path)?JSON.parse(readFileSync(path,'utf8')):
  {schema:'identity.wso2.tenant-brand.v1',originHash:hash,domains,tenants:{},clients:{},acceptance:'NOT_VERIFIED'};
 if(s.schema!=='identity.wso2.tenant-brand.v1'||s.originHash!==hash||
    BRANDS.some(b=>s.domains?.[b]!==domains[b])||!s.tenants||!s.clients)throw Error('TENANT_STATE_ORIGIN_OR_DOMAIN_CHANGE_REFUSED');
 return s;
}
async function jsonCall(fetchImpl,base,path,{method='GET',auth,payload}={}){
 if(!path.startsWith('/')||path.startsWith('//')||path.includes('..')||path.includes('\\'))throw Error('UNTRUSTED_WSO2_PATH');
 const url=new URL(path,base);
 if(url.origin!==base)throw Error('CROSS_ORIGIN_MANAGEMENT_REFUSED');
 const res=await fetchImpl(url.href,{method,redirect:'error',headers:{Accept:'application/json',
  ...(payload?{'Content-Type':'application/json'}:{}),Authorization:'Basic '+Buffer.from(`${auth.username}:${auth.password}`,'utf8').toString('base64')},
  ...(payload?{body:JSON.stringify(payload)}:{}),signal:AbortSignal.timeout(15000)});
 const raw=await res.text();if(raw.length>524288)throw Error('WSO2_RESPONSE_TOO_LARGE');
 let data={};try{data=raw?JSON.parse(raw):{}}catch{if(res.ok)throw Error('WSO2_NON_JSON_SUCCESS')}
 if(!res.ok){const err=new Error(`WSO2_${method}_${res.status}_${String(data?.code||data?.error||'API_ERROR').slice(0,100)}`);err.status=res.status;throw err;}
 return {data,status:res.status,location:res.headers?.get('location')||null};
}
function tenantList(data){
 const arr=Array.isArray(data)?data:data?.tenants??data?.list??data?.resources;
 if(Array.isArray(arr))return arr;
 // WSO2 IS 7.3 can omit `tenants` for an empty paginated result.
 // Accept only that exact empty shape; never hide malformed/nonempty responses.
 if(data && typeof data==='object' && !Array.isArray(data) &&
    Object.keys(data).length===4 &&
    ['totalResults','startIndex','count','links'].every(k=>Object.hasOwn(data,k)) &&
    data.totalResults===0 && data.count===0 &&
    Number.isSafeInteger(data.startIndex) && data.startIndex>=0 &&
    Array.isArray(data.links) && data.links.length===0)return [];
 throw Error('TENANT_LIST_RESPONSE_SHAPE_UNRECOGNIZED');
}
async function remoteTenants(fetchImpl,base,admin){
 const collected=[];
 for(let offset=0;offset<=10000;offset+=100){
  const r=await jsonCall(fetchImpl,base,`${ROOT_TENANT_LIST}?limit=100&offset=${offset}`,{auth:admin});
  const batch=tenantList(r.data);collected.push(...batch);
  if(batch.length<100)break;
  const total=r.data?.totalResults??r.data?.totalCount??r.data?.total;
  if(typeof total==='number'&&collected.length>=total)break;
  if(offset===10000)throw Error('TENANT_LIST_TOO_MANY_PAGES');
 }
 return new Set(collected.map(x=>x.domain??x.domainName).filter(Boolean));
}
/** GET-only prerequisite check; no journal, tenant writes, or operator confirmation. */
export async function tenantApiPreflight({env=process.env,fetchImpl=fetch}={}){
 const base=origin(env.WSO2_BASE_URL||'');
 if(!['localhost','127.0.0.1'].includes(new URL(base).hostname))throw Error('TENANT_AUTH_CHECK_LOCAL_ONLY');
 if(!env.WSO2_ADMIN_USER||!env.WSO2_ADMIN_PASSWORD)throw Error('ADMIN_CREDENTIALS_REQUIRED');
 const tenants=await remoteTenants(fetchImpl,base,{username:env.WSO2_ADMIN_USER,password:env.WSO2_ADMIN_PASSWORD});
 return {tenantApiRoute:ROOT_TENANT_LIST,authentication:'VERIFIED_READ_ONLY',tenantCount:tenants.size,tenantWrites:0};
}
function safeOwner(){return {username:'labtenantadmin',password:randomBytes(21).toString('base64url'),
 firstname:'Identity',lastname:'Lab',email:'lab-tenant-admin@example.invalid',provisioningMethod:'inline-password'};}
function tenantPath(domain,suffix){return `/t/${encodeURIComponent(domain)}${suffix}`;}
function clientPayload(app,uri){return {
 name:app.name,description:'Lab-owned browser-backed OIDC client; not a native-app proof',isManagementApp:false,accessUrl:app.accessUrl,
 inboundProtocolConfiguration:{oidc:{grantTypes:['authorization_code','refresh_token'],publicClient:false,
  callbackURLs:[app.callback],pkce:{mandatory:true,supportPlainTransformAlgorithm:false},
  subject:{subjectType:'pairwise',sectorIdentifierUri:uri},
  accessToken:{type:'JWT',userAccessTokenExpiryInSeconds:1800,applicationAccessTokenExpiryInSeconds:1800}}}
};}
function responseId(r){const id=r.data?.id||r.location?.split('/').pop();if(!id||!ID.test(id))throw Error('APPLICATION_ID_NOT_RETURNED');return id;}

export async function bootstrapTenants({env=process.env,fetchImpl=fetch,stateFile=statePath,
  sectorFetchImpl=fetch,emit=console.log,onlyTenants=false}={}){
 const {base,domains}=requireLab(env);
 const c=config();const plan=deploymentPlan(c,env);
 const admin={username:env.WSO2_ADMIN_USER,password:env.WSO2_ADMIN_PASSWORD};
 const s=readState(stateFile,base,domains);
 const live=await remoteTenants(fetchImpl,base,admin);
 for(const brand of BRANDS){
  const domain=domains[brand];let item=s.tenants[brand];
  if(item&&item.domain!==domain)throw Error('TENANT_STATE_DOMAIN_MISMATCH');
  if(!item){
   if(live.has(domain))throw Error(`TENANT_ALREADY_EXISTS_UNOWNED_${brand}`);
   item={domain,owner:safeOwner(),state:'prepared',owned:true};
   s.tenants[brand]=item;privateWrite(stateFile,s);
  }
  if(item.owned!==true||!item.owner?.username||!item.owner?.password||
     !['prepared','create-started','created'].includes(item.state))
   throw Error(`TENANT_OWNERSHIP_JOURNAL_INVALID_${brand}`);
  // A prepared journal never adopts a tenant that appeared independently.
  if(item.state==='prepared'&&live.has(domain))
   throw Error(`TENANT_PREPARED_BUT_DOMAIN_EXISTS_${brand}_MANUAL_REVIEW`);
  if(item.createOutcome==='CONFLICT_409'||item.createOutcome==='PARTIAL_206')
   throw Error(`TENANT_CREATE_PREVIOUS_AMBIGUOUS_RESPONSE_${brand}_MANUAL_REVIEW`);
  if(item.state==='create-started'&&!live.has(domain))
   throw Error(`TENANT_CREATE_OUTCOME_UNCERTAIN_${brand}_MANUAL_REVIEW`);
  if(item.state==='created'&&!live.has(domain))
   throw Error(`JOURNALED_TENANT_MISSING_${brand}_MANUAL_REVIEW`);
  if(item.state==='prepared'){
   item.state='create-started';privateWrite(stateFile,s);
   let created;
   try{
    created=await jsonCall(fetchImpl,base,ROOT_TENANT_LIST,{method:'POST',auth:admin,payload:{
     name:brand==='aurora'?'Identity Lab Aurora':'Identity Lab Brisa',domain,owners:[item.owner]}});
   }catch(e){
    if(e.status===409){item.createOutcome='CONFLICT_409';privateWrite(stateFile,s);}
    throw e;
   }
   // 206 is partial; a 409 is a collision. Neither can be automatically adopted.
   if(created.status!==201){
    if(created.status===206){item.createOutcome='PARTIAL_206';privateWrite(stateFile,s);}
    throw Error(`TENANT_CREATE_HTTP_${created.status}_${brand}_MANUAL_REVIEW`);
   }
   item.createOutcome='ACKNOWLEDGED_201';privateWrite(stateFile,s);
   const refreshed=await remoteTenants(fetchImpl,base,admin);
   if(!refreshed.has(domain))
    throw Error(`TENANT_NOT_PRESENT_AFTER_CREATE_${brand}_MANUAL_REVIEW`);
  }
  // The super-tenant tenant-management API is the authoritative root inventory.
  // Tenant-scoped Basic authentication may be disabled, so it is NOT an ownership test.
  const tenantResult=await jsonCall(fetchImpl,base,
   `${ROOT_TENANT_LIST}/domain/${encodeURIComponent(domain)}`,{auth:admin});
  const tenant=tenantResult.data;
  if(tenantResult.status!==200||tenant?.domain!==domain||!ID.test(tenant?.id||'')||
     tenant?.lifecycleStatus?.activated!==true)
   throw Error(`ROOT_TENANT_READBACK_FAILED_${brand}`);
  if(item.tenantId&&item.tenantId!==tenant.id)
   throw Error(`ROOT_TENANT_ID_CHANGED_${brand}_MANUAL_REVIEW`);
  const ownersResult=await jsonCall(fetchImpl,base,
   `${ROOT_TENANT_LIST}/${encodeURIComponent(tenant.id)}/owners`,{auth:admin});
  if(ownersResult.status!==200||!Array.isArray(ownersResult.data))
   throw Error(`ROOT_OWNER_LIST_INVALID_${brand}`);
  const matches=ownersResult.data.filter(x=>x?.username===item.owner.username&&ID.test(x?.id||''));
  if(matches.length!==1)
   throw Error(`ROOT_OWNER_MISMATCH_${brand}_MANUAL_REVIEW`);
  const ownerId=matches[0].id;
  if(item.ownerId&&item.ownerId!==ownerId)
   throw Error(`ROOT_OWNER_ID_CHANGED_${brand}_MANUAL_REVIEW`);
  if(item.ownerRecovery&&item.ownerRecovery.state!=='update-started')
   throw Error(`ROOT_OWNER_RECOVERY_STATE_INVALID_${brand}_MANUAL_REVIEW`);
  if(item.ownerRecovery&&(item.ownerRecovery.tenantId!==tenant.id||
      item.ownerRecovery.ownerId!==ownerId))
   throw Error(`ROOT_OWNER_RECOVERY_ID_MISMATCH_${brand}_MANUAL_REVIEW`);
  const detailResult=await jsonCall(fetchImpl,base,
   `${ROOT_TENANT_LIST}/${encodeURIComponent(tenant.id)}/owners/${encodeURIComponent(ownerId)}`,
   {auth:admin});
  const detail=detailResult.data;
  if(detailResult.status!==200||detail?.id!==ownerId||detail?.username!==item.owner.username||
     !['email','firstname','lastname'].every(k=>detail[k]===item.owner[k]))
   throw Error(`ROOT_OWNER_DETAILS_MISMATCH_${brand}_MANUAL_REVIEW`);
  // Durable identity proof is NOT a password, session or API-permission proof.
  item.tenantId=tenant.id;item.ownerId=ownerId;
  item.state='created';item.ownerAuthentication='NOT_VERIFIED';
  privateWrite(stateFile,s);
  live.add(domain);
  emit(`ROOT_TENANT_INVENTORY_VERIFIED ${brand} ${domain} (admin login NOT_VERIFIED)`);
 }
 // Don't convert root-tenant success into a false SSO or OIDC acceptance pass.
 s.tenantProvisioning='TWO_ROOT_TENANTS_CREATED_OR_VERIFIED';
 if(onlyTenants){privateWrite(stateFile,s);return s;}
 // Tenant APIs reject Basic authentication by tenant policy in this live instance.
 // Don't attempt the four OIDC application writes without a scoped management token.
 s.acceptance='NOT_VERIFIED';privateWrite(stateFile,s);
 throw Error('TENANT_OIDC_MANAGEMENT_OAUTH_NOT_CONFIGURED');
 let urls;
 try{urls=sectorUris(env)}catch(e){
  if(!e.message.includes('REQUIRED_TWO_DISTINCT_HTTPS_HOSTS'))throw e;
  s.pairwise='PENDING_STABLE_HTTPS_SECTOR_HOSTS';privateWrite(stateFile,s);
  emit('PAIRWISE_PENDING_STABLE_HTTPS_SECTOR_HOSTS (no tunnels started)');
  return s;
 }
 // Before any brand app write, retrieve BOTH external HTTPS documents.
 await assertSectorDocuments(plan,env,sectorFetchImpl);
 for(const brand of BRANDS){
  const domain=domains[brand],owner=s.tenants[brand].owner;
  const tenantAuth={username:`${owner.username}@${domain}`,password:owner.password};
  const apps=plan.apps.filter(x=>x.brand===brand);
  for(const app of apps){
   const previous=s.clients[app.key];
   if(previous){
    if(previous.state==='create-started'||!previous.id)throw Error(`UNCERTAIN_CLIENT_WRITE_${app.key}_MANUAL_REVIEW`);
    if(previous.tenant!==domain)throw Error('APP_TENANT_MISMATCH');
    await jsonCall(fetchImpl,base,tenantPath(domain,`/api/server/v1/applications/${encodeURIComponent(previous.id)}`),{auth:tenantAuth});
    emit(`TENANT_OIDC_VERIFIED ${app.key} ${domain}`);
    continue;
   }
   // Keep an explicit journal entry before a remote create. Unknown HTTP
   // outcome can NOT be retried by name or adopted without operator review.
   s.clients[app.key]={tenant:domain,state:'create-started',callback:app.callback,sectorUri:urls[brand]};privateWrite(stateFile,s);
   let created;try{created=await jsonCall(fetchImpl,base,tenantPath(domain,'/api/server/v1/applications'),{
    method:'POST',auth:tenantAuth,payload:clientPayload(app,urls[brand])});}
   catch(e){
    // For a definite 4xx rejection, no client was created. A timeout or 5xx
    // may have committed, so retain the journal and demand manual review.
    if(e.status>=400&&e.status<500&&e.status!==409){delete s.clients[app.key];privateWrite(stateFile,s);}
    throw e;
   }
   const id=responseId(created);
   s.clients[app.key].id=id;s.clients[app.key].state='created';privateWrite(stateFile,s);
   emit(`TENANT_OIDC_CREATED ${app.key} ${domain} ${id}`);
  }
 }
 // Retrieve OIDC protocol/client credentials only AFTER saving all IDs.
 for(const app of plan.apps.filter(x=>x.brand!=='workload')){
  const r=s.clients[app.key];
  if(r.state==='create-started')throw Error(`UNCERTAIN_CLIENT_WRITE_${app.key}_MANUAL_REVIEW`);
  const owner=s.tenants[app.brand].owner;
  const result=await jsonCall(fetchImpl,base,tenantPath(r.tenant,`/api/server/v1/applications/${encodeURIComponent(r.id)}/inbound-protocols/oidc`),
   {auth:{username:`${owner.username}@${r.tenant}`,password:owner.password}});
  if(!result.data?.clientId||!result.data?.clientSecret)throw Error(`TENANT_OIDC_SECRET_UNAVAILABLE_${app.key}`);
  if(result.data?.subject?.subjectType!=='pairwise')throw Error(`TENANT_OIDC_NOT_PAIRWISE_${app.key}`);
  if(result.data?.subject?.sectorIdentifierUri!==r.sectorUri)throw Error(`TENANT_OIDC_SECTOR_MISMATCH_${app.key}`);
  r.clientId=result.data.clientId;r.clientSecret=result.data.clientSecret;r.state='verified';privateWrite(stateFile,s);
 }
 // No statement that cross-tenant canonical identity or shared SSO works.
 const ids=Object.values(s.clients).map(x=>x.clientId);
 if(new Set(ids).size!==4)throw Error('TENANT_CLIENT_IDS_NOT_DISTINCT');
 s.pairwise='FOUR_BRAND_CLIENTS_CONFIGURED_NOT_TOKEN_VERIFIED';
 s.acceptance='NOT_VERIFIED';privateWrite(stateFile,s);
 emit('FOUR_TENANT_OIDC_CLIENTS_CONFIGURED — SSO, signed pairwise ID tokens and login flow NOT_VERIFIED');
 return s;
}
export function tenantStatus({env=process.env,stateFile=statePath}={}){
 const base=origin(env.WSO2_BASE_URL||'');const domainEnv={aurora:env.WSO2_AURORA_ROOT_TENANT||'aurora.identity.test',brisa:env.WSO2_BRISA_ROOT_TENANT||'brisa.identity.test'};
 const s=readState(stateFile,base,domainEnv);
 return {tenants:BRANDS.map(brand=>({brand,domain:s.tenants[brand]?.domain||domainEnv[brand],state:s.tenants[brand]?.state||'MISSING',ownerAuthentication:s.tenants[brand]?.ownerAuthentication||'NOT_VERIFIED',ownerRecovery:s.tenants[brand]?.ownerRecovery?.state||'NOT_STARTED'})),
  oidcClients:Object.entries(s.clients).map(([key,c])=>({key,tenant:c.tenant,state:c.state,appId:c.id||null,sectorUri:c.sectorUri})),
  tenantProvisioning:s.tenantProvisioning||'NOT_STARTED',pairwise:s.pairwise||'NOT_STARTED',crossTenantSSO:'NOT_VERIFIED',signedPairwiseSub:'NOT_VERIFIED',identityBff:'NOT_INTEGRATED',acceptance:'NOT_VERIFIED'};
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(fileURLToPath(import.meta.url))){
 const cmd=process.argv[2]||'bootstrap';
 try{
  if(cmd==='status')console.log(JSON.stringify(tenantStatus(),null,2));
  else if(cmd==='auth-check')console.log(JSON.stringify(await tenantApiPreflight(),null,2));
  else if(cmd==='bootstrap'||cmd==='tenants-only'){const result=await bootstrapTenants({onlyTenants:cmd==='tenants-only'});
   if(cmd==='bootstrap'&&result.pairwise!=='FOUR_BRAND_CLIENTS_CONFIGURED_NOT_TOKEN_VERIFIED')process.exitCode=2;}
  else throw Error('EXPECTED_bootstrap_tenants-only_auth-check_status');
 }catch(e){console.error('TENANT_BOOTSTRAP_ERROR:',e.message);process.exitCode=1}
}
