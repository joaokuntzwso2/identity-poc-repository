/**
 * Tenant-isolated WSO2 IS 7.3 management control plane.
 * No global Basic enablement, container restart, tenant creation, owner resets,
 * or implicit adoption. All writes have durable intent journals.
 * Management admin Basic is a TEMPORARY bootstrap credential, not a token.
 */
import {randomBytes} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync, openSync, closeSync, unlinkSync} from 'node:fs';
import {dirname, resolve} from 'node:path';

const BRANDS = ['aurora','brisa'];
const REQUIRED = Object.freeze([
  'internal_application_mgt_view',
  'internal_application_mgt_create',
  'internal_application_mgt_client_secret_view'
]);
const API_ID = '/api/server/v1/applications';
const ID = /^[a-zA-Z0-9-]{5,128}$/;
const RESOURCE_ID = /^[A-Za-z0-9_-]{5,256}={0,2}$/;
const DOMAIN = /^[a-z][a-z0-9.-]{2,120}$/;

export function assertLab(env){
  const base = new URL(env.WSO2_BASE_URL || '');
  if(base.protocol!=='https:' || base.port!=='9443' || !['localhost','127.0.0.1'].includes(base.hostname) ||
      base.pathname!=='/' || base.search || base.hash || base.username || base.password)
    throw Error('LOCALHOST_HTTPS_9443_REQUIRED');
  if(env.WSO2_LAB_CONFIRM!=='CREATE_SYNTHETIC_RESOURCES') throw Error('EXPLICIT_LAB_WRITE_CONSENT_REQUIRED');
  return {base:base.origin, domains:{
    aurora:env.WSO2_AURORA_ROOT_TENANT||'aurora.identity.test',
    brisa:env.WSO2_BRISA_ROOT_TENANT||'brisa.identity.test'
  }};
}

export function readPrivate(path, fallback){
  if(!existsSync(path))return fallback;
  const s=JSON.parse(readFileSync(path,'utf8'));
  if(!s || typeof s!=='object' || Array.isArray(s))throw Error('PRIVATE_JOURNAL_INVALID');
  return s;
}
export function privateWrite(path, obj){
  mkdirSync(dirname(path),{recursive:true,mode:0o700});
  const tmp=`${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  try{
    writeFileSync(tmp,JSON.stringify(obj,null,2)+'\n',{mode:0o600,flag:'wx'});
    chmodSync(tmp,0o600);
    renameSync(tmp,path);
  }catch(e){try{unlinkSync(tmp)}catch{}throw e}
}

export function ownerCredential(tenant, brand, domain){
  if(!tenant || tenant.state!=='created' || tenant.owned!==true || tenant.domain!==domain ||
      !ID.test(tenant.tenantId||'') || !ID.test(tenant.ownerId||'') ||
      tenant.owner?.username!=='labtenantadmin' || !tenant.owner.password)
    throw Error(`OWNERSHIP_JOURNAL_NOT_VERIFIED_${brand}`);
  if(tenant.ownerRecovery){
    if(brand!=='aurora' || tenant.ownerRecovery.state!=='update-started' ||
        tenant.ownerRecovery.tenantId!==tenant.tenantId || tenant.ownerRecovery.ownerId!==tenant.ownerId ||
        typeof tenant.ownerRecovery.candidatePassword!=='string')
      throw Error(`UNRESOLVED_OWNER_RECOVERY_STATE_${brand}`);
  }
  return {
    username:`${tenant.owner.username}@${domain}`,
    password:tenant.ownerRecovery?.candidatePassword ?? tenant.owner.password
  };
}
export function authHeader({basic,bearer}){
  if(Boolean(basic)===Boolean(bearer))throw Error('EXACTLY_ONE_AUTH_MECHANISM_REQUIRED');
  if(basic){if(!basic.username||!basic.password)throw Error('BASIC_CREDENTIALS_MISSING');
    return 'Basic '+Buffer.from(`${basic.username}:${basic.password}`,'utf8').toString('base64');}
  if(typeof bearer!=='string'||!bearer)throw Error('EMPTY_BEARER_TOKEN');
  return 'Bearer '+bearer;
}

export async function call(fetchImpl, base, suffix,{method='GET',basic,bearer,payload,form}={}){
  if(!suffix.startsWith('/t/') && suffix!=='/oauth2/token')throw Error('TENANT_API_ROUTE_REQUIRED');
  if(method!=='GET' && !['POST','PATCH'].includes(method))throw Error('API_METHOD_NOT_ALLOWED');
  const res=await fetchImpl(base+suffix,{method,redirect:'error',signal:AbortSignal.timeout(15000),
    headers:{Authorization:authHeader({basic,bearer}),Accept:'application/json',
      ...(payload?{'Content-Type':'application/json'}:{}),
      ...(form?{'Content-Type':'application/x-www-form-urlencoded'}:{})},
    ...(payload?{body:JSON.stringify(payload)}:{}),...(form?{body:new URLSearchParams(form).toString()}:{})});
  const raw=await res.text();
  if(raw.length>200000)throw Error('RESPONSE_TOO_LARGE');
  let data={}; if(raw.trim())try{data=JSON.parse(raw)}catch{throw Error(`RESPONSE_NOT_JSON_${res.status}`)}
  if(!res.ok){const e=Error(`WSO2_HTTP_${res.status}`);e.status=res.status;throw e}
  return {status:res.status,data,location:res.headers.get('location')};
}
const tp=(domain,suffix)=>`/t/${encodeURIComponent(domain)}${suffix}`;
const appId=(result)=>{
  const candidate=result.data?.id || result.location?.split('?')[0].split('/').pop();
  if(!ID.test(candidate||''))throw Error('APP_ID_NOT_RETURNED_MANUAL_REVIEW');
  return candidate;
};
const resources=(data)=>{
  if(Array.isArray(data))return data;
  for(const k of ['APIResources','apiResources','resources','list'])if(Array.isArray(data?.[k]))return data[k];
  // A verified empty catalog may omit its collection property (as tenant list
  // responses on this server do). Never treat a nonzero total as empty.
  if(data && typeof data==='object' && !Array.isArray(data) &&
     data.totalResults===0 && Array.isArray(data.links) && data.links.length===0 &&
     Object.keys(data).every(k=>['totalResults','links','count','startIndex'].includes(k)) &&
     (!Object.hasOwn(data,'count')||data.count===0))return [];
  throw Error('API_RESOURCES_RESPONSE_SHAPE_UNKNOWN');
};
const authEntries=(data)=>{
  if(Array.isArray(data))return data;
  for(const k of ['authorizedAPIs','authorizedApis','apis','resources'])if(Array.isArray(data?.[k]))return data[k];
  throw Error('AUTHORIZED_API_RESPONSE_SHAPE_UNKNOWN');
};
const scopesOf=(entry)=>{
  const items=entry?.authorizedScopes??entry?.scopes;
  if(!Array.isArray(items))throw Error('AUTHORIZED_SCOPES_RESPONSE_SHAPE_UNKNOWN');
  const scopes=items.map(x=>typeof x==='string'?x:x?.name);
  if(scopes.some(x=>typeof x!=='string'||!x))throw Error('AUTHORIZED_SCOPES_RESPONSE_SHAPE_UNKNOWN');
  return new Set(scopes);
};
/**
 * WSO2's API-resource catalog uses cursor pagination and its list items need
 * not contain scopes. Resolve the exact system API and read scopes from the
 * dedicated API if necessary. This is entirely GET-only and always tenant-local.
 */
export async function discoverApplicationResource({fetchImpl=fetch,base,domain,basic}){
  const root=tp(domain,'/api/server/v1');
  const path=root+'/api-resources';
  const seen=new Map();
  function collect(data){
    const entries=resources(data);
    for(const entry of entries){
      if(entry?.identifier!==API_ID)continue;
      if(!RESOURCE_ID.test(entry.id||''))throw Error('APPLICATION_API_RESOURCE_INVALID_ID');
      if(seen.has(entry.id) && JSON.stringify(seen.get(entry.id))!==JSON.stringify(entry))
        throw Error('APPLICATION_API_RESOURCE_INCONSISTENT_DUPLICATE');
      seen.set(entry.id,entry);
    }
    if(seen.size>1)throw Error('APPLICATION_API_RESOURCE_AMBIGUOUS');
    return entries.length;
  }
  function cursor(data){
    if(!Array.isArray(data?.links))return null;
    const links=data.links.filter(x=>['next','after'].includes(x?.rel));
    if(links.length>1)throw Error('APPLICATION_API_RESOURCE_MULTIPLE_CURSORS');
    if(!links.length)return null;
    if(typeof links[0].href!=='string')throw Error('APPLICATION_API_RESOURCE_CURSOR_INVALID');
    // A server-supplied URL is NEVER followed directly; only its cursor is used.
    let parsed;
    try{parsed=new URL(links[0].href,base)}catch{throw Error('APPLICATION_API_RESOURCE_CURSOR_INVALID')}
    if(parsed.origin!==base)throw Error('APPLICATION_API_RESOURCE_CURSOR_ORIGIN_INVALID');
    if(parsed.pathname!==path && parsed.pathname!=='/api/server/v1/api-resources')
      throw Error('APPLICATION_API_RESOURCE_CURSOR_PATH_INVALID');
    const after=parsed.searchParams.getAll('after');
    if(after.length!==1 || !after[0] || after[0].length>512)
      throw Error('APPLICATION_API_RESOURCE_CURSOR_VALUE_INVALID');
    return after[0];
  }
  const first=await call(fetchImpl,base,path+'?limit=100',{basic});
  collect(first.data);
  if(seen.size===0){
    // Official API supports `filter=identifier eq ...`. This avoids relying on
    // the first unfiltered page for installations with many API resources.
    const query=new URLSearchParams({filter:`identifier eq ${API_ID}`,limit:'20'}).toString();
    const filtered=await call(fetchImpl,base,path+'?'+query,{basic});
    collect(filtered.data);
  }
  if(seen.size===0){
    // Fall back to bounded cursor pagination when filters are ineffective.
    let current=first.data;
    const cursors=new Set();
    for(let page=0;page<25 && seen.size===0;page++){
      const after=cursor(current);
      if(!after)break;
      if(cursors.has(after))throw Error('APPLICATION_API_RESOURCE_CURSOR_LOOP');
      cursors.add(after);
      const next=await call(fetchImpl,base,path+'?'+new URLSearchParams({limit:'100',after}).toString(),{basic});
      collect(next.data);
      current=next.data;
    }
    if(seen.size===0 && cursor(current))throw Error('APPLICATION_API_RESOURCE_PAGE_LIMIT');
  }
  if(seen.size!==1)throw Error('APPLICATION_API_RESOURCE_NOT_FOUND');
  const resource=[...seen.values()][0];
  const id=resource.id;
  const names=list=>Array.isArray(list)
    ?new Set(list.map(x=>typeof x==='string'?x:x?.name).filter(x=>typeof x==='string'&&x))
    :new Set();
  let scopes=names(resource.scopes);
  if(!REQUIRED.every(s=>scopes.has(s))){
    const detail=await call(fetchImpl,base,path+'/'+encodeURIComponent(id),{basic});
    if(detail.data?.id!==id || detail.data?.identifier!==API_ID)
      throw Error('APPLICATION_API_RESOURCE_DETAIL_MISMATCH');
    scopes=names(detail.data.scopes);
  }
  if(!REQUIRED.every(s=>scopes.has(s))){
    const response=await call(fetchImpl,base,path+'/'+encodeURIComponent(id)+'/scopes',{basic});
    scopes=names(response.data);
  }
  if(!REQUIRED.every(s=>scopes.has(s)))throw Error('APPLICATION_API_SCOPES_UNAVAILABLE');
  return {id,identifier:API_ID};
}

function verifyAdminJournal(rootJournal, domains){
  if(rootJournal?.tenantProvisioning!=='TWO_ROOT_TENANTS_CREATED_OR_VERIFIED')
    throw Error('ROOT_TENANT_JOURNAL_NOT_READY');
  const creds={};
  for(const brand of BRANDS){
    if(!DOMAIN.test(domains[brand]))throw Error('TENANT_DOMAIN_INVALID');
    creds[brand]=ownerCredential(rootJournal.tenants?.[brand],brand,domains[brand]);
  }
  return creds;
}

export async function adminPreflight({fetchImpl=fetch,base,domains,rootJournal}){
  const creds=verifyAdminJournal(rootJournal,domains);
  // Read-only preflight for BOTH brands BEFORE the FIRST M2M write.
  for(const brand of BRANDS){
    try{
      const r=await call(fetchImpl,base,tp(domains[brand],'/api/server/v1/applications?limit=1'),{basic:creds[brand]});
      if(r.status!==200)throw Error(`ADMIN_PREFLIGHT_HTTP_UNEXPECTED_${brand}`);
    }catch(e){
      const reason=e.status===401?'ADMIN_CREDENTIALS_OR_BASIC_DISABLED':e.status===403?'ADMIN_LACKS_APP_PERMISSION':e.message;
      throw Error(`TENANT_ADMIN_BOOTSTRAP_UNAVAILABLE_${brand}_${reason}`);
    }
  }
  return creds;
}

export async function requestTenantToken({fetchImpl=fetch,base,domain,clientId,clientSecret}){
  if(!clientId||!clientSecret)throw Error('CLIENT_CREDENTIALS_MISSING');
  const suffix=tp(domain,'/oauth2/token');
  const result=await call(fetchImpl,base,suffix,{method:'POST',basic:{username:clientId,password:clientSecret},
    form:{grant_type:'client_credentials',scope:REQUIRED.join(' ')}});
  if(typeof result.data?.access_token!=='string'||!result.data.access_token||
     String(result.data.token_type||'').toLowerCase()!=='bearer')throw Error('TOKEN_RESPONSE_NOT_BEARER');
  const granted=new Set(String(result.data.scope||'').split(/\s+/).filter(Boolean));
  if(!REQUIRED.every(x=>granted.has(x)))throw Error('MANAGEMENT_SCOPES_NOT_GRANTED');
  const bearer=result.data.access_token;
  const probe=await call(fetchImpl,base,tp(domain,'/api/server/v1/applications?limit=1'),{bearer});
  if(probe.status!==200)throw Error('MANAGEMENT_BEARER_READBACK_FAILED');
  return bearer;
}

function m2mName(brand){return `Identity Lab ${brand.toUpperCase()} Management Bootstrap`}
/** Creates lab-owned management apps; caller must arrange temporary Basic availability. */
export async function seedManagement({fetchImpl=fetch,base,domains,rootJournal,stateFile,emit=()=>{}}){
  const creds=await adminPreflight({fetchImpl,base,domains,rootJournal});
  // Resolve both resources BEFORE creating even one new management app.
  const appResources={};
  for(const brand of BRANDS){
    appResources[brand]=await discoverApplicationResource({fetchImpl,base,domain:domains[brand],basic:creds[brand]});
  }
  const state=readPrivate(stateFile,{schemaVersion:1,base,management:{}});
  if(state.base!==base||state.schemaVersion!==1||!state.management||Array.isArray(state.management))
    throw Error('MANAGEMENT_JOURNAL_CONTEXT_MISMATCH');
  const bearerTokens={};
  for(const brand of BRANDS){
    const domain=domains[brand];const name=m2mName(brand);const admin=creds[brand];
    let item=state.management[brand];
    if(item && (item.domain!==domain||item.name!==name))throw Error(`MANAGEMENT_APP_STATE_MISMATCH_${brand}`);
    if(!item){
      item={domain,name,state:'prepared'};state.management[brand]=item;privateWrite(stateFile,state);
    }
    const root=tp(domain,'/api/server/v1');
    if(item.apiResourceId && item.apiResourceId!==appResources[brand].id)
      throw Error(`MANAGEMENT_API_RESOURCE_ID_CHANGED_${brand}`);
    if(item.state==='prepared'){
      item.state='create-started';privateWrite(stateFile,state);
      const result=await call(fetchImpl,base,root+'/applications',{method:'POST',basic:admin,payload:{
        name,description:'Lab-owned scoped bootstrap client; never customer-facing',isManagementApp:true,
        inboundProtocolConfiguration:{oidc:{grantTypes:['client_credentials'],publicClient:false}}
      }});
      if(result.status!==201)throw Error(`MANAGEMENT_CREATE_NOT_201_${brand}_MANUAL_REVIEW`);
      item.id=appId(result);item.state='created';privateWrite(stateFile,state);
    }
    if(!ID.test(item.id||''))throw Error(`MANAGEMENT_CREATE_UNCERTAIN_${brand}_MANUAL_REVIEW`);
    const existing=await call(fetchImpl,base,root+`/applications/${encodeURIComponent(item.id)}`,{basic:admin});
    if(existing.data?.name!==name || existing.data?.isManagementApp!==true)
      throw Error(`MANAGEMENT_APP_READBACK_MISMATCH_${brand}`);
    if(item.state==='created'||item.state==='authorization-started'){
      const resource=appResources[brand];
      if(item.apiResourceId && item.apiResourceId!==resource.id)
        throw Error(`MANAGEMENT_API_RESOURCE_ID_CHANGED_${brand}`);
      const authUrl=root+`/applications/${encodeURIComponent(item.id)}/authorized-apis`;
      const authorized=await call(fetchImpl,base,authUrl,{basic:admin});
      const matches=authEntries(authorized.data).filter(x=>x.id===resource.id);
      if(matches.length>1)throw Error(`DUPLICATE_AUTHORIZED_API_${brand}`);
      if(matches.length===1){
        if(!REQUIRED.every(x=>scopesOf(matches[0]).has(x)))throw Error(`MANAGEMENT_PARTIAL_AUTH_MANUAL_REVIEW_${brand}`);
        item.state='authorized';item.apiResourceId=resource.id;privateWrite(stateFile,state);
      }else{
        // An earlier POST may have committed even if the process observed an
        // unexpected HTTP status or lost the response. Never send a second POST
        // while the journal says authorization-started. We already performed
        // the authoritative GET above; a missing authorization requires review.
        if(item.state==='authorization-started')
          throw Error(`MANAGEMENT_AUTH_OUTCOME_UNCERTAIN_${brand}_READBACK_MISSING_MANUAL_REVIEW`);
        item.state='authorization-started';item.apiResourceId=resource.id;privateWrite(stateFile,state);
        const result=await call(fetchImpl,base,authUrl,{method:'POST',basic:admin,payload:{
          id:resource.id,policyIdentifier:'RBAC',scopes:REQUIRED
        }});
        // API docs specify HTTP 201 for create. A different 2xx status is not
        // proof of authorization; save only the HTTP status (never response
        // bodies or credentials) and require a full scopes readback.
        item.authorizationHttpStatus=result.status;
        privateWrite(stateFile,state);
        const read=await call(fetchImpl,base,authUrl,{basic:admin});
        const match=authEntries(read.data).filter(x=>x.id===resource.id);
        if(match.length!==1 || !REQUIRED.every(x=>scopesOf(match[0]).has(x)))
          throw Error(`MANAGEMENT_AUTH_NOT_CONFIRMED_${brand}_HTTP_${result.status}_MANUAL_REVIEW`);
        item.state='authorized';privateWrite(stateFile,state);
      }
    }
    if(!['authorized','verified'].includes(item.state))throw Error(`MANAGEMENT_JOURNAL_STATE_INVALID_${brand}`);
    const protocol=await call(fetchImpl,base,root+`/applications/${encodeURIComponent(item.id)}/inbound-protocols/oidc`,{basic:admin});
    if(!protocol.data?.clientId||!protocol.data?.clientSecret)
      throw Error(`MANAGEMENT_CLIENT_CREDENTIALS_NOT_RETURNED_${brand}`);
    if(item.clientId && item.clientId!==protocol.data.clientId)
      throw Error(`MANAGEMENT_CLIENT_ID_CHANGED_${brand}`);
    item.clientId=protocol.data.clientId;item.clientSecret=protocol.data.clientSecret;
    item.state='authorized';privateWrite(stateFile,state);
    bearerTokens[brand]=await requestTenantToken({fetchImpl,base,domain,
      clientId:item.clientId,clientSecret:item.clientSecret});
    item.state='verified';privateWrite(stateFile,state);
    emit(`TENANT_MANAGEMENT_BEARER_VERIFIED ${brand} ${domain}`);
  }
  return {bearerTokens,state};
}

export async function verifyManagement({fetchImpl=fetch,base,domains,stateFile}){
  const state=readPrivate(stateFile,null);
  if(state?.base!==base||state?.schemaVersion!==1)throw Error('MANAGEMENT_JOURNAL_MISSING_OR_WRONG_BASE');
  const result={};
  for(const brand of BRANDS){
    const item=state.management?.[brand];
    if(item?.state!=='verified'||item.domain!==domains[brand]||!ID.test(item.id||'') ||
       !item.clientId||!item.clientSecret)throw Error(`MANAGEMENT_NOT_VERIFIED_${brand}`);
    result[brand]=await requestTenantToken({fetchImpl,base,domain:item.domain,
      clientId:item.clientId,clientSecret:item.clientSecret});
  }
  return result;
}

/** Never pass management credentials directly to UI or browser. */
export function publicControlPlane({base,domains,rootJournal,managementJournal,clients={}}){
  return {schemaVersion:1,authority:'WSO2_IDENTITY_SERVER',environment:'local-lab',
    previewIsLive:false, generatedAt:new Date().toISOString(),
    brands:Object.fromEntries(BRANDS.map(brand=>{
      const domain=domains[brand],manager=managementJournal?.management?.[brand];
      const brandClients=Object.entries(clients).filter(([,v])=>v?.tenant===domain)
        .map(([key,v])=>({key,appId:v.id||null,clientId:v.clientId||null,
          callback:v.callback||null,sectorUri:v.sectorUri||null,
          provisioned:v.state==='verified'}));
      return [brand,{domain,issuer:`${base}/t/${domain}/oauth2/token`,
        tenantInventoryVerified:rootJournal?.tenants?.[brand]?.state==='created',
        managementBearerVerified:manager?.state==='verified',
        oidcClients:brandClients,
        browserLoginVerified:null,
        ssoVerified:false,pairwiseTokenVerified:false}];
    }))};
}
