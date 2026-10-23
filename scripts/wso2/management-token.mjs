/**
 * Bootstrap a short-lived root Organization Management API access token.
 * This module DOES NOT bypass WSO2 API authorization: it creates a tracked
 * management application through the administrator's management-API access,
 * grants the documented scopes, then requests a real OAuth2 token.
 */
import {origin} from './api.mjs';

export const REQUIRED_ORG_SCOPES=Object.freeze([
 'internal_organization_create',
 'internal_organization_view',
 'internal_organization_delete',
]);
const IDENTIFIER='/api/server/v1/organizations';

function unwrapResources(data){
 if(Array.isArray(data))return data;
 for(const key of ['APIResources','apiResources','resources','list'])if(Array.isArray(data?.[key]))return data[key];
 throw Error('API_RESOURCE_LIST_FORMAT_UNRECOGNIZED');
}
export function findOrgResource(data){
 const found=unwrapResources(data).filter(x=>x.identifier===IDENTIFIER);
 if(found.length!==1||!found[0].id)throw Error('ORG_API_RESOURCE_NOT_UNIQUELY_FOUND');
 return found[0];
}
function scopesFromAuthorized(data){
 if(Array.isArray(data))return data;
 for(const name of ['authorizedAPIs','authorizedApis','apis','resources'])if(Array.isArray(data?.[name]))return data[name];
 throw Error('AUTHORIZED_API_LIST_FORMAT_UNRECOGNIZED');
}

/** WSO2 GET /authorized-apis returns authorizedScopes objects ({name}),
 * while its POST request accepts scopes strings. Never treat an unreadable
 * response as successfully authorized. Legacy fixture/string shapes work too.
 */
export function authorizedScopeNames(entry){
 const values=entry?.authorizedScopes??entry?.scopes;
 if(!Array.isArray(values))throw Error('AUTHORIZED_API_SCOPES_FORMAT_UNRECOGNIZED');
 const names=values.map(x=>typeof x==='string'?x:x?.name);
 if(names.some(x=>typeof x!=='string'||!x))throw Error('AUTHORIZED_API_SCOPES_FORMAT_UNRECOGNIZED');
 return new Set(names);
}

/** Ensures app is authorized for exactly this root API (not broad admin scope grants). */
export async function authorizeOrgManagement(client,appId){
 const orgResource=findOrgResource((await client.listApiResources(IDENTIFIER)).data);
 const available=new Set((orgResource.scopes||[]).map(s=>typeof s==='string'?s:s.name||s.scope));
 if(available.size && REQUIRED_ORG_SCOPES.some(s=>!available.has(s)))
  throw Error('ORG_API_RESOURCE_MISSING_REQUIRED_SCOPES');
 const entries=scopesFromAuthorized((await client.getAuthorizedApis(appId)).data);
 const found=entries.find(x=>x.id===orgResource.id);
 if(found){
  const scopes=authorizedScopeNames(found);
  if(REQUIRED_ORG_SCOPES.every(s=>scopes.has(s)))return 'ALREADY_AUTHORIZED';
  throw Error('ORG_API_PARTIALLY_AUTHORIZED_MANUAL_REVIEW');
 }
 await client.authorizeApi(appId,{id:orgResource.id,policyIdentifier:'RBAC',scopes:REQUIRED_ORG_SCOPES});
 return 'AUTHORIZED';
}

export async function requestOrgManagementToken({base,clientId,clientSecret,fetchImpl=fetch}){
 const server=origin(base);
 if(!clientId||!clientSecret)throw Error('BOOTSTRAP_MANAGEMENT_CLIENT_CREDENTIALS_MISSING');
 const url=new URL('/oauth2/token',server);
 const header='Basic '+Buffer.from(`${clientId}:${clientSecret}`,'utf8').toString('base64');
 const res=await fetchImpl(url.href,{
  method:'POST',headers:{Authorization:header,Accept:'application/json',
   'Content-Type':'application/x-www-form-urlencoded'},
  body:new URLSearchParams({grant_type:'client_credentials',scope:REQUIRED_ORG_SCOPES.join(' ')}).toString(),
  redirect:'error',signal:AbortSignal.timeout(15000)
 });
 const raw=await res.text();
 if(raw.length>32768)throw Error('ORG_TOKEN_RESPONSE_TOO_LARGE');
 let data;try{data=JSON.parse(raw)}catch{throw Error('ORG_TOKEN_RESPONSE_NOT_JSON')}
 if(!res.ok||typeof data.access_token!=='string'||!data.access_token)
  throw Error(`ORG_TOKEN_REQUEST_${res.status}_${data.error||'UNAUTHORIZED'}`);
 const granted=new Set(String(data.scope||'').split(/\s+/).filter(Boolean));
 if(REQUIRED_ORG_SCOPES.some(s=>!granted.has(s)))throw Error('ORG_TOKEN_REQUIRED_SCOPES_NOT_GRANTED');
 if(data.token_type && data.token_type.toLowerCase()!=='bearer')throw Error('ORG_TOKEN_NOT_BEARER');
 return data.access_token;
}
