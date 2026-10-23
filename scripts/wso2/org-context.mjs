/** WSO2 7.3 child-organization provisioning with a parent-scoped M2M token.
 * Does not use a root management bearer to create a nested organization.
 */
import {origin} from './api.mjs';
import {authorizedScopeNames} from './management-token.mjs';

export const ORG_LEVEL_API='/o/api/server/v1/organizations';
export const ORG_LEVEL_SCOPES=Object.freeze([
 'internal_org_organization_create',
 'internal_org_organization_view',
 'internal_org_organization_delete',
]);

export function findOrgLevelResource(data){
 const values=Array.isArray(data)?data:
  (data?.apiResources||data?.resources||data?.list);
 if(!Array.isArray(values))throw Error('ORG_LEVEL_RESOURCE_LIST_UNRECOGNIZED');
 const matched=values.filter(x=>x.identifier===ORG_LEVEL_API);
 if(matched.length!==1||!matched[0].id)throw Error('ORG_LEVEL_RESOURCE_NOT_UNIQUELY_FOUND');
 const permitted=new Set((matched[0].scopes||[]).map(s=>typeof s==='string'?s:s?.name||s?.scope));
 if(permitted.size && ORG_LEVEL_SCOPES.some(s=>!permitted.has(s)))
  throw Error('ORG_LEVEL_RESOURCE_MISSING_REQUIRED_SCOPES');
 return matched[0];
}

export async function authorizeOrgLevel(api,appId){
 const resource=findOrgLevelResource((await api.listApiResources(ORG_LEVEL_API)).data);
 const response=(await api.getAuthorizedApis(appId)).data;
 const authorized=Array.isArray(response)?response:(response?.authorizedAPIs||response?.authorizedApis||response?.apis||response?.resources);
 if(!Array.isArray(authorized))throw Error('ORG_LEVEL_AUTHORIZED_LIST_UNRECOGNIZED');
 const existing=authorized.find(a=>a.id===resource.id);
 if(existing){
  const granted=authorizedScopeNames(existing);
  if(!ORG_LEVEL_SCOPES.every(s=>granted.has(s)))throw Error('ORG_LEVEL_SCOPES_PARTIALLY_AUTHORIZED');
  return 'VERIFIED';
 }
 await api.authorizeApi(appId,{id:resource.id,policyIdentifier:'RBAC',scopes:ORG_LEVEL_SCOPES});
 return 'AUTHORIZED';
}

/** Shares only with the parent; no global child sharing. Checks already shared list. */
export async function shareWithParent(api,appId,parentId){
 if(!/^[a-zA-Z0-9-]{5,128}$/.test(parentId))throw Error('ORG_PARENT_ID_INVALID');
 const existing=(await api.listSharedOrgs(appId)).data;
 const entries=Array.isArray(existing?.organizations)?existing.organizations:(Array.isArray(existing)?existing:[]);
 if(entries.some(x=>x.id===parentId||x.orgId===parentId))return 'SHARED_VERIFIED';
 // The 7.3 API has a synchronous legacy endpoint for sharing a single app.
 // It is deprecated, but documented for supported 7.3 deployments. Fail closed on 4xx.
 await api.shareAppWithOrgs(appId,{shareWithAllChildren:false,sharedOrganizations:[parentId]});
 return 'SHARED';
}

export async function scopedOrgToken({base,parentId,clientId,clientSecret,fetchImpl=fetch}){
 const server=origin(base);
 if(!/^[a-zA-Z0-9-]{5,128}$/.test(parentId))throw Error('ORG_PARENT_ID_INVALID');
 if(!clientId||!clientSecret)throw Error('ORG_LEVEL_M2M_CREDENTIALS_MISSING');
 const path=`/t/carbon.super/o/${encodeURIComponent(parentId)}/oauth2/token`;
 const url=new URL(path,server);
 const req=await fetchImpl(url.href,{
  method:'POST',redirect:'error',headers:{
   Authorization:'Basic '+Buffer.from(`${clientId}:${clientSecret}`).toString('base64'),
   Accept:'application/json','Content-Type':'application/x-www-form-urlencoded'},
  body:new URLSearchParams({grant_type:'client_credentials',scope:ORG_LEVEL_SCOPES.join(' ')}).toString(),
  signal:AbortSignal.timeout(15000)
 });
 const raw=await req.text();if(raw.length>32768)throw Error('ORG_LEVEL_TOKEN_RESPONSE_OVERSIZE');
 let data;try{data=JSON.parse(raw)}catch{throw Error('ORG_LEVEL_TOKEN_NOT_JSON')}
 if(!req.ok||!data?.access_token)throw Error(`ORG_LEVEL_TOKEN_${req.status}_${data?.error||'REJECTED'}`);
 const granted=new Set(String(data.scope||'').split(/\s+/).filter(Boolean));
 if(!ORG_LEVEL_SCOPES.every(x=>granted.has(x)))throw Error('ORG_LEVEL_TOKEN_SCOPES_MISSING');
 if(data.token_type&&data.token_type.toLowerCase()!=='bearer')throw Error('ORG_LEVEL_TOKEN_NOT_BEARER');
 return data.access_token;
}
