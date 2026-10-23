import {createHash} from 'node:crypto';
export function origin(raw){
 const u=new URL(raw);
 if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw Error('WSO2_BASE_MUST_BE_HTTPS_ORIGIN');
 return u.origin;
}
export function makeClient({base,adminUser,adminPassword,orgToken,fetchImpl=fetch}={}){
 const server=origin(base);
 if(!adminUser||!adminPassword)throw Error('ADMIN_CREDENTIALS_REQUIRED');
 const basic=`Basic ${Buffer.from(`${adminUser}:${adminPassword}`).toString('base64')}`;
 async function request(method,path,payload,auth='basic'){
  if(!path.startsWith('/')||path.startsWith('//')||path.includes('..')||path.includes('\\'))throw Error('INVALID_MANAGEMENT_PATH');
  if(auth==='org'&&!orgToken)throw Error('ORG_BEARER_REQUIRED');
  const uri=new URL(path,server);
  if(uri.origin!==server)throw Error('MANAGEMENT_ORIGIN_MISMATCH');
  const r=await fetchImpl(uri.href,{method,headers:{Accept:'application/json',...(payload?{'Content-Type':'application/json'}:{}),Authorization:auth==='org'?`Bearer ${orgToken}`:basic},body:payload?JSON.stringify(payload):undefined,redirect:'error',signal:AbortSignal.timeout(15000)});
  const text=await r.text();if(text.length>524288)throw Error('WSO2_REPLY_OVERSIZE');
  let data;try{data=text?JSON.parse(text):{}}catch{data={raw:'NON_JSON_RESPONSE'}}
  if(!r.ok){
   // Documented API error fields; bounded and scrubbed to avoid logging credentials.
   const safe=x=>String(x||'').replace(/Bearer\s+[^\s,;]+/gi,'Bearer [REDACTED]').replace(/Basic\s+[^\s,;]+/gi,'Basic [REDACTED]').slice(0,500);
   const e=new Error(`WSO2_${method}_${r.status}_${safe(data?.code||'API_ERROR')}__${safe(data?.message)}__${safe(data?.description)}__trace_${safe(data?.traceId)}`);e.status=r.status;throw e
  }
  return {status:r.status,data,location:r.headers?.get('location')||null};
 }
 const appRoot='/api/server/v1/applications';
 return {
  getApp:id=>request('GET',`${appRoot}/${encodeURIComponent(id)}`),
  createApp:obj=>request('POST',appRoot,obj),
  listApiResources:identifier=>request('GET',`/api/server/v1/api-resources?filter=${encodeURIComponent(`identifier eq ${identifier}`)}&limit=100`),
  getAuthorizedApis:id=>request('GET',`${appRoot}/${encodeURIComponent(id)}/authorized-apis`),
  authorizeApi:(id,body)=>request('POST',`${appRoot}/${encodeURIComponent(id)}/authorized-apis`,body),
  getOidc:id=>request('GET',`${appRoot}/${encodeURIComponent(id)}/inbound-protocols/oidc`),
  listSharedOrgs:id=>request('GET',`${appRoot}/${encodeURIComponent(id)}/share`),
  shareAppWithOrgs:(id,body)=>request('POST',`${appRoot}/${encodeURIComponent(id)}/share`,body),
  createOrgScoped:obj=>request('POST','/o/api/server/v1/organizations',obj,'org'),
  getOrgScoped:id=>request('GET',`/o/api/server/v1/organizations/${encodeURIComponent(id)}`,undefined,'org'),
  deleteOrgScoped:id=>request('DELETE',`/o/api/server/v1/organizations/${encodeURIComponent(id)}`,undefined,'org'),
  deleteApp:id=>request('DELETE',`${appRoot}/${encodeURIComponent(id)}`),
  createUser:obj=>request('POST','/scim2/Users',obj),
  getUser:id=>request('GET',`/scim2/Users/${encodeURIComponent(id)}`),
  listRootUsersByName:username=>request('GET',`/scim2/Users?filter=${encodeURIComponent('userName eq '+JSON.stringify(username))}&count=10`),
  deleteUser:id=>request('DELETE',`/scim2/Users/${encodeURIComponent(id)}`),
  createOrg:obj=>request('POST','/api/server/v1/organizations',obj,'org'),
  deleteOrg:id=>request('DELETE',`/api/server/v1/organizations/${encodeURIComponent(id)}`,undefined,'org'),
  getOrg:id=>request('GET',`/api/server/v1/organizations/${encodeURIComponent(id)}`,undefined,'org'),
  hashOrigin:()=>createHash('sha256').update(server).digest('hex').slice(0,20)
 };
}
