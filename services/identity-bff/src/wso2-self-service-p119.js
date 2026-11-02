/** Delegated WSO2 self-service: scoped to the logged-in bearer token's own /scim2/Me. */
import {inspectAccessToken} from './wso2-authority.js';
import {assertTrustedEndpoint} from './oidc.js';
const PATCH_SCHEMA='urn:ietf:params:scim:api:messages:2.0:PatchOp';
const EDITABLE=Object.freeze({'nickName':'nickName', 'givenName':'name.givenName',
  'familyName':'name.familyName'});
const respond=(res,status,data)=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8',
  'cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'});
  res.end(JSON.stringify(data));};
function endpoint(client){
 const issuer=new URL(client.issuer);
 if(!issuer.pathname.endsWith('/oauth2/token'))throw new Error('UNSUPPORTED_WSO2_ISSUER_PATH');
 const path=issuer.pathname.replace(/\/oauth2\/token$/,'/scim2/Me');
 return assertTrustedEndpoint(`${issuer.origin}${path}`,client.issuer);
}
function released(scim) {
 if(!scim || typeof scim!=='object'||Array.isArray(scim) ||
   typeof scim.id!=='string'||scim.id.length>1024)throw new Error('INVALID_WSO2_SCIM_ME');
 const name=scim.name && typeof scim.name==='object' && !Array.isArray(scim.name)?scim.name:{};
 const obj={id:scim.id};
 if(typeof scim.active==='boolean')obj.active=scim.active;
 for(const [k,v] of Object.entries({nickName:scim.nickName,givenName:name.givenName,familyName:name.familyName}))
   if(typeof v==='string' && v.length<=128)obj[k]=v;
 if(Array.isArray(scim.emails))obj.emails=scim.emails.filter(x=>x && typeof x.value==='string'&&x.value.length<=256)
    .slice(0,3).map(x=>({value:x.value,primary:x.primary===true}));
 return obj;
}
async function readBounded(res){
 if(Number(res.headers?.get?.('content-length')||0)>16384)throw new Error('WSO2_SCIM_RESPONSE_TOO_LARGE');
 const body=await res.text();if(Buffer.byteLength(body)>16384)throw new Error('WSO2_SCIM_RESPONSE_TOO_LARGE');
 return body?JSON.parse(body):null;
}
export async function scimMe({client,token,request=fetch,method='GET',body}){
 const url=endpoint(client);
 const response=await request(url,{method,redirect:'error',signal:AbortSignal.timeout(8000),
  headers:{authorization:`Bearer ${token}`,accept:'application/scim+json',
    ...(body?{'content-type':'application/scim+json'}:{})},
  ...(body?{body:JSON.stringify(body)}:{})});
 if(response.status===401)return {status:401,error:'wso2_session_expired'};
 if(response.status===403)return {status:403,error:'wso2_self_service_permission_denied'};
 if(!response.ok)return {status:502,error:'wso2_self_service_rejected',upstreamStatus:response.status};
 if(method==='PATCH')return {status:200};
 return {status:200,profile:released(await readBounded(response))};
}
function navigation(client,brand,env){
 const base=new URL(client.issuer);
 const root=base.origin;
 const names={registration:'REGISTRATION',passwordChange:'PASSWORD_CHANGE',passwordRecovery:'PASSWORD_RECOVERY'};
 const urls={};
 for(const [label,suffix] of Object.entries(names)){
   const configured=env[`WSO2_${brand.toUpperCase()}_${suffix}_URL`];
   if(!configured) {urls[label]=null;continue;}
   const u=new URL(configured);
   if(u.origin!==root || u.username || u.password || u.hash || u.search ||
       (u.protocol!=='https:' && !(env.ALLOW_INSECURE_LOCAL==='true' &&
         ['localhost','127.0.0.1'].includes(u.hostname))))
     throw new Error(`UNTRUSTED_${suffix}_URL`);
   urls[label]=u.toString();
 }
 return urls;
}
async function parsePatchBody(req){
 if(!(req.headers['content-type']||'').startsWith('application/json'))
   return {error:'json_content_type_required',status:415};
 let text='';for await(const chunk of req){text+=chunk.toString('utf8');
   if(Buffer.byteLength(text)>1024)return {error:'request_too_large',status:413};}
 let x;try{x=JSON.parse(text);}catch{return {error:'invalid_json',status:400};}
 if(!x || typeof x!=='object' || Array.isArray(x) || !Object.keys(x).length ||
    Object.keys(x).some(k=>!Object.hasOwn(EDITABLE,k) || typeof x[k]!=='string' ||
        x[k].trim()!==x[k] || x[k].length<1 || x[k].length>80 || /[\x00-\x1f\x7f]/.test(x[k])))
   return {error:'invalid_profile_fields',status:400};
 return {value:x};
}
export async function handleSelfService(req,res,u,s,{clients,sameOrigin,safeCsrf,env=process.env,
    introspect=inspectAccessToken,request=fetch}) {
 const match=/^\/api\/brands\/(aurora|brisa)\/self-service\/(me|navigation)$/.exec(u.pathname);
 if(!match)return false;
 const [,brand,operation]=match,key=u.searchParams.get('client');
 if(!key || !Object.hasOwn(clients,key)){respond(res,400,{error:'invalid_client'});return true;}
 const client=clients[key];if(client.brand!==brand){respond(res,403,{error:'tenant_brand_mismatch'});return true;}
 if(operation==='navigation'){
   if(req.method!=='GET'){respond(res,405,{error:'method_not_allowed'});return true;}
   try {respond(res,200,{brand,source:'WSO2_HOSTED_SELF_SERVICE',urls:navigation(client,brand,env)});}
   catch {respond(res,503,{error:'self_service_navigation_not_configured'});}return true;
 }
 if(!['GET','PATCH'].includes(req.method)){respond(res,405,{error:'method_not_allowed'});return true;}
 if(req.method==='PATCH' && env.WSO2_SELF_SERVICE_WRITES_ENABLED!=='1') {
   respond(res,503,{error:'self_service_writes_not_enabled'});return true;
 }
 if(req.method==='PATCH' && (!sameOrigin(req)||!safeCsrf(req,s))){respond(res,403,{error:'csrf_or_origin_denied'});return true;}
 const login=s?.logins?.[key];
 if(!login?.verified || login.claims?.iss!==client.issuer || !login.claims?.sub){
   respond(res,401,{error:'authentication_required'});return true;
 }
 let access;
 try { access=await introspect(login,client); }
 catch {respond(res,503,{error:'wso2_authority_unavailable'});return true;}
 if(!access.active){delete s.logins[key];respond(res,401,{error:'wso2_session_expired'});return true;}
 try {
   if(req.method==='GET'){
     const result=await scimMe({client,token:login.accessToken,request});
     respond(res,result.status,result.status===200?{brand,identitySource:'WSO2_SCIM_ME',
       profile:result.profile,persistent:true}:{error:result.error});return true;
   }
   const input=await parsePatchBody(req);
   if(input.error){respond(res,input.status,{error:input.error});return true;}
   const ops=Object.entries(input.value).map(([k,value])=>({op:'replace',path:EDITABLE[k],value}));
   const sent=await scimMe({client,token:login.accessToken,request,method:'PATCH',body:{
     schemas:[PATCH_SCHEMA],Operations:ops}});
   if(sent.status!==200){respond(res,sent.status,{error:sent.error});return true;}
   const checked=await scimMe({client,token:login.accessToken,request});
   if(checked.status!==200 || Object.entries(input.value).some(([k,v])=>checked.profile[k]!==v)){
     respond(res,502,{error:'wso2_profile_change_unconfirmed',identitySource:'WSO2'});return true;
   }
   respond(res,200,{status:'WSO2_PROFILE_CHANGE_CONFIRMED',brand,profile:checked.profile,persistent:true});
   return true;
 } catch {
   respond(res,503,{error:'wso2_self_service_unavailable'});return true;
 }
}
