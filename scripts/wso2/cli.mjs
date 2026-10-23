import {existsSync,mkdirSync,readFileSync,writeFileSync,renameSync,chmodSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {config,root,assertUpdatedBuild,deploymentPlan} from './domain.mjs';
import {makeClient,origin} from './api.mjs';
import {authorizeOrgManagement,requestOrgManagementToken} from './management-token.mjs';
import {scopedOrgToken} from './org-context.mjs';
import {assertSectorDocuments,sectorUris} from './sector.mjs';
import {generateBffEnvironment} from './bff-env.mjs';
const stateDir=resolve(root,'var/wso2'),stateFile=join(stateDir,'inventory.private.json'),secretsFile=join(stateDir,'credentials.private.json');
const command=process.argv[2]||'plan';
function privateWrite(p,obj){mkdirSync(resolve(p,'..'),{recursive:true,mode:0o700});const tmp=`${p}.${process.pid}.tmp`;writeFileSync(tmp,JSON.stringify(obj,null,2)+'\n',{mode:0o600,flag:'wx'});chmodSync(tmp,0o600);renameSync(tmp,p)}
function load(p,d){return existsSync(p)?JSON.parse(readFileSync(p,'utf8')):d}
function checkEnv(env){
 const build=assertUpdatedBuild(env);const url=origin(env.WSO2_BASE_URL||'');
 if(env.WSO2_ADMIN_USER===undefined||!env.WSO2_ADMIN_PASSWORD)throw Error('ADMIN_CREDENTIALS_REQUIRED');
 return {build,url};
}
function maskedError(e){return e instanceof Error?e.message:'UNKNOWN_ERROR'}
export async function execute(cmd,{c=config(),env=process.env,client=null,emit=console.log,inventoryPath=stateFile,credentialsPath=secretsFile,sectorFetchImpl=fetch,managementFetchImpl=fetch}={}){
 const plan=deploymentPlan(c,env);
 if(cmd==='bff-env'){emit('PRIVATE_BFF_ENV_CREATED '+generateBffEnvironment(env));return {status:'PRIVATE_BFF_ENV_CREATED'}}
 if(cmd==='plan'){emit(JSON.stringify(plan,null,2));return {status:'PLAN_ONLY'}}
 // WSO2_CORE_BOOTSTRAP_V084: core provisioning is NOT pairwise OIDC activation.
 if(!['apply','core','reset','status'].includes(cmd))throw Error('COMMAND_EXPECTED_plan_apply_core_status_reset_bff-env');
 if(cmd==='status'){
  const s=load(inventoryPath,{resources:[],completion:'NOT_BOOTSTRAPPED'});emit(JSON.stringify({resources:s.resources.map(({type,key,id})=>({type,key,id})),completion:s.completion,acceptance:'NOT_VERIFIED'},null,2));return s;
 }
 if(['apply','core'].includes(cmd)&&env.WSO2_LAB_CONFIRM!=='CREATE_SYNTHETIC_RESOURCES')throw Error('EXPLICIT_APPLY_ACK_REQUIRED');
 if(cmd==='reset'&&env.WSO2_LAB_CONFIRM!=='DELETE_LAB_OWNED_RESOURCES')throw Error('EXPLICIT_RESET_ACK_REQUIRED');
 const {build,url}=checkEnv(env);
 // First construct an administrator-only management client. This never uses
 // Basic authentication for the organization API itself.
 const adminApi=client||makeClient({base:url,adminUser:env.WSO2_ADMIN_USER,adminPassword:env.WSO2_ADMIN_PASSWORD});
 let s=load(inventoryPath,null);if(s&&s.origin!==adminApi.hashOrigin())throw Error('INVENTORY_ISSUER_ORIGIN_MISMATCH');
 if(!s)s={schema:'identity.wso2.inventory.v1',origin:adminApi.hashOrigin(),createdAt:new Date().toISOString(),resources:[],completion:'IN_PROGRESS',build};
 const passwords=load(credentialsPath,{schema:'identity.wso2.secrets.v1',users:{},clients:{}});
 // Resolve the real scoped OAuth bearer AUTOMATICALLY. An operator-provided
 // token is supported for managed environments but never required locally.
 let token=env.WSO2_ORG_API_TOKEN||'';
 if(!token){
  const key='bootstrap-org-management';
  const previous=s.resources.find(r=>r.type==='application'&&r.key===key);
  // Preflight sector hosting BEFORE creating any new management client.
  if(cmd==='apply')await assertSectorDocuments(plan,env,sectorFetchImpl);
  if(!previous){
   if(cmd==='reset')throw Error('NO_OWNED_MANAGEMENT_CLIENT_FOR_RESET');
   const created=await adminApi.createApp({
    name:'Identity Lab Bootstrap Organization Management',
    description:'Lab-owned, scoped bootstrap client (automatically removed by reset)',
    isManagementApp:true,
    inboundProtocolConfiguration:{oidc:{grantTypes:['client_credentials'],publicClient:false,
      accessToken:{type:'JWT',userAccessTokenExpiryInSeconds:3600,applicationAccessTokenExpiryInSeconds:900}}}
   });
   const id=created.data?.id||created.location?.split('/').pop();
   if(!id||!/^[a-zA-Z0-9-]{5,128}$/.test(id))throw Error('BOOTSTRAP_MANAGEMENT_CLIENT_ID_MISSING');
   s.resources.push({type:'application',key,id});
   s.completion='IN_PROGRESS';privateWrite(inventoryPath,s);
   emit('CREATED application bootstrap-org-management '+id);
  }else{
   await adminApi.getApp(previous.id);
   emit('VERIFIED_EXISTING application bootstrap-org-management');
  }
  const appId=s.resources.find(r=>r.type==='application'&&r.key===key).id;
  if(!passwords.management||passwords.management.appId!==appId){
   const response=await adminApi.getOidc(appId);
   if(!response.data?.clientId||!response.data?.clientSecret)
    throw Error('BOOTSTRAP_MANAGEMENT_CLIENT_SECRET_UNAVAILABLE');
   passwords.management={appId,clientId:response.data.clientId,clientSecret:response.data.clientSecret};
   privateWrite(credentialsPath,passwords);
  }
  await authorizeOrgManagement(adminApi,appId);
  token=await requestOrgManagementToken({base:url,
   clientId:passwords.management.clientId,clientSecret:passwords.management.clientSecret,
   fetchImpl:managementFetchImpl});
  emit('ORG_MANAGEMENT_TOKEN_ACQUIRED (in-memory, scoped, not printed or stored)');
 }
 const api=client||makeClient({base:url,adminUser:env.WSO2_ADMIN_USER,adminPassword:env.WSO2_ADMIN_PASSWORD,orgToken:token});
 const remember=(type,key,id)=>{if(!id||!/^[a-zA-Z0-9-]{5,128}$/.test(id))throw Error('MISSING_RESOURCE_ID');s.resources.push({type,key,id});s.completion='IN_PROGRESS';privateWrite(inventoryPath,s)};
 if(cmd==='apply'||cmd==='core'){
  const add=async(type,key,action)=>{
   const prior=s.resources.find(r=>r.type===type&&r.key===key);
   if(prior){
    if(type==='application')await api.getApp(prior.id);
    else if(type==='user')await api.getUser(prior.id);
    else if(type==='org'&&prior.parentId){
     if(!passwords.nestedManagement?.clientId||!passwords.nestedManagement?.clientSecret)throw Error('NESTED_ORG_VIEW_REQUIRES_SCOPED_M2M_CREDENTIALS');
     const scopedToken=await scopedOrgToken({base:url,parentId:prior.parentId,clientId:passwords.nestedManagement.clientId,clientSecret:passwords.nestedManagement.clientSecret});
     const scoped=makeClient({base:url,adminUser:env.WSO2_ADMIN_USER,adminPassword:env.WSO2_ADMIN_PASSWORD,orgToken:scopedToken});
     await scoped.getOrgScoped(prior.id);
    } else if(type==='org')await api.getOrg(prior.id);
    else throw Error('UNKNOWN_RESOURCE_TYPE');
    emit(`VERIFIED_EXISTING ${type} ${key}`);return;
   }
   const r=await action();const id=r.data?.id||r.location?.split('/').pop();remember(type,key,id);emit(`CREATED ${type} ${key} ${id}`);
  };
  // All 4 OIDC application registrations and two workloads have distinct client IDs.
  // Browser-based mobile simulations remain confidential BFF clients until native-app flows are built.
  if(cmd==='apply')await assertSectorDocuments(plan,env,sectorFetchImpl);
  const sectorUrls=cmd==='apply'?sectorUris(env):{};
  for(const app of plan.apps){
   // In core mode, never register customer-facing clients with an unverified
   // public subject identifier. Defer them until distinct pairwise sectors exist.
   if(cmd==='core'&&app.kind!=='m2m')continue;
   const isMachine=app.kind==='m2m';
   const sectorUri=isMachine?undefined:sectorUrls[app.brand];
   if(!isMachine&&new URL(sectorUri).protocol!=='https:')throw Error('HTTPS_SECTOR_URI_REQUIRED_FOR_LIVE_PAIRWISE');
   const oidc=isMachine?{grantTypes:['client_credentials'],publicClient:false,accessToken:{type:'JWT',userAccessTokenExpiryInSeconds:3600,applicationAccessTokenExpiryInSeconds:1800}}:
    {grantTypes:['authorization_code','refresh_token'],publicClient:false,callbackURLs:[app.callback],pkce:{mandatory:true,supportPlainTransformAlgorithm:false},
     subject:{subjectType:'pairwise',sectorIdentifierUri:sectorUri},accessToken:{type:'JWT',userAccessTokenExpiryInSeconds:1800,applicationAccessTokenExpiryInSeconds:1800}};
   const obj={name:app.name,description:'Synthetic training resource, created by identity lab bootstrap',isManagementApp:false,
    ...(isMachine?{}:{accessUrl:app.accessUrl}),inboundProtocolConfiguration:{oidc}};
   await add('application',app.key,()=>api.createApp(obj));
   const id=s.resources.find(r=>r.type==='application'&&r.key===app.key).id;
   // Secrets may be withheld by WSO2 application management scope, never invent them.
   if(!passwords.clients[app.key]||passwords.clients[app.key].appId!==id){
    const read=await api.getOidc(id);if(!read.data?.clientId)throw Error(`CLIENT_ID_UNAVAILABLE_${app.key}`);
    if(!read.data.clientSecret)throw Error(`CLIENT_SECRET_NOT_RETURNED_${app.key}_grant_view_or_configure_secret`);
    passwords.clients[app.key]={appId:id,clientId:read.data.clientId,clientSecret:read.data.clientSecret};privateWrite(credentialsPath,passwords);
   }
  }
  for(const person of c.users){
   const existing=s.resources.some(r=>r.type==='user'&&r.key===person.key);
   if(existing){
    // Never overwrite a persisted password on a repeat run: the actual SCIM user's
    // password has NOT changed. A missing credential needs an operator reset.
    await add('user',person.key,()=>{throw Error('DUPLICATE_GUARD')});
    if(!passwords.users[person.key])throw Error(`OWNED_USER_SECRET_MISSING_${person.key}_RESET_REQUIRED`);
    continue;
   }
   const password=randomBytes(24).toString('base64url');
   const user={schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],userName:person.username,password,
    name:{givenName:person.givenName,familyName:person.familyName},emails:[{value:person.email,primary:true}]};
   await add('user',person.key,()=>api.createUser(user));
   passwords.users[person.key]={username:person.username,password};privateWrite(credentialsPath,passwords);
  }
  for(const org of c.b2bOrganizations){
   const parent=org.parent?s.resources.find(r=>r.type==='org'&&r.key===org.parent)?.id:undefined;
   if(org.parent&&!parent)throw Error('PARENT_MISSING_IN_INVENTORY');
   const request={name:org.name,orgHandle:org.handle,description:'Synthetic seller organization managed by identity lab',...(parent?{parentId:parent}:{})};
   await add('org',org.key,()=>api.createOrg(request));
  }
  s.completion=cmd==='core'?'CORE_PROVISIONED_PAIRWISE_PENDING':'PARTIAL_INTEGRATION_REQUIRED';
  privateWrite(inventoryPath,s);
  if(cmd==='core')emit('BOOTSTRAP_CORE_CREATED — management and M2M clients, synthetic users and organizations. Four brand OIDC applications NOT CREATED; pairwise, SSO and acceptance NOT_VERIFIED.');
  else emit('BOOTSTRAP_RESOURCES_CREATED — OIDC clients, users, organizations. Agent identities, MCP resources, roles, consent, real SSO, MFA and acceptance remain NOT_VERIFIED.');
  emit('Private credentials saved to var/wso2/credentials.private.json (0600). Configure BFF with values, never ship to frontend.');
  return s;
 }
 // Reverse topological order, only resources whose IDs were recorded by this lab.
 let failed=[];for(const r of [...s.resources].reverse()){
  try{
   if(r.type==='application')await api.deleteApp(r.id);
   else if(r.type==='user')await api.deleteUser(r.id);
   else if(r.type==='org'&&r.parentId){
    if(!passwords.nestedManagement?.clientId||!passwords.nestedManagement?.clientSecret)throw Error('NESTED_ORG_DELETE_REQUIRES_SCOPED_M2M_CREDENTIALS');
    const bearer=await scopedOrgToken({base:url,parentId:r.parentId,clientId:passwords.nestedManagement.clientId,clientSecret:passwords.nestedManagement.clientSecret});
    const scoped=makeClient({base:url,adminUser:env.WSO2_ADMIN_USER,adminPassword:env.WSO2_ADMIN_PASSWORD,orgToken:bearer});
    await scoped.deleteOrgScoped(r.id);
   }
   else if(r.type==='org')await api.deleteOrg(r.id);
   else throw Error('UNKNOWN_INVENTORY_RESOURCE');
   s.resources=s.resources.filter(x=>!(x.type===r.type&&x.key===r.key&&x.id===r.id));
   if(r.type==='application'){
    if(r.key==='bootstrap-org-management')delete passwords.management;
    else if(r.key==='bootstrap-nested-org-management')delete passwords.nestedManagement;
    else delete passwords.clients[r.key];
   }
   if(r.type==='user')delete passwords.users[r.key];
   privateWrite(credentialsPath,passwords);privateWrite(inventoryPath,s);emit(`DELETED ${r.type} ${r.key}`);
  }catch(e){failed.push({type:r.type,key:r.key,error:maskedError(e)});emit(`FAILED ${r.type} ${r.key}: ${maskedError(e)}`)}
 }
 s.completion=failed.length?'RESET_PARTIAL':'RESET_COMPLETE';privateWrite(inventoryPath,s);
 // Keep private credentials as an audit artifact until manually erased by operator; reset does not revoke unmanaged secrets.
 emit(`RESET_${failed.length?'PARTIAL':'COMPLETE'} owned_remaining=${s.resources.length}`);
 if(failed.length)throw Error(`RESET_PARTIAL_${failed.length}_REVIEW_INVENTORY`);
 return s;
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(import.meta.filename||'')){
 execute(command).catch(e=>{console.error('LAB_ERROR:',maskedError(e));process.exitCode=1});
}
