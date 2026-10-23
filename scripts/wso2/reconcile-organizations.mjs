/**
 * Reconcile only the lab-owned B2B organization hierarchy in an existing
 * carbon.super bootstrap inventory. Never adopt unowned resources by name.
 */
import {readFileSync,writeFileSync,renameSync,chmodSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {root,config,assertUpdatedBuild} from './domain.mjs';
import {makeClient,origin} from './api.mjs';
import {requestOrgManagementToken} from './management-token.mjs';
import {authorizeOrgLevel,shareWithParent,scopedOrgToken} from './org-context.mjs';

const inventoryDefault=join(root,'var/wso2/inventory.private.json');
const credentialsDefault=join(root,'var/wso2/credentials.private.json');
const ID=/^[a-zA-Z0-9-]{5,128}$/;
function load(p){return JSON.parse(readFileSync(p,'utf8'));}
function writePrivate(p,x){const tmp=p+`.${process.pid}.tmp`;writeFileSync(tmp,JSON.stringify(x,null,2)+'\n',{flag:'wx',mode:0o600});chmodSync(tmp,0o600);renameSync(tmp,p);}
function requireId(r){const id=r?.data?.id||r?.location?.split('/').pop();if(!id||!ID.test(id))throw Error('RESOURCE_ID_NOT_RETURNED');return id;}
function remember(s,path,item){
 if(s.resources.some(x=>x.key===item.key&&x.type===item.type))throw Error('DUPLICATE_INVENTORY_RESOURCE');
 s.resources.push(item);s.completion='IN_PROGRESS';writePrivate(path,s);
}
function orgAttr(username,id){return [{key:'creator.id',value:id},{key:'creator.username',value:username}];}
export async function reconcileOrganizations({env=process.env,emit=console.log,
  inventoryPath=inventoryDefault,credentialsPath=credentialsDefault,rootApi=null,
  scopedApiFactory=null,orgTokenFetch=fetch}={}){
 if(env.WSO2_LAB_CONFIRM!=='CREATE_SYNTHETIC_RESOURCES')throw Error('EXPLICIT_APPLY_ACK_REQUIRED');
 assertUpdatedBuild(env);
 const c=config();if(c.tenantDomain!=='carbon.super')throw Error('RECONCILE_ONLY_EXISTING_CARBON_SUPER');
 const base=origin(env.WSO2_BASE_URL||'');
 if(!env.WSO2_ADMIN_USER||!env.WSO2_ADMIN_PASSWORD)throw Error('ADMIN_CREDENTIALS_REQUIRED');
 const s=load(inventoryPath),passwords=load(credentialsPath);
 const client=rootApi||makeClient({base,adminUser:env.WSO2_ADMIN_USER,adminPassword:env.WSO2_ADMIN_PASSWORD});
 if(s.origin!==client.hashOrigin())throw Error('INVENTORY_ISSUER_ORIGIN_MISMATCH');
 if(!Array.isArray(s.resources))throw Error('INVENTORY_SHAPE_INVALID');
 const key='bootstrap-org-management';
 const helperKey='bootstrap-nested-org-management';
 if(!s.resources.some(x=>x.type==='application'&&x.key===key)||!passwords.management?.clientSecret)
  throw Error('EXISTING_BOOTSTRAP_MANAGEMENT_APP_REQUIRED');
 const rootToken=await requestOrgManagementToken({base,clientId:passwords.management.clientId,
  clientSecret:passwords.management.clientSecret,fetchImpl:orgTokenFetch});
 const api=rootApi||makeClient({base,adminUser:env.WSO2_ADMIN_USER,adminPassword:env.WSO2_ADMIN_PASSWORD,orgToken:rootToken});
 const rootParent=s.resources.find(x=>x.type==='org'&&x.key==='partner-nova');
 if(!rootParent)throw Error('EXPECTED_OWNED_PARENT_ORG_NOT_IN_INVENTORY');
 await api.getOrg(rootParent.id);emit('VERIFIED_EXISTING_ORG partner-nova '+rootParent.id);
 // Resolve a real SCIM administrator ID. Never synthesize creator.id.
 const adminLookup=await api.listRootUsersByName(env.WSO2_ADMIN_USER);
 const matches=adminLookup.data?.Resources;
 if(!Array.isArray(matches)||matches.length!==1||!matches[0]?.id||matches[0].userName!==env.WSO2_ADMIN_USER)
  throw Error('ROOT_ADMIN_SCIM_ID_NOT_UNIQUELY_RESOLVED_NO_WRITE');
 const adminId=matches[0].id;
 const newRoot=c.b2bOrganizations.find(o=>o.key==='partner-lumen');
 if(!newRoot)throw Error('EXPECTED_SECOND_ROOT_B2B_ORG_NOT_IN_PLAN');
 if(!s.resources.some(r=>r.type==='org'&&r.key===newRoot.key)){
  const payload={name:newRoot.name,orgHandle:newRoot.handle,
   description:'Synthetic lab-owned B2B merchant organization',
   attributes:orgAttr(env.WSO2_ADMIN_USER,adminId)};
  const id=requireId(await api.createOrg(payload));remember(s,inventoryPath,{type:'org',key:newRoot.key,id});
  emit('CREATED_ORG_WITH_CREATOR '+newRoot.key+' '+id);
 }else{
  const known=s.resources.find(r=>r.type==='org'&&r.key===newRoot.key);
  await api.getOrg(known.id);emit('VERIFIED_EXISTING_ORG '+newRoot.key);
 }
 const nested=c.b2bOrganizations.find(o=>o.key==='partner-nova-outlet');
 if(!nested||nested.parent!=='partner-nova')throw Error('UNEXPECTED_NESTED_ORG_PLAN');
 const knownChild=s.resources.find(r=>r.type==='org'&&r.key===nested.key);
 if(knownChild){
  const verified=(await api.getOrg(knownChild.id)).data;
  const actualParent=verified?.parent?.id||verified?.parentId;
  if(actualParent&&actualParent!==rootParent.id)throw Error('OWNED_NESTED_ORG_PARENT_MISMATCH');
  emit('VERIFIED_EXISTING_CHILD_ORG '+nested.key);
  emit('CONSOLE_ADMIN_PENDING_EXISTING parent-nova (needs actual Console role assignment)');
  return s;
 }
 let helper=s.resources.find(r=>r.type==='application'&&r.key===helperKey);
 if(!helper){
  const app={name:'Identity Lab Scoped Child Organization Bootstrap',isManagementApp:true,
   description:'Temporary lab M2M app shared only with the parent seller organization',
   inboundProtocolConfiguration:{oidc:{grantTypes:['client_credentials'],publicClient:false,
    accessToken:{type:'JWT',userAccessTokenExpiryInSeconds:3600,applicationAccessTokenExpiryInSeconds:900}}}};
  const id=requireId(await api.createApp(app));helper={type:'application',key:helperKey,id};
  remember(s,inventoryPath,helper);emit('CREATED_SCOPED_M2M_APP '+id);
 }else{await api.getApp(helper.id);emit('VERIFIED_EXISTING_SCOPED_M2M_APP');}
 if(!passwords.nestedManagement||passwords.nestedManagement.appId!==helper.id){
  const response=(await api.getOidc(helper.id)).data;
  if(!response?.clientId||!response?.clientSecret)throw Error('SCOPED_CLIENT_SECRET_UNAVAILABLE');
  passwords.nestedManagement={appId:helper.id,clientId:response.clientId,clientSecret:response.clientSecret};
  writePrivate(credentialsPath,passwords);
 }
 await authorizeOrgLevel(api,helper.id);
 await shareWithParent(api,helper.id,rootParent.id);
 const scopedBearer=await scopedOrgToken({base,parentId:rootParent.id,
  clientId:passwords.nestedManagement.clientId,clientSecret:passwords.nestedManagement.clientSecret,
  fetchImpl:orgTokenFetch});
 const childApi=scopedApiFactory?scopedApiFactory(scopedBearer):makeClient({base,
  adminUser:env.WSO2_ADMIN_USER,adminPassword:env.WSO2_ADMIN_PASSWORD,orgToken:scopedBearer});
 // An organization-scoped API creates children of the current organization;
 // explicitly include the matching parentId so the server verifies the context.
 const payload={name:nested.name,orgHandle:nested.handle,
  parentId:rootParent.id,description:'Synthetic lab-owned nested merchant organization'};
 const id=requireId(await childApi.createOrgScoped(payload));
 remember(s,inventoryPath,{type:'org',key:nested.key,id,parentId:rootParent.id});
 emit('CREATED_NESTED_ORG '+nested.key+' '+id);
 emit('CONSOLE_ADMIN_PENDING_EXISTING partner-nova: must verify real Console Administrator assignment');
 return s;
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(fileURLToPath(import.meta.url)))
 reconcileOrganizations().catch(e=>{console.error('LAB_RECONCILE_ERROR:',e.message);process.exitCode=1});
