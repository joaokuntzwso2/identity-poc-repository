/** P2.24 operator-only user-token acceptance. No browser routes or synthetic success. */
import { randomBytes } from 'node:crypto';
import { readFileSync, lstatSync, mkdirSync, openSync, closeSync, renameSync, writeFileSync, fsyncSync, unlinkSync, constants } from 'node:fs';
import { join } from 'node:path';
export const TENANT='aurora.identity.test';
export const ROOT='5252717e-1024-40f0-89ee-016b513d36f3';
export const PARTNER='629e590a-9072-406d-95a8-71f0cfc52cbe';
export const USER='82321ec6-0522-4a84-8e5f-d8fc057338ab';
export const ROLE='b199e082-cb5e-455a-8155-59fa199c9a0a';
export const CLIENT_NAME='Identity Lab P2 Verde User Token Acceptance';
export const SCOPE='internal_org_user_mgt_list';
// Organization application listing uses the view permission in WSO2 IS 7.3.0 GA.
export const APP_SCOPES=Object.freeze(['internal_org_application_mgt_view',
  'internal_org_application_mgt_create','internal_org_application_mgt_update']);
export const USERS_API='/o/scim2/Users';
const UUID=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const must=(v,code)=>{if(!v)throw Error(code);return v};
const allowed=(x)=>x==='https://localhost:9444';
const apiRoot=`https://localhost:9444/t/${TENANT}/o/api/server/v1/applications`;
const orgRoot=`https://localhost:9444/t/${TENANT}/o/api/server/v1/organizations/self`;
const currentUserApi=`https://localhost:9444/t/${TENANT}/o/scim2/Users?startIndex=1&count=1`;
export function verifyDelegateJournal(doc) {
  must(doc?.schema==='identity.wso2.p224.delegation.v1'&&doc.partnerId===PARTNER&&
       doc.rootId===ROOT&&doc.tenant===TENANT&&doc.user?.id===USER&&
       doc.user.phase==='verified'&&typeof doc.user.password==='string'&&
       doc.user.password.length>=32&&doc.role?.id===ROLE&&doc.role.phase==='verified'&&
       doc.assignment?.phase==='verified'&&doc.membership?.phase==='verified',
       'P224_USER_PRIVATE_DELEGATE_NOT_VERIFIED');
  return {username:'p2-verde-operator',password:doc.user.password};
}
export function verifyIntrospection(obj,clientId,now=Math.floor(Date.now()/1000)){
  must(obj?.active===true&&obj.aut==='APPLICATION_USER', 'P224_TOKEN_NOT_AN_END_USER');
  must(obj.org_id===PARTNER, 'P224_TOKEN_ORGANIZATION_MISMATCH');
  must(obj.client_id===clientId && typeof obj.client_id==='string', 'P224_TOKEN_CLIENT_MISMATCH');
  // The WSO2-issued immutable subject is the authoritative delegated-user binding.
  // Never substitute a visually similar username or an unverified user_id claim.
  must(typeof obj.sub==='string' && obj.sub===USER,
    'P224_TOKEN_SUBJECT_MISMATCH');
  const username=typeof obj.username==='string'&&obj.username.startsWith('PRIMARY/')
    ?obj.username.slice(8):obj.username;
  const localName='p2-verde-operator';
  const qualifier=typeof username==='string' && username.startsWith(localName+'@')
    ?username.slice(localName.length+1):null;
  must(typeof username==='string' && username.length<=256 &&
    (username===localName ||
      (qualifier!==null && qualifier.length>0 &&
       /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(qualifier))),
    'P224_TOKEN_USERNAME_CONTRADICTION');
  must(Number.isSafeInteger(obj.exp)&&obj.exp>now&&obj.exp<=now+3600,
    'P224_TOKEN_EXPIRY_INVALID');
  must(Number.isSafeInteger(obj.iat)&&obj.iat<=now+60&&obj.iat>=now-3600,
    'P224_TOKEN_ISSUE_TIME_INVALID');
  // WSO2's organization-introspection example omits scope. The OAuth token
  // response must grant SCOPE, and the real SCIM call is additionally required.
  // If introspection provides scope, it must agree with those proofs.
  if(obj.scope!==undefined)must(typeof obj.scope==='string' &&
    obj.scope.split(/\s+/).includes(SCOPE), 'P224_TOKEN_SCOPE_CONTRADICTION');
  return true;
}
export function verifyOAuthToken(data){
  must(data?.token_type?.toLowerCase()==='bearer' &&
       typeof data.access_token==='string' && data.access_token.length>=16 &&
       !/\s/.test(data.access_token) && Number.isInteger(data.expires_in) &&
       data.expires_in>0 && data.expires_in<=3600, 'P224_USER_OAUTH_TOKEN_INVALID');
  must(typeof data.scope==='string'&&data.scope.split(/\s+/).includes(SCOPE),
       'P224_USER_OAUTH_SCOPE_MISSING');
  return data.access_token;
}
export function verifyApp(doc,appId,marker){
  must(doc?.id===appId&&UUID.test(appId)&&doc?.name===CLIENT_NAME&&
    doc?.description===marker&&doc?.isManagementApp===false,
    'P224_USER_APP_IDENTITY_DRIFT');
  must(doc?.associatedRoles?.allowedAudience==='ORGANIZATION',
    'P224_USER_APP_ROLE_AUDIENCE_INVALID');
  if(Array.isArray(doc.associatedRoles.roles) && doc.associatedRoles.roles.length){
    must(doc.associatedRoles.roles.length===1 &&
      (doc.associatedRoles.roles[0].id===ROLE || doc.associatedRoles.roles[0].value===ROLE),
      'P224_USER_APP_FOREIGN_ROLE_ASSOCIATION');
  }
  return true;
}
export function verifyAppProtocol(doc){
  must(Array.isArray(doc?.grantTypes)&&doc.grantTypes.length===1&&doc.grantTypes[0]==='password',
    'P224_USER_APP_GRANT_DRIFT');
  must(doc.publicClient===false&&typeof doc.clientId==='string'&&
    doc.clientId.length>=8&&typeof doc.clientSecret==='string'&&doc.clientSecret.length>=8,
    'P224_USER_APP_CREDENTIALS_UNAVAILABLE');
  return {clientId:doc.clientId,clientSecret:doc.clientSecret};
}
export function verifyAuthorizedApi(doc,id){
  must(doc && doc.id===id && (doc.policyIdentifier||doc.policyId||'RBAC')==='RBAC',
    'P224_USER_APP_API_AUTH_MISSING');
  const v=doc.authorizedScopes??doc.scopes;
  must(Array.isArray(v),'P224_USER_APP_API_SCOPE_SHAPE_INVALID');
  const scopes=v.map(x=>typeof x==='string'?x:x?.name);
  // The same lab application may be narrowly extended for the guarded
  // delegated-member demonstration; never accept an arbitrary extra scope.
  const baseline=scopes.length===1&&scopes[0]===SCOPE;
  const extended=scopes.length===3&&new Set(scopes).size===3&&
    [SCOPE,'internal_org_user_mgt_view','internal_org_user_mgt_create']
      .every(scope=>scopes.includes(scope));
  must(baseline||extended, 'P224_USER_APP_API_SCOPE_NOT_EXACT');
  return true;
}
export function parseAppList(body){
  must(body&&typeof body==='object'&&!Array.isArray(body),'P224_USER_APP_LIST_INVALID');
  if(body.totalResults===0){
    must(body.applications===undefined ||
      (Array.isArray(body.applications)&&body.applications.length===0),
      'P224_USER_APP_EMPTY_CONTRADICTION');
    return {items:[],total:0};
  }
  must(Array.isArray(body.applications)&&body.applications.length<=100,
    'P224_USER_APP_LIST_COLLECTION_MISSING');
  const total=body.totalResults;
  must(Number.isSafeInteger(total)&&total>=body.applications.length&&total<=3000,
    'P224_USER_APP_LIST_TOTAL_INVALID');
  return {items:body.applications,total};
}
export async function inventoryApps(client){
  let offset=0,total=null;const all=[],seen=new Set();
  for(let i=0;i<30;i++){
    const body=await client('GET',`${apiRoot}?limit=100&offset=${offset}`);
    const page=parseAppList(body);
    if(total===null) total=page.total;
    must(total===page.total,'P224_USER_APP_TOTAL_CHANGED');
    if(total>0)must(page.items.length>0,'P224_USER_APP_EMPTY_CONTINUATION');
    for(const item of page.items){
      must(item && UUID.test(item.id) && !seen.has(item.id.toLowerCase()),
        'P224_USER_APP_ID_DUPLICATE_OR_INVALID');
      seen.add(item.id.toLowerCase());all.push(item);
    }
    if(all.length===total)return all;
    must(page.items.length===100,'P224_USER_APP_PAGINATION_INCOMPLETE');
    offset=all.length;
  }
  throw Error('P224_USER_APP_PAGE_LIMIT');
}
export function privateRead(path,optional=false){
  let stat;
  try{stat=lstatSync(path);}catch(e){if(optional&&e.code==='ENOENT')return null;throw e;}
  must(stat.isFile()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0&&stat.size<=131072&&
    (!process.getuid||stat.uid===process.getuid()),'P224_USER_PRIVATE_FILE_UNSAFE');
  return JSON.parse(readFileSync(path,'utf8'));
}
export function userAppJournal(dir){
  const stat=lstatSync(dir);
  must(stat.isDirectory()&&!stat.isSymbolicLink()&&(stat.mode&0o022)===0&&
    (!process.getuid||stat.uid===process.getuid()), 'P224_USER_PRIVATE_DIRECTORY_UNSAFE');
  const path=join(dir,'p224-verde-user-app.private.json');
  const lock=join(dir,'p224-verde-user-app.lock');
  const load=()=>{
    const doc=privateRead(path,true);
    if(doc)must(doc.schema==='identity.wso2.p224.userapp.v1'&&doc.partnerId===PARTNER&&
      doc.roleId===ROLE && /^p224-userapp-[a-f0-9]{32}$/.test(doc.marker),
      'P224_USER_APP_JOURNAL_INVALID');
    return doc;
  };
  const save=(doc)=>{
    const tmp=join(dir,`.p224-userapp-${process.pid}-${randomBytes(6).toString('hex')}`);
    const fd=openSync(tmp,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);
    try{writeFileSync(fd,JSON.stringify(doc)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
    try{renameSync(tmp,path);}catch(e){unlinkSync(tmp);throw e;}
  };
  return {load,save,acquire(){try{return openSync(lock,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY,0o600);}catch{throw Error('P224_USER_APP_CONCURRENT_OR_STALE_LOCK');}},
    release(fd){closeSync(fd);unlinkSync(lock);}};
}
export async function reconcileUserApp({client,usersResourceId,journal,write=false}){
  must(typeof client==='function'&&UUID.test(usersResourceId)&&journal?.load&&journal?.save,
    'P224_USER_APP_DEPENDENCIES_INVALID');
  const context=await client('GET',orgRoot);
  must(context?.id===PARTNER&&context?.parent?.id===ROOT&&context?.status==='ACTIVE',
    'P224_USER_APP_ORGANIZATION_CONTEXT_WRONG');
  const found=(await inventoryApps(client)).filter(x=>x.name===CLIENT_NAME);
  must(found.length<=1,'P224_USER_APP_NAME_COLLISION');
  let j=journal.load();
  if(!j){
    must(!found.length,'P224_USER_APP_UNJOURNALED_COLLISION');
    if(!write)return {phase:'P2.24-USER-APP',mode:'CHECK',state:'CREATE_REQUIRED',managementWrites:0};
    j={schema:'identity.wso2.p224.userapp.v1',partnerId:PARTNER,roleId:ROLE,
       marker:'p224-userapp-'+randomBytes(16).toString('hex'),phase:'prepared',authPhase:'none'};
    journal.save(j);
  }
  if(found.length){
    must(j.phase!=='prepared','P224_USER_APP_UNJOURNALED_COLLISION');
    if(j.appId) must(found[0].id===j.appId,'P224_USER_APP_JOURNAL_ID_DRIFT');
    const doc=await client('GET',`${apiRoot}/${found[0].id}`);
    verifyApp(doc,found[0].id,j.marker);
    if(j.phase==='create-started'){
      j.appId=found[0].id;j.phase='created';if(write)journal.save(j);
    }
  }else if(j.phase==='create-started'){
    throw Error('P224_USER_APP_CREATE_UNCERTAIN_NO_RETRY');
  }else if(j.appId){throw Error('P224_USER_APP_REMOTE_MISSING');}
  else if(write){
    must(j.phase==='prepared','P224_USER_APP_UNEXPECTED_CREATE_STATE');
    j.phase='create-started';journal.save(j);
    const payload={name:CLIENT_NAME,description:j.marker,isManagementApp:false,
      associatedRoles:{allowedAudience:'ORGANIZATION',roles:[{id:ROLE}]},
      inboundProtocolConfiguration:{oidc:{grantTypes:['password'],publicClient:false,
        accessToken:{type:'JWT',userAccessTokenExpiryInSeconds:900,
                     applicationAccessTokenExpiryInSeconds:900}}}};
    const response=await client('POST',apiRoot,payload);
    must(UUID.test(response?.id),'P224_USER_APP_POST_RESULT_UNCERTAIN');
    j.appId=response.id;j.phase='created';journal.save(j);
  }
  if(!j.appId)return {phase:'P2.24-USER-APP',mode:'CHECK',state:'CREATE_REQUIRED',managementWrites:0};
  const app=await client('GET',`${apiRoot}/${j.appId}`);
  verifyApp(app,j.appId,j.marker);
  const protocol=verifyAppProtocol(await client('GET',`${apiRoot}/${j.appId}/inbound-protocols/oidc`));
  if(j.clientId && j.clientId!==protocol.clientId)throw Error('P224_USER_APP_CLIENT_ID_DRIFT');
  const list=await client('GET',`${apiRoot}/${j.appId}/authorized-apis`);
  must(list && typeof list==='object','P224_USER_APP_AUTH_COLLECTION_INVALID');
  const entries=Array.isArray(list)?list:(list.authorizedAPIs||list.authorizedApis);
  must(Array.isArray(entries),'P224_USER_APP_AUTH_LIST_MISSING');
  must(entries.every(x=>x.id===usersResourceId),'P224_USER_APP_EXTRA_API_AUTH_DENIED');
  const selected=entries.filter(x=>x.id===usersResourceId);
  must(selected.length<=1,'P224_USER_APP_DUPLICATE_API_AUTH');
  if(!selected.length){
    if(j.authPhase==='started')throw Error('P224_USER_APP_AUTH_OUTCOME_UNCERTAIN_NO_RETRY');
    if(!write)return {phase:'P2.24-USER-APP',mode:'CHECK',state:'API_AUTH_REQUIRED',managementWrites:0};
    j.authPhase='started';journal.save(j);
    await client('POST',`${apiRoot}/${j.appId}/authorized-apis`,
      {id:usersResourceId,policyIdentifier:'RBAC',scopes:[SCOPE]});
    const fresh=await client('GET',`${apiRoot}/${j.appId}/authorized-apis`);
    const rec=Array.isArray(fresh)?fresh:(fresh?.authorizedAPIs||fresh?.authorizedApis);
    must(Array.isArray(rec)&&rec.length===1,'P224_USER_APP_AUTH_POST_NO_READBACK');
    verifyAuthorizedApi(rec[0],usersResourceId);
    j.authPhase='verified';journal.save(j);
  }else{
    verifyAuthorizedApi(selected[0],usersResourceId);
    if(j.authPhase==='started'&&write){j.authPhase='verified';journal.save(j);}
  }
  if(write){
    j.clientId=protocol.clientId;j.clientSecret=protocol.clientSecret;
    j.phase='verified';journal.save(j);
  }
  return {phase:'P2.24-USER-APP',mode:write?'APPLY':'CHECK',state:'VERIFIED',
    appId:j.appId,roleAudience:'ORGANIZATION',apiAuthorization:'EXACT_READBACK_VERIFIED',
    credentialStorage:'PRIVATE_OWNER_ONLY',managementWrites:write?'READBACK_CONFIRMED':'0'};
}
export async function acceptance({oauth,read,clientId,username,password,now=Math.floor(Date.now()/1000)}){
  must(typeof oauth==='function'&&typeof read==='function'&&
    typeof clientId==='string'&&username==='p2-verde-operator'&&
    typeof password==='string'&&password.length>=32,'P224_USER_ACCEPT_DEPENDENCIES_INVALID');
  const result=await oauth('token',{grant_type:'password',username,password,scope:SCOPE});
  const token=verifyOAuthToken(result);
  const introspect=await oauth('introspect',{token});
  verifyIntrospection(introspect,clientId,now);
  const positives=[['VERDE_USER_LIST',currentUserApi]];
  const negatives=[
    ['AURORA_ROOT_DENIED',`https://localhost:9444/t/${TENANT}/scim2/Users?startIndex=1&count=1`],
    ['BRISA_TENANT_DENIED','https://localhost:9444/t/brisa.identity.test/o/scim2/Users?startIndex=1&count=1'],
    ['ROLE_ADMINISTRATION_DENIED',`https://localhost:9444/t/${TENANT}/o/scim2/v2/Roles?startIndex=1&count=1`]
  ];
  const verdict={};
  for(const [label,url] of positives){
    const status=await read(url,token);
    must(status===200,'P224_ACCEPT_POSITIVE_DENIED_'+label);
    verdict[label]='VERIFIED_HTTP_200';
  }
  for(const [label,url] of negatives){
    const status=await read(url,token);
    must(status===401||status===403,'P224_ACCEPT_NEGATIVE_NOT_DENIED_'+label);
    verdict[label]=`VERIFIED_HTTP_${status}`;
  }
  return {phase:'P2.24-USER-TOKEN',state:'WSO2_USER_TOKEN_ACCEPTANCE_VERIFIED',
    tokenAuthority:'WSO2_INTROSPECTION_APPLICATION_USER',partnerId:PARTNER,
    userId:USER,grantedScope:SCOPE,checks:verdict,
    otherPartnerDenial:'NOT_EXECUTED_NO_SECOND_VERIFIED_PARTNER',
    protocol:'LAB_ONLY_PASSWORD_GRANT_NOT_PRODUCTION_LOGIN'};
}
