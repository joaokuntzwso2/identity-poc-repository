#!/usr/bin/env node
/** Operator-only, bound to the verified Aurora/Verde bootstrap; no browser API. */
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadAuthority,verifyRuntimeImage,createOAuthProvider} from './p2-bootstrap-auto.mjs';
import {ROOT_SCOPES} from './p2-bootstrap-core.mjs';
import {TENANT,ROOT,PARTNER,ROLE,USER,USERS_API,APP_SCOPES,
  privateRead,verifyDelegateJournal,userAppJournal,reconcileUserApp,acceptance} from './p224-user-token-core.mjs';
const base='https://localhost:9444';
const permittedAppPath=`/t/${TENANT}/o/api/server/v1/applications`;
const orgSelf=`/t/${TENANT}/o/api/server/v1/organizations/self`;
function privateHome(){
  const home=process.env.CIAM_V10_HOME||join(process.env.HOME||'', 'wso2-ciam-v10');
  if(!home.startsWith('/')||home.includes('..'))throw Error('P224_USER_HOME_INVALID');
  return join(home,'private');
}
function wire({token,request=fetch}){
  if(typeof token!=='string'||token.length<16||/\s/.test(token))throw Error('P224_USER_MANAGEMENT_TOKEN_INVALID');
  return async(method,uri,body)=>{
    const url=new URL(uri);
    if(url.origin!==base||url.username||url.password||url.hash)throw Error('P224_USER_REMOTE_ORIGIN_DENIED');
    const path=url.pathname;
    const id='[a-f\\d]{8}-[a-f\\d]{4}-[1-8][a-f\\d]{3}-[89ab][a-f\\d]{3}-[a-f\\d]{12}';
    const valid=path===orgSelf && method==='GET' ||
      path===permittedAppPath && method==='GET' && /^\?limit=100&offset=(?:0|[1-9][0-9]{0,3})$/.test(url.search) ||
      path===permittedAppPath && method==='POST' && !url.search ||
      new RegExp(`^${permittedAppPath}/${id}(?:/inbound-protocols/oidc|/authorized-apis)?$`,'i').test(path) && method==='GET' && !url.search ||
      new RegExp(`^${permittedAppPath}/${id}/authorized-apis$`,'i').test(path) && method==='POST' && !url.search;
    if(!valid)throw Error('P224_USER_APPLICATION_PATH_DENIED');
    if(body && method==='GET'||(!body&&method==='POST'))throw Error('P224_USER_APPLICATION_BODY_MISMATCH');
    let response;
    try{response=await request(url.href,{method,redirect:'manual',signal:AbortSignal.timeout(10000),
      headers:{Authorization:`Bearer ${token}`,Accept:'application/json',
        ...(body?{'Content-Type':'application/json'}:{})},
      ...(body?{body:JSON.stringify(body)}:{})});}
    catch{throw Error('P224_USER_APPLICATION_TRANSPORT_UNCERTAIN_NO_RETRY');}
    if(response.status<200||response.status>=300)throw Error(`P224_USER_APPLICATION_HTTP_${response.status}_NO_RETRY`);
    const text=await response.text();
    if(text.length>262144)throw Error('P224_USER_APPLICATION_RESPONSE_TOO_LARGE');
    let parsed;
    if(!text)parsed={};
    else {try{parsed=JSON.parse(text);}catch{throw Error('P224_USER_APPLICATION_RESPONSE_INVALID_JSON');}}
    // App-create may return the identifier only in Location. Verify it is
    // precisely this tenant's newly created application, not an arbitrary URL.
    if(method==='POST' && path===permittedAppPath && response.status===201 && !parsed.id){
      const location=response.headers?.get?.('location');
      if(typeof location==='string'){
        const loc=new URL(location,base);
        const match=new RegExp(`^${permittedAppPath}/(${id})$`,'i').exec(loc.pathname);
        if(loc.origin===base&&!loc.username&&!loc.password&&!loc.search&&!loc.hash&&match)
          parsed.id=match[1];
      }
    }
    return parsed;
  };
}
function oauth({clientId,clientSecret,request=fetch}){
  const basic=Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  return async(kind,data)=>{
    const endpoint=`${base}/t/${TENANT}/o/${PARTNER}/oauth2/${kind==='token'?'token':'introspect'}`;
    let response;
    try{response=await request(endpoint,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),
      headers:{Authorization:`Basic ${basic}`,'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},
      body:new URLSearchParams(data).toString()});}
    catch{throw Error('P224_USER_OAUTH_UNAVAILABLE');}
    if(response.status!==200)throw Error(`P224_USER_OAUTH_${kind.toUpperCase()}_HTTP_${response.status}`);
    const text=await response.text();
    if(text.length>32768)throw Error('P224_USER_OAUTH_RESPONSE_TOO_LARGE');
    try{return JSON.parse(text);}catch{throw Error('P224_USER_OAUTH_RESPONSE_INVALID_JSON');}
  };
}
async function requestUser(url,token,request=fetch){
  const allowed=[
    `${base}/t/${TENANT}/o/scim2/Users?startIndex=1&count=1`,
    `${base}/t/${TENANT}/scim2/Users?startIndex=1&count=1`,
    `${base}/t/brisa.identity.test/o/scim2/Users?startIndex=1&count=1`,
    `${base}/t/${TENANT}/o/scim2/v2/Roles?startIndex=1&count=1`];
  if(!allowed.includes(url))throw Error('P224_USER_REQUEST_NOT_ALLOWED');
  let response;
  try{response=await request(url,{method:'GET',redirect:'manual',signal:AbortSignal.timeout(9000),
    headers:{Authorization:`Bearer ${token}`,Accept:'application/json, application/scim+json'}});}
  catch{throw Error('P224_USER_SCIM_TRANSPORT_UNAVAILABLE');}
  if(response.status>=300&&response.status<400)throw Error('P224_USER_SCIM_REDIRECT_BLOCKED');
  return response.status;
}
async function main(){
  const mode=process.argv[2]||'check';
  if(!['check','apply'].includes(mode))throw Error('P224_USER_MODE_INVALID');
  if(process.env.NODE_ENV==='production'||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')
    throw Error('P224_USER_PRODUCTION_OR_TLS_BYPASS_DENIED');
  verifyRuntimeImage();
  const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  const privateDir=privateHome();
  const user=verifyDelegateJournal(privateRead(join(privateDir,'p224-verde-delegation.private.json')));
  const authority=privateRead(join(privateDir,'p2-bootstrap-authority.private.json'));
  if(authority?.domain!==TENANT||authority?.rootOrganizationId!==ROOT ||
     authority?.state!=='verified'||!authority.resources ||
     typeof authority.resources[USERS_API]!=='string')throw Error('P224_USER_AUTHORITY_NOT_VERIFIED');
  const creds=loadAuthority(repo);
  const provider=createOAuthProvider({credentials:creds});
  const root=await provider.root(TENANT,ROOT_SCOPES);
  const switched=await provider.partner(TENANT,PARTNER,
    [...APP_SCOPES,'internal_org_organization_view'],root.access_token);
  const store=userAppJournal(privateDir),lock=store.acquire();
  let app;
  try{app=await reconcileUserApp({client:wire({token:switched.access_token}),
    usersResourceId:authority.resources[USERS_API],journal:store,write:mode==='apply'});}
  finally{store.release(lock);}
  if(app.state!=='VERIFIED'){
    process.stdout.write(JSON.stringify({...app,userTokenAcceptance:'NOT_EXECUTED'})+'\n');
    return;
  }
  const recorded=store.load();
  if(!recorded || recorded.phase!=='verified')throw Error('P224_USER_APP_PRIVATE_READBACK_UNVERIFIED');
  const accepted=await acceptance({oauth:oauth({clientId:recorded.clientId,clientSecret:recorded.clientSecret}),
    read:requestUser,clientId:recorded.clientId,username:user.username,password:user.password});
  process.stdout.write(JSON.stringify({...app,acceptance:accepted},null,2)+'\n');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{const raw=String(e.message||'P224_USER_ACCEPTANCE_BLOCKED');
    const code=/^[A-Z0-9_:.-]{3,170}$/.test(raw)?raw:'P224_USER_ACCEPTANCE_UNEXPECTED_BLOCKED';
    process.stderr.write(JSON.stringify({phase:'P2.24-USER-TOKEN',status:'BLOCKED',error:code,
      userTokenAcceptance:'NOT_VERIFIED',managementMutationState:'NOT_ASSUMED'})+'\n');
    process.exitCode=1;});
