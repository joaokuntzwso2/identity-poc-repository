#!/usr/bin/env node
/** Operator CLI. Reuses verified Verde client and user's credentials, no BFF route. */
import {resolve,dirname,join} from 'node:path';
import {lstatSync,readFileSync} from 'node:fs';
import {X509Certificate} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {loadAuthority,verifyRuntimeImage,createOAuthProvider} from './p2-bootstrap-auto.mjs';
import {ROOT_SCOPES} from './p2-bootstrap-core.mjs';
import {APP_SCOPES,SCOPE,verifyDelegateJournal,userAppJournal,privateRead} from './p224-user-token-core.mjs';
import {BASE,TENANT,ROOT,PARTNER,USER,API,VIEW,CREATE,REQUIRED,appBase,apiBase,orgSelf,uuid,
  store,verifyContext,validateApp,remoteAuthorization,validateToken,reconcileMember} from './p224-delegated-write-core.mjs';
const uuidPath='[a-f\\d]{8}-[a-f\\d]{4}-[1-8][a-f\\d]{3}-[89ab][a-f\\d]{3}-[a-f\\d]{12}';
const must=(x,code)=>{if(!x)throw Error(code);};
const privacy=()=>{const h=process.env.CIAM_V10_HOME||join(process.env.HOME||'','wso2-ciam-v10');
  must(h.startsWith('/')&&!h.includes('..'),'P224W_PRIVATE_HOME_INVALID');return join(h,'private');};
function validRemote(method,url,identity){
  const u=new URL(url);
  must(u.origin===BASE&&!u.username&&!u.password&&!u.hash,'P224W_REMOTE_ORIGIN_DENIED');
  const p=u.pathname;
  const allowedOwner=(method==='GET'&&!u.search&&(
      p===new URL(orgSelf).pathname ||
      new RegExp(`^${new URL(appBase).pathname}/${uuidPath}(?:/inbound-protocols/oidc|/authorized-apis)?$`,'i').test(p))) ||
    (method==='PATCH'&&!u.search&&
      new RegExp(`^${new URL(appBase).pathname}/${uuidPath}/authorized-apis/${uuidPath}$`,'i').test(p));
  const allowedUser=(method==='GET'&&!u.search&&
      new RegExp(`^${new URL(apiBase).pathname}/${uuidPath}$`,'i').test(p)) ||
    (method==='GET'&&p===new URL(apiBase).pathname&&
      /^\?startIndex=([1-9][0-9]{0,3})&count=100$/.test(u.search)) ||
    (method==='POST'&&p===new URL(apiBase).pathname&&!u.search);
  const ok=identity==='owner'?allowedOwner:identity==='user'?allowedUser:false;
  must(ok,'P224W_METHOD_OR_URL_DENIED');
  return u.href;
}
export function jsonClient(token,identity,request=fetch){
  must(typeof token==='string'&&token.length>=16&&token.length<32768&&!/\s/.test(token),
    'P224W_BEARER_UNVERIFIED');
  return async(method,url,body)=>{
    const href=validRemote(method,url,identity);
    must(method==='GET'?body===undefined:body!==undefined,'P224W_REQUEST_BODY_INVALID');
    let res;
    try{res=await request(href,{method,redirect:'manual',signal:AbortSignal.timeout(12000),
      headers:{Authorization:`Bearer ${token}`,Accept:'application/json, application/scim+json',
        ...(body!==undefined?{'Content-Type':identity==='owner'?'application/json':'application/scim+json'}:{})},
      ...(body!==undefined?{body:JSON.stringify(body)}:{})});}
    catch{throw Error('P224W_REMOTE_REQUEST_UNCERTAIN_NO_RETRY');}
    must(res.status>=200&&res.status<300,'P224W_REMOTE_HTTP_'+res.status+'_NO_RETRY');
    const text=await res.text();
    must(text.length<=262144,'P224W_RESPONSE_TOO_LARGE');
    if(!text)return {};
    try{return JSON.parse(text);}catch{throw Error('P224W_REMOTE_RESPONSE_NON_JSON');}
  };
}
async function oauth(creds,kind,data,request=fetch){
  must(kind==='token'||kind==='introspect','P224W_OAUTH_ENDPOINT_DENIED');
  const base=`${BASE}/t/${TENANT}/o/${PARTNER}/oauth2/`;
  const auth='Basic '+Buffer.from(creds.clientId+':'+creds.clientSecret).toString('base64');
  let res;
  try{res=await request(base+kind,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(12000),
    headers:{Authorization:auth,'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},
    body:new URLSearchParams(data).toString()});}
  catch{throw Error('P224W_OAUTH_REQUEST_UNAVAILABLE');}
  must(res.status===200,'P224W_OAUTH_'+kind.toUpperCase()+'_HTTP_'+res.status);
  const body=await res.text();must(body.length<=32768,'P224W_OAUTH_TOO_LARGE');
  try{return JSON.parse(body);}catch{throw Error('P224W_OAUTH_INVALID_RESPONSE');}
}
async function denyCheck(url,token,request=fetch){
  must([
    `${BASE}/t/${TENANT}/scim2/Users?startIndex=1&count=1`,
    `${BASE}/t/brisa.identity.test/o/scim2/Users?startIndex=1&count=1`,
    `${BASE}/t/${TENANT}/o/scim2/v2/Roles?startIndex=1&count=1`
  ].includes(url),'P224W_NEGATIVE_URL_DENIED');
  let res;
  try{res=await request(url,{method:'GET',redirect:'manual',signal:AbortSignal.timeout(10000),
    headers:{Authorization:`Bearer ${token}`,Accept:'application/json'}});}
  catch{throw Error('P224W_NEGATIVE_REQUEST_UNAVAILABLE');}
  must(res.status===401||res.status===403,'P224W_CROSS_TENANT_OR_ROLE_NOT_DENIED');
  return res.status;
}
export async function run(mode){
  must(['check','apply'].includes(mode),'P224W_MODE_DENIED');
  must(process.env.NODE_ENV!=='production'&&process.env.NODE_TLS_REJECT_UNAUTHORIZED!=='0',
    'P224W_PRODUCTION_OR_TLS_BYPASS_DENIED');
  const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  const cert=resolve(repo,'var/wso2/tls/wso2-local.pem');
  const stat=lstatSync(cert);
  must(stat.isFile()&&!stat.isSymbolicLink()&&
    resolve(process.env.NODE_EXTRA_CA_CERTS||'/')===cert,
    'P224W_TLS_CA_NOT_PINNED');
  const pin='2B:A3:61:A0:32:FF:D4:B3:4F:7D:F0:66:DE:72:B6:1C:5E:83:6A:09:F7:A7:BD:71:05:EB:87:B4:09:4D:97:12';
  must(new X509Certificate(readFileSync(cert)).fingerprint256.toUpperCase()===pin,
    'P224W_TLS_CERT_CHANGED');
  verifyRuntimeImage();
  const dir=privacy();
  const delegated=verifyDelegateJournal(privateRead(join(dir,'p224-verde-delegation.private.json')));
  const authority=privateRead(join(dir,'p2-bootstrap-authority.private.json'));
  must(authority?.domain===TENANT && authority?.rootOrganizationId===ROOT &&
    authority?.state==='verified'&&uuid.test(authority?.resources?.[API]),
    'P224W_BOOTSTRAP_AUTHORITY_NOT_VERIFIED');
  const userApp=userAppJournal(dir).load();
  must(userApp?.phase==='verified'&&userApp.partnerId===PARTNER&&
    userApp.roleId=== 'b199e082-cb5e-455a-8155-59fa199c9a0a' &&
    uuid.test(userApp.appId)&&typeof userApp.clientId==='string'&&
    typeof userApp.clientSecret==='string','P224W_EXISTING_USER_APP_NOT_VERIFIED');
  const provider=createOAuthProvider({credentials:loadAuthority(repo)});
  const root=await provider.root(TENANT,ROOT_SCOPES);
  const switched=await provider.partner(TENANT,PARTNER,
    [...APP_SCOPES,'internal_org_organization_view'],root.access_token);
  const owner=jsonClient(switched.access_token,'owner');
  verifyContext(await owner('GET',orgSelf));
  const app=await owner('GET',`${appBase}/${userApp.appId}`);
  const protocol=await owner('GET',`${appBase}/${userApp.appId}/inbound-protocols/oidc`);
  const credentials=validateApp({app,protocol,appId:userApp.appId,marker:userApp.marker});
  must(credentials.clientId===userApp.clientId &&
    credentials.clientSecret===userApp.clientSecret,'P224W_APP_CREDENTIALS_DRIFT');
  const j=store(dir);
  const lock=j.acquire();
  try{
    const authorization=await remoteAuthorization({request:owner,appId:userApp.appId,
      resourceId:authority.resources[API],journal:j,apply:mode==='apply'});
    if(authorization==='AUTHORIZATION_REQUIRED')return {phase:'P2.24-DELEGATED-WRITE',
      mode:'CHECK',state:'AUTHORIZATION_REQUIRED',wso2Writes:0};
    const received=await oauth(credentials,'token',{
      grant_type:'password',username:delegated.username,password:delegated.password,
      scope:REQUIRED.join(' ')});
    must(typeof received.access_token==='string','P224W_USER_TOKEN_MISSING');
    const claims=await oauth(credentials,'introspect',{token:received.access_token});
    const token=validateToken(received,claims,credentials.clientId);
    const user=jsonClient(token,'user');
    const verdict={};
    verdict.AURORA_ROOT_DENIED=await denyCheck(`${BASE}/t/${TENANT}/scim2/Users?startIndex=1&count=1`,token);
    verdict.BRISA_TENANT_DENIED=await denyCheck(`${BASE}/t/brisa.identity.test/o/scim2/Users?startIndex=1&count=1`,token);
    verdict.ROLE_ADMINISTRATION_DENIED=await denyCheck(`${BASE}/t/${TENANT}/o/scim2/v2/Roles?startIndex=1&count=1`,token);
    const output=await reconcileMember({read:user,write:user,journal:j,apply:mode==='apply'});
    return {...output,mode:mode.toUpperCase(),authorization:'EXACT_SCOPES_READBACK_VERIFIED',
      tokenAuthority:'WSO2_INTROSPECTED_EXACT_USER_ORG_AND_CLIENT',
      denials:verdict,otherPartnerWriteDenial:'NOT_EXECUTED_NO_SECOND_VERIFIED_PARTNER',
      deactivation:'NOT_EXECUTED_REQUIRES_SEPARATE_AUTHORIZATION',
      protocol:'LAB_ONLY_PASSWORD_GRANT',secretsPrinted:false};
  }finally{j.release(lock);}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  run(process.argv[2]||'check').then(x=>process.stdout.write(JSON.stringify(x,null,2)+'\n'))
    .catch(e=>{const s=String(e?.message||'P224W_UNKNOWN');const code=/^[A-Z0-9_:.\-]{4,150}$/.test(s)?s:'P224W_BLOCKED_UNEXPECTED';
      process.stderr.write(JSON.stringify({phase:'P2.24-DELEGATED-WRITE',status:'BLOCKED',error:code,
        mutationState:'NOT_ASSUMED',secretsPrinted:false})+'\n');process.exitCode=1;});
}
