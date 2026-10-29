/** Real, bounded P0.11 operator-assisted negative acceptance.
 * Only the listed browser scenarios can emit PASS, after real WSO2 authentication.
 * Never store secrets, code, state, cookies, URLs or response bodies in evidence.
 * Requires explicit approval for any persistent case write.
 */
import { chromium } from '@playwright/test';
import { fetchLocalWso2BrowserPin, chromiumPinnedTlsArgs } from './ciam-p010-local-cert-pin.mjs';
import { waitForPortalReturn } from './ciam-p010-browser-progress.mjs';
import { mkdir, writeFile, chmod } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { browserScenario, acceptedAuthCallbackError, validateUrl } from './ciam-p011-remaining-contract.mjs';

const scenario=process.argv[2];
if (!browserScenario(scenario)) throw Error('SCENARIO_NOT_SUPPORTED');
if (process.env.CIAM_P011_SECURITY_CONFIRM !== 'RUN_THIS_LIVE_SECURITY_SCENARIO')
  throw Error('LIVE_SECURITY_APPROVAL_REQUIRED');
const writesCase=scenario !== 'expired-session';
if (writesCase && process.env.CIAM_P011_CASE_WRITE_CONFIRM !== 'CREATE_ONE_PERSISTENT_SECURITY_TEST_CASE')
  throw Error('PERSISTENT_CASE_WRITE_APPROVAL_REQUIRED');
const base=process.env.CIAM_LIVE_BFF_BASE_URL || 'http://127.0.0.1:4400';
if (!validateUrl(base)) throw Error('ONLY_LOCAL_BFF_SUPPORTED');
const evidence={schema:'ciam.p011.negative-browser.v32',at:new Date().toISOString(),
  scenario,status:'BLOCKED',evidenceClass:'LIVE_AUTHENTICATION',
  operatorInteraction:true,sourceGitSha:process.env.CIAM_P011_SOURCE_SHA || '',
  runtimeIdentity:process.env.CIAM_P011_RUNTIME_ID || '',caseId:null,
  checks:{},reason:'NOT_EXECUTED'};
let browser;
const recorded=(key,value)=>{evidence.checks[key]=value;};
async function api(page,method,path,payload){
 return page.evaluate(async ({method,path,payload})=>{
  const identity=await fetch('/api/identity/me',{cache:'no-store',credentials:'same-origin'});
  const state=await identity.json().catch(()=>({}));
  const headers=method==='POST'?{'content-type':'application/json','x-csrf-token':state.csrf||''}:{};
  const response=await fetch(path,{method,headers,credentials:'same-origin',cache:'no-store',
    body:method==='POST'?JSON.stringify(payload||{}):undefined});
  return {status:response.status,body:await response.json().catch(()=>({}))};
 },{method,path,payload});
}
async function login(key,kind){
 const brand=key.split('-')[0];
 const context=await browser.newContext({ignoreHTTPSErrors:false,acceptDownloads:false});
 const page=await context.newPage();
 const portal=`/portal/${brand}/web`;
 await page.goto(`${base}/auth/${key}/login?returnTo=${encodeURIComponent(portal)}`);
 const location=new URL(page.url());
 if (!((location.protocol==='https:'&&location.hostname==='localhost'&&location.port==='9444') || location.origin===base))
   throw Error('UNTRUSTED_IDP_REDIRECT');
 await waitForPortalReturn(page,base,portal,key,`${kind} — authenticate at WSO2`);
 const me=await api(page,'GET','/api/identity/me');
 const user=me.body?.clients?.[key];
 if (me.status!==200 || user?.authenticated!==true || !String(user.issuer||'').includes(`/t/${brand}.identity.test/`))
   throw Error('REAL_WSO2_LOGIN_NOT_ATTESTED');
 const scopes=Array.isArray(user.permissions)?user.permissions:[];
 return {page,context,scopes,subjectFingerprint:user.subjectFingerprint||null};
}
async function createCase(customer){
 if (!customer.scopes.includes('ciam:cases:create') || !customer.scopes.includes('ciam:cases:read'))
   throw Error('REAL_CREATE_SCOPE_NOT_GRANTED');
 const created=await api(customer.page,'POST','/api/brands/aurora/cases?client=aurora-web',
  {title:`P011 security ${scenario} ${randomUUID()}`.slice(0,120),
   description:'Operator-approved security negative fixture; retain for reconciliation'});
 if (created.status!==201 || !/^[a-f\d-]{36}$/i.test(created.body?.id||''))
   throw Error('LIVE_CASE_CREATION_NOT_ATTESTED');
 evidence.caseId=created.body.id;
 return created.body.id;
}
async function openCase(user,id){
 const r=await api(user.page,'GET','/api/brands/aurora/cases?client=aurora-web');
 return r.status===200 && Array.isArray(r.body.records) &&
   r.body.records.some(x=>x.id===id&&x.status==='OPEN');
}
async function stepup(seller,id){
 if (!seller.scopes.includes('ciam:cases:approve')) throw Error('SELLER_APPROVAL_SCOPE_NOT_GRANTED');
 const r=await api(seller.page,'POST',`/api/brands/aurora/cases/${id}/approve?client=aurora-web`);
 if (r.status!==202 || r.body.status!=='WSO2_TOTP_STEP_UP_REQUIRED' ||
     !validateUrl(r.body.authorizationUrl,{wso2:true})) throw Error('REAL_STEPUP_NOT_STARTED');
 const state=new URL(r.body.authorizationUrl).searchParams.get('state');
 if (typeof state!=='string' || state.length<8) throw Error('STEPUP_STATE_UNVERIFIABLE');
 return {url:r.body.authorizationUrl,ttl:r.body.expiresInSeconds,state};
}
async function realCanceledMfa(){
 const customer=await login('aurora-web','Customer');
 const id=await createCase(customer);
 const seller=await login('aurora-web','Different seller');
 if (!customer.subjectFingerprint || !seller.subjectFingerprint || customer.subjectFingerprint===seller.subjectFingerprint)
   throw Error('SEPARATE_CUSTOMER_SELLER_NOT_VERIFIED');
 const challenge=await stepup(seller,id);
 let canceled=false;
 seller.page.on('request',request=>{
   // Only inspect protocol metadata transiently in memory; never save raw callback URL.
   if (acceptedAuthCallbackError(request.url(),base,challenge.state)) canceled=true;
 });
 await seller.page.goto(challenge.url);
 // WSO2 must issue a real error callback; merely closing/navigating away is not proof.
 const deadline=Date.now()+180000;
 while (!canceled && Date.now()<deadline) await delay(500);
 recorded('realProviderCancelCallback',canceled);
 recorded('caseStillOpen',await openCase(customer,id));
 if (!canceled || evidence.checks.caseStillOpen!==true) throw Error('CANCELED_MFA_NOT_ATTESTED');
 evidence.status='PASS';
 await seller.context.close();await customer.context.close();
}
async function stalePendingTransaction(){
 // Tests expired *authorization transaction state*, not stale signed auth_time.
 const customer=await login('aurora-web','Customer');
 const id=await createCase(customer);
 const seller=await login('aurora-web','Different seller');
 if (!customer.subjectFingerprint || !seller.subjectFingerprint || customer.subjectFingerprint===seller.subjectFingerprint)
   throw Error('SEPARATE_CUSTOMER_SELLER_NOT_VERIFIED');
 const challenge=await stepup(seller,id);
 if (!Number.isInteger(challenge.ttl) || challenge.ttl<60 || challenge.ttl>600)
   throw Error('UNTRUSTED_TRANSACTION_TTL');
 const started=Date.now();
 await delay((challenge.ttl+8)*1000); // do not make BFF requests during the wait
 let callbackCode=false,callbackStatus=null;
 seller.page.on('request',request=>{
   try {
    const u=new URL(request.url());
    if (u.origin===base && u.pathname==='/auth/aurora-web/callback' &&
        u.searchParams.get('state')===challenge.state && Boolean(u.searchParams.get('code'))) callbackCode=true;
   } catch {}
 });
 seller.page.on('response',response=>{
   try {
    const u=new URL(response.url());
    if (u.origin===base && u.pathname==='/auth/aurora-web/callback' && u.searchParams.get('state')===challenge.state) callbackStatus=response.status();
   } catch {}
 });
 await seller.page.goto(challenge.url,{waitUntil:'domcontentloaded'});
 const deadline=Date.now()+180000;
 while (!callbackCode && Date.now()<deadline) await delay(500);
 await delay(1500);
 recorded('transactionTtlSeconds',challenge.ttl);
 recorded('pendingElapsedSeconds',Math.floor((Date.now()-started)/1000));
 recorded('realCodeCallback',callbackCode);
 recorded('callbackHttp',callbackStatus);
 recorded('caseStillOpen',await openCase(customer,id));
 if (!callbackCode || callbackStatus!==400 || !evidence.checks.caseStillOpen)
   throw Error('EXPIRED_STEPUP_TRANSACTION_NOT_ATTESTED');
 evidence.status='PASS';
 await seller.context.close();await customer.context.close();
}
async function liveSelfApproval(){
 const both=await login('aurora-web','Authorized dual-role self-approval fixture');
 if (!['ciam:cases:create','ciam:cases:read','ciam:cases:approve']
   .every(scope=>both.scopes.includes(scope))) throw Error('DUAL_ROLE_FIXTURE_UNAVAILABLE');
 const id=await createCase(both);
 const result=await api(both.page,'POST',`/api/brands/aurora/cases/${id}/approve?client=aurora-web`);
 recorded('selfApprovalHttp',result.status);
 recorded('caseStillOpen',await openCase(both,id));
 if (result.status!==403 || evidence.checks.caseStillOpen!==true)
   throw Error('SELF_APPROVAL_DENIAL_NOT_ATTESTED');
 evidence.status='PASS';
 await both.context.close();
}
async function liveExpiredSession(){
 const customer=await login('aurora-web','Session expiry fixture');
 const started=Date.now();
 const idleMs=3660_000; // real BFF sliding TTL is 3600 s, no requests during this wait
 await delay(idleMs);
 const me=await api(customer.page,'GET','/api/identity/me');
 const expires=me.status===200&&me.body?.clients?.['aurora-web']?.authenticated===false;
 recorded('idleSeconds',Math.floor((Date.now()-started)/1000));
 recorded('authenticatedAfterIdle',me.body?.clients?.['aurora-web']?.authenticated===true);
 if (!expires || evidence.checks.idleSeconds<3600) throw Error('REAL_SESSION_EXPIRY_NOT_ATTESTED');
 evidence.status='PASS';
 await customer.context.close();
}
async function save(){
 const dir=join(homedir(),'wso2-ciam-v10','inspection');
 await mkdir(dir,{recursive:true,mode:0o700});
 const path=join(dir,`p011-live-negative-v32-${scenario}-${new Date().toISOString().replace(/[:.]/g,'-')}-${randomUUID()}.json`);
 await writeFile(path,JSON.stringify(evidence,null,2)+'\n',{mode:0o600,flag:'wx'});
 await chmod(path,0o600);
 console.log(JSON.stringify({outcome:evidence.status,scenario,report:path,reason:evidence.reason,caseCreated:Boolean(evidence.caseId)}));
}
try {
 const pin=await fetchLocalWso2BrowserPin({confirm:process.env.CIAM_P010_LOCAL_WSO2_TLS_CONFIRM});
 browser=await chromium.launch({headless:false,args:chromiumPinnedTlsArgs(pin)});
 if (scenario==='canceled-mfa') await realCanceledMfa();
 if (scenario==='expired-stepup-transaction') await stalePendingTransaction();
 if (scenario==='self-approval') await liveSelfApproval();
 if (scenario==='expired-session') await liveExpiredSession();
 if(evidence.status==='PASS') evidence.reason='REAL_BROWSER_OBSERVATION_VERIFIED';
} catch(e){
 // Only explicit allowlisted error names; never print or persist raw exceptions or URLs.
 const code=String(e?.message||'').match(/^[A-Z0-9_]{4,100}$/)?.[0];
 evidence.reason=code||'LIVE_SCENARIO_UNAVAILABLE';
 process.exitCode=2;
}finally{await save();await browser?.close();}
