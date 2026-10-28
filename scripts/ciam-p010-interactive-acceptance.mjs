/** Real browser acceptance. Requires operator interaction with WSO2 login/TOTP UI.
 * No credentials, codes, seeds, tokens, or cookie values are printed or stored.
 * Never produces a PASS for a flow that wasn't completed against live WSO2.
 */
import { chromium } from '@playwright/test';
import { fetchLocalWso2BrowserPin, chromiumPinnedTlsArgs } from './ciam-p010-local-cert-pin.mjs';
import { safeFailureCode, classifyBrowserLocation, waitForPortalReturn } from './ciam-p010-browser-progress.mjs';
import { mkdir, writeFile, chmod } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
const KEYS=[
 ['aurora-web','aurora','web'],['aurora-app','aurora','mobile'],
 ['brisa-web','brisa','web'],['brisa-app','brisa','mobile']
];
const base=process.env.CIAM_LIVE_BFF_BASE_URL||'http://127.0.0.1:4400';
if(process.env.CIAM_P010_LIVE_CONFIRM!=='INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE')
 throw Error('LIVE_CONFIRMATION_REQUIRED_FOR_PERSISTENT_CASE_WRITE');
const url=new URL(base);if(!['127.0.0.1','localhost'].includes(url.hostname)||url.protocol!=='http:')
 throw Error('ONLY_LOCAL_V10_BFF_SUPPORTED');
const evidence={schema:'ciam-p010.live-acceptance.v1',at:new Date().toISOString(),status:'INCOMPLETE',
  browserDriven:true,credentialsSaved:false,tokenOrCookieDataSaved:false,mfaOperatorInteractionRequired:true,
  clients:{},cases:{},denials:{}};
let browser; let activeStage='BROWSER_SETUP'; let activeClient=null; let activePage=null;
function record(client,me){const p=me.clients?.[client];return {
 issuerTenant:p?.issuer?.includes('/t/aurora.identity.test/')?'aurora':p?.issuer?.includes('/t/brisa.identity.test/')?'brisa':'UNVERIFIED',
 subjectFingerprint:p?.subjectFingerprint||null,scopes:Array.isArray(p?.permissions)?p.permissions.filter(s=>s.startsWith('ciam:cases:')):[],
 idTokenAssurance:{acrPresent:Boolean(p?.acrFromVerifiedIdToken),amrPresent:Boolean(p?.amrFromVerifiedIdToken?.length)},
 loginVerified:p?.authenticated===true,at:new Date().toISOString()};}
async function api(page,method,path,payload){return page.evaluate(async ({method,path,payload})=>{
 const me=await (await fetch('/api/identity/me',{credentials:'same-origin',cache:'no-store'})).json();
 const res=await fetch(path,{method,credentials:'same-origin',cache:'no-store',headers:{
  ...(method==='POST'?{'content-type':'application/json','x-csrf-token':me.csrf}:{})},
  body:method==='POST'?JSON.stringify(payload||{}):undefined});
 const body=await res.json().catch(()=>({error:'invalid_json'}));return {status:res.status,body};
},{method,path,payload});}
async function authenticate(key,brand,channel,note,evidenceKey=key){
 activeStage='LOGIN_'+key.toUpperCase().replaceAll('-', '_'); activeClient=key;
 const context=await browser.newContext({ignoreHTTPSErrors:false,acceptDownloads:false});
 const page=await context.newPage(); activePage=page;
 const portal=`/portal/${brand}/${channel}`;
 await page.goto(`${base}/auth/${channel==='mobile'?brand+'-mobile':key}/login?returnTo=${encodeURIComponent(portal)}`);
 const redirected=new URL(page.url());
 if (!(redirected.protocol==='https:' && redirected.hostname==='localhost' && redirected.port==='9444') &&
     !(redirected.origin===base)) throw Error('OIDC_REDIRECT_NOT_LOCAL_WSO2_OR_BFF');
 await waitForPortalReturn(page,base,portal,key,note);
 const me=await api(page,'GET','/api/identity/me');
 evidence.loginDiagnostics ??= {};
 evidence.loginDiagnostics[evidenceKey]={identityHttp:me.status,portalReturned:true,at:new Date().toISOString()};
 if(me.status!==200||!me.body.clients?.[key]?.authenticated)throw Error('LIVE_LOGIN_NOT_VERIFIED_'+key);
 const info=record(key,me.body);
 if(info.issuerTenant!==brand)throw Error('TENANT_ISSUER_MISMATCH_'+key);
 activeStage='USERINFO_'+key.toUpperCase().replaceAll('-', '_');
 const profile=await api(page,'GET',`/api/oidc/userinfo?client=${key}`);
 evidence.loginDiagnostics[evidenceKey].userInfoHttp=profile.status;
 if(profile.status!==200||profile.body.identitySource!=='WSO2_USERINFO'){
   console.error('SANITIZED_USERINFO_HTTP='+profile.status);
   throw Error('LIVE_USERINFO_NOT_VERIFIED_'+key);
 }
 info.userInfoVerified=true;info.userInfoHttp=profile.status;
 if(evidenceKey===key) evidence.clients[key]=info; else evidence.seller=info;
 return {context,page,me:me.body};
}
async function writeEvidence(){
 const dir=join(homedir(),'wso2-ciam-v10','inspection');await mkdir(dir,{recursive:true,mode:0o700});
 const name='p010-live-browser-'+new Date().toISOString().replace(/[:.]/g,'-')+'.json';
 const target=join(dir,name);await writeFile(target,JSON.stringify(evidence,null,2)+'\n',{mode:0o600,flag:'wx'});await chmod(target,0o600);
 console.log('SANITIZED_EVIDENCE_PATH='+target);
}
try{
 // Trust only this run's local WSO2 TLS public key; no global HTTPS bypass.
 const pinInfo=await fetchLocalWso2BrowserPin({confirm:process.env.CIAM_P010_LOCAL_WSO2_TLS_CONFIRM});
 evidence.localWso2Tls={mode:pinInfo.trustScope,peer:pinInfo.peer,
   certFingerprintSha256:pinInfo.certificateFingerprintSha256};
 browser=await chromium.launch({headless:false,args:chromiumPinnedTlsArgs(pinInfo)});
 const customer=await authenticate('aurora-web','aurora','web','AURORA CUSTOMER');
 activeStage='CASES_CUSTOMER_CREATE';
 const customerRead=evidence.clients['aurora-web'];
 if(!customerRead.scopes.includes('ciam:cases:create')||!customerRead.scopes.includes('ciam:cases:read'))
  throw Error('CUSTOMER_SCOPES_NOT_ISSUED');
 const created=await api(customer.page,'POST','/api/brands/aurora/cases?client=aurora-web',
   {title:'P010 acceptance - '+Date.now(),description:'Operator-authorized persistent real business acceptance'});
 evidence.cases.createHttp=created.status;
 if(created.status!==201||!created.body.id)throw Error('PERSISTENT_CUSTOMER_CASE_CREATION_FAILED');
 const caseId=created.body.id;
 const own=await api(customer.page,'GET','/api/brands/aurora/cases?client=aurora-web');
 evidence.cases.ownerReadHttp=own.status;
 if(own.status!==200||!own.body.records?.some(r=>r.id===caseId&&r.status==='OPEN'))throw Error('OWNER_VISIBILITY_FAILED');
 const denied=await api(customer.page,'GET','/api/brands/brisa/cases?client=aurora-web');
 evidence.denials.crossTenantHttp=denied.status;
 if(denied.status!==403)throw Error('CROSS_TENANT_NOT_DENIED');
 activeStage='LOGIN_OTHER_CLIENTS';
 for(const [key,brand,channel] of KEYS.slice(1)){const result=await authenticate(key,brand,channel,'TENANT USER');await result.context.close();}
 const seller=await authenticate('aurora-web','aurora','web','AURORA SELLER (separate browser)','seller');
 activeStage='CASES_SELLER_REVIEW';
 const grant=evidence.seller;
 if(!grant.scopes.includes('ciam:cases:review')||!grant.scopes.includes('ciam:cases:approve'))
   throw Error('SELLER_SCOPE_NOT_ISSUED');
 const queue=await api(seller.page,'GET','/api/brands/aurora/cases?client=aurora-web');
 evidence.cases.sellerReviewHttp=queue.status;
 if(queue.status!==200||queue.body.visibility!=='BRAND_REVIEW'||!queue.body.records.some(r=>r.id===caseId&&r.status==='OPEN'))
   throw Error('SELLER_REVIEW_NOT_VERIFIED');
 activeStage='STEPUP_START';
 const start=await api(seller.page,'POST',`/api/brands/aurora/cases/${caseId}/approve?client=aurora-web`);
 evidence.cases.stepUpStartHttp=start.status;
 if(start.status!==202||start.body.status!=='WSO2_TOTP_STEP_UP_REQUIRED'||!start.body.authorizationUrl)
   throw Error('SEPARATE_TOTP_CHALLENGE_NOT_STARTED');
 activeStage='STEPUP_BROWSER'; activePage=seller.page;
 await seller.page.goto(start.body.authorizationUrl);
 await waitForPortalReturn(seller.page,base,'/portal/aurora/web','aurora-web','SELLER TOTP STEP-UP');
 activeStage='STEPUP_BUSINESS_READBACK';
 const after=await api(seller.page,'GET','/api/brands/aurora/cases?client=aurora-web');
 evidence.cases.sellerAfterHttp=after.status;
 if(after.status!==200||!after.body.records.some(r=>r.id===caseId&&r.status==='APPROVED'))
   throw Error('REAL_TOTP_APPROVAL_NOT_ATTESTED');
 const ownerAfter=await api(customer.page,'GET','/api/brands/aurora/cases?client=aurora-web');
 evidence.cases.customerAfterHttp=ownerAfter.status;
 if(ownerAfter.status!==200||!ownerAfter.body.records.some(r=>r.id===caseId&&r.status==='APPROVED'))
   throw Error('CUSTOMER_POST_APPROVAL_STATE_NOT_VERIFIED');
 activeStage='CASES_APPROVAL_OWNER_READBACK';
 evidence.status='PASS_REAL_WSO2_FOUR_CLIENTS_AND_TOTP_APPROVAL';
 console.log('REAL_WSO2_E2E_VERIFIED_WITH_OPERATOR_INTERACTION');
 await seller.context.close();await customer.context.close();
}catch(e){evidence.status='BLOCKED_OR_FAILED';
 evidence.failureStage=activeStage;
 evidence.failureCode=safeFailureCode(e);
 evidence.failureClient=activeClient;
 // Do not write the current URL, callback query, response bodies, cookies, codes, or state.
 evidence.browserLocationClass=activePage?.isClosed()?'BROWSER_CLOSED':
   activePage?classifyBrowserLocation(activePage.url(),base):'NO_PAGE';
 console.error('LIVE_ACCEPTANCE_NOT_PASSED:'+evidence.failureCode);
 console.error('SANITIZED_FAILURE_STAGE='+activeStage);
 console.error('SANITIZED_BROWSER_LOCATION='+evidence.browserLocationClass);
 process.exitCode=2;
}finally{await writeEvidence();await browser?.close();}
