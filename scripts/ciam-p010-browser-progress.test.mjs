import test from 'node:test';
import assert from 'node:assert/strict';
import {safeFailureCode,classifyBrowserLocation,waitForPortalReturn,safeClient} from './ciam-p010-browser-progress.mjs';
const BASE='http://127.0.0.1:4400';
function fake(url,fail=false) {return {url:()=>url,isClosed:()=>false,async waitForURL(pred,{timeout}) {assert.equal(timeout,7);if(fail) throw Error('Timeout with private callback?code=mustnotleak');assert.equal(pred(new URL(BASE+'/portal/aurora/web?state=mustnotleak')),true);}};}
test('recognizes client-bound meaningful failures without leaking values',()=>{
 assert.equal(safeFailureCode(Error('LIVE_LOGIN_NOT_VERIFIED_aurora-web')),'LIVE_LOGIN_NOT_VERIFIED_AURORA_WEB');
 assert.equal(safeFailureCode(Error('LIVE_USERINFO_NOT_VERIFIED_aurora-app')),'LIVE_USERINFO_NOT_VERIFIED_AURORA_APP');
 assert.equal(safeFailureCode(Error('page.goto failed http://localhost/?code=SENSITIVE')),'BROWSER_UNEXPECTED_ERROR');
 assert.equal(safeFailureCode(Error('net::ERR_CERT_AUTHORITY_INVALID at https://localhost/?state=secret')),'LOCAL_WSO2_CERTIFICATE_NOT_TRUSTED');
});
test('classifies location without including OAuth callback query',()=>{
 assert.equal(classifyBrowserLocation('https://localhost:9444/commonauth?sessionDataKey=secret',BASE),'LOCAL_WSO2_LOGIN');
 assert.equal(classifyBrowserLocation(BASE+'/auth/aurora-web/callback?code=secret',BASE),'BFF_AUTH_ROUTE');
 assert.equal(classifyBrowserLocation(BASE+'/portal/aurora/web?anything=secret',BASE),'BFF_PORTAL');
 assert.equal(classifyBrowserLocation('https://evil.test/?state=secret',BASE),'OTHER_OR_UNTRUSTED_ORIGIN');
});
test('returns only after exact BFF portal, without waiting for terminal input',async()=>{
 const result=await waitForPortalReturn(fake(BASE+'/portal/aurora/web'),BASE,'/portal/aurora/web','aurora-web','AURORA CUSTOMER',{timeoutMs:7,log:()=>{}});
 assert.equal(result.status,'PORTAL_RETURNED');
});
test('reports WSO2 login still open with a non-sensitive code',async()=>{
 await assert.rejects(waitForPortalReturn(fake('https://localhost:9444/commonauth?code=private',true),BASE,'/portal/aurora/web','aurora-web','AURORA CUSTOMER',{timeoutMs:7,log:()=>{}}), e=>{
   assert.equal(e.message,'LOGIN_STILL_ON_WSO2_AURORA_WEB');assert.equal(e.locationClass,'LOCAL_WSO2_LOGIN');return true;
 });
});
test('refuses external return path and nonregistered client',async()=>{
 await assert.rejects(waitForPortalReturn(fake(BASE),BASE,'https://evil.test/portal/aurora/web','aurora-web','BAD',{timeoutMs:7,log:()=>{}}),/UNTRUSTED_PORTAL_RETURN_PATH/);
 assert.throws(()=>safeClient('arbitrary'),/UNEXPECTED_CLIENT_KEY/);
});
test('unknown browser errors never expose URLs, code, state or session identifiers',()=>{
 for (const input of ['page.evaluate: https://localhost:9444/?code=ABCD', 'foo=state-secret', 'Unexpected token < in JSON']) {
   const result=safeFailureCode(new Error(input));assert.equal(result,'BROWSER_UNEXPECTED_ERROR');assert.equal(result.includes('ABCD'),false);
 }
});
