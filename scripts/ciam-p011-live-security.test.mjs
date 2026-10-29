import test from 'node:test';
import assert from 'node:assert/strict';
import {observedCallbackIsLocal,replayConsumedCallback,denyUnsolicitedCallback,observeBffLogout} from './ciam-p011-live-security.mjs';
const base='http://127.0.0.1:4400';
const legitimate=base+'/auth/aurora-web/callback?state=opaque&code=secret-code';
test('only a real local callback with state/code can be replayed',()=>{
 assert.equal(observedCallbackIsLocal(legitimate,base),true);
 for (const value of [base+'/auth/aurora-web/login?state=x&code=y',
  'https://evil.example/auth/aurora-web/callback?state=x&code=y',
  'http://localhost:4400/auth/aurora-web/callback?state=x&code=y',
  base+'/auth/aurora-web/callback?state=x',
  base+'/auth/aurora-web/callback?state=&code=y'])
  assert.equal(observedCallbackIsLocal(value,base),false);
});
test('real replay sends one request with redirect disabled and returns numeric status only',async()=>{
 let calls=0;
 const context={request:{get:async (url,opts)=>{calls++;assert.equal(url,legitimate);
  assert.equal(opts.maxRedirects,0);return {status:()=>400};}}};
 assert.equal(await replayConsumedCallback(context,legitimate,base),400);
 assert.equal(calls,1);
 assert.equal(await replayConsumedCallback(context,'https://evil.example/?code=x&state=y',base),null);
 assert.equal(calls,1);
});
test('unissued state is tested against actual BFF endpoint and is not called MFA cancellation',async()=>{
 const context={request:{get:async (url,opts)=>{
  assert.equal(new URL(url).pathname,'/auth/aurora-web/callback');
  assert.equal(opts.maxRedirects,0);return {status:()=>400};}}};
 assert.equal(await denyUnsolicitedCallback(context,base),400);
});
test('timeouts never turn into PASS',async()=>{
 const ctx={request:{get:async()=>{throw Error('private credential');}}};
 assert.equal(await replayConsumedCallback(ctx,legitimate,base),null);
 assert.equal(await denyUnsolicitedCallback(ctx,base),null);
});
test('logout records statuses and booleans without copying sensitive response contents',async()=>{
 const customerPage={evaluate:async()=>({logoutHttp:200,customerSessionDestroyed:true,wso2GlobalLogoutClaimed:false})};
 const sellerPage={evaluate:async()=>true};
 assert.deepEqual(await observeBffLogout(customerPage,sellerPage),{
  logoutHttp:200,customerSessionDestroyed:true,sellerSessionIndependent:true,wso2GlobalLogoutClaimed:false});
});
test('logout unavailable is blocked, not PASS',async()=>{
 const customerPage={evaluate:async()=>{throw Error('Bearer SECRET_VALUE');}};
 const sellerPage={evaluate:async()=>true};
 assert.deepEqual(await observeBffLogout(customerPage,sellerPage),{
  logoutHttp:null,customerSessionDestroyed:null,sellerSessionIndependent:null,wso2GlobalLogoutClaimed:null});
});
