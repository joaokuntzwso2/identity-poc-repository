import test from 'node:test';
import assert from 'node:assert/strict';
import { makePartnerPortalHandler, PARTNER_CALLBACK_PATH, PARTNER_LOGIN_PATH,
  loadPartnerPortalClient } from '../src/partner-portal-route.js';
const origin='http://localhost:4000';
const callback=origin+PARTNER_CALLBACK_PATH;
const issuer='https://localhost:9444/t/aurora.identity.test/oauth2/token';
const client={issuer,clientId:'partner-client-unique',clientSecret:'long-secret-12345',redirectUri:callback};
const clients={'aurora-web':{clientId:'existing-aurora-web',issuer}};
function res(){return {status:0,headers:{},body:'',writeHead(status,headers){this.status=status;this.headers=headers;},end(data){this.body=data||'';}};}
function harness({loaded=client,verified=true,active=true,now=100000}={}) {
  let calls={exchange:0,inspect:0,verify:0,discover:0};
  const route=makePartnerPortalHandler({
    load:()=>loaded,now:()=>now,newRandom:(n)=>n===32?'s'.repeat(43):'n'.repeat(40),
    discoverIssuer:async()=>{calls.discover++;return {authorization_endpoint:issuer.replace('token','authorize')};},
    authorize:(_,p)=>{assert.equal(p.scope,'openid');assert.equal(p.redirectUri,callback);
      return `https://localhost:9444/oauth2/authorize?state=${p.state}`;},
    exchange:async(_doc,args)=>{calls.exchange++;assert.equal(args.clientId,client.clientId);
      assert.equal(args.redirectUri,callback);return {id_token:'signed',access_token:'opaque'};},
    verify:async(_id,args)=>{calls.verify++;assert.equal(args.issuer,issuer);
      assert.equal(args.clientId,client.clientId);assert.equal(args.nonce,'n'.repeat(40));
      if(!verified)throw Error('signature rejected');
      return {iss:issuer,sub:'subject',aud:client.clientId,exp:999999};},
    inspect:async()=>{calls.inspect++;return {active};},
  });
  const s={pending:Object.create(null),logins:Object.create(null)};
  let rotated=0;
  async function call(path,method='GET'){
    const r=res();const u=new URL(path,origin);
    const consumed=await route({req:{method},res:r,u,s,origin,clients,
      rotate:()=>{rotated++;s.pending=Object.create(null);}});
    return {r,consumed};
  }
  return {call,calls,s,rotated:()=>rotated};
}
test('partner callback route is independent of four consumer channels',async()=>{
  const h=harness();const r=await h.call('/auth/aurora-web/callback');
  assert.equal(r.consumed,false);assert.equal(h.s.partnerPortalLogin,undefined);
});
test('unshared/unprovisioned app rejects login before OIDC calls',async()=>{
  const h=harness({loaded:null});for(const path of [PARTNER_LOGIN_PATH,PARTNER_CALLBACK_PATH+'?state=x']){
    const {r,consumed}=await h.call(path);assert.equal(consumed,true);assert.equal(r.status,503);
  }assert.equal(h.calls.discover,0);assert.equal(h.calls.exchange,0);
});
test('POST and malformed login query cannot initiate OAuth',async()=>{
  const h=harness();assert.equal((await h.call(PARTNER_LOGIN_PATH,'POST')).r.status,405);
  assert.equal((await h.call(PARTNER_LOGIN_PATH+'?returnTo=https://evil.test')).r.status,400);
  assert.equal(Object.keys(h.s.pending).length,0);
});
test('login emits state-bound PKCE authorization without broad scopes',async()=>{
  const h=harness();const {r}=await h.call(PARTNER_LOGIN_PATH);assert.equal(r.status,302);
  assert.equal(r.headers['cache-control'],'no-store');
  assert.equal(Object.keys(h.s.pending).length,1);
  assert.equal(h.s.pending['s'.repeat(43)].clientId,client.clientId);
});
test('signed ID token and live introspection required; isolated partner session only',async()=>{
  const h=harness();await h.call(PARTNER_LOGIN_PATH);
  const {r}=await h.call(PARTNER_CALLBACK_PATH+'?state='+'s'.repeat(43)+'&code=real');
  assert.equal(r.status,302);assert.equal(h.rotated(),1);
  assert.equal(h.calls.exchange,1);assert.equal(h.calls.verify,1);assert.equal(h.calls.inspect,1);
  assert.equal(h.s.partnerPortalLogin.verified,true);
  assert.equal(Object.keys(h.s.logins).length,0);
  assert.equal(Object.keys(h.s.pending).length,0);
});
test('state is single use and replay rejected',async()=>{
  const h=harness();await h.call(PARTNER_LOGIN_PATH);const url=PARTNER_CALLBACK_PATH+'?state='+'s'.repeat(43)+'&code=x';
  assert.equal((await h.call(url)).r.status,302);
  assert.equal((await h.call(url)).r.status,400);assert.equal(h.calls.exchange,1);
});
test('wrong channel, client binding, and callback ambiguity are rejected',async()=>{
  const h=harness();await h.call(PARTNER_LOGIN_PATH);
  const state='s'.repeat(43);h.s.pending[state].key='aurora-web';
  assert.equal((await h.call(PARTNER_CALLBACK_PATH+'?state='+state+'&code=x')).r.status,400);
  h.s.pending[state].key='aurora-partner-web';h.s.pending[state].clientId='another-client';
  assert.equal((await h.call(PARTNER_CALLBACK_PATH+'?state='+state+'&code=x')).r.status,400);
  h.s.pending[state].clientId=client.clientId;
  assert.equal((await h.call(PARTNER_CALLBACK_PATH+'?state='+state+'&code=x&code=y')).r.status,400);
  assert.equal(h.calls.exchange,0);
});
test('expired state never triggers exchange',async()=>{
  const h=harness({now:400001});h.s.pending['s'.repeat(43)]={
    key:'aurora-partner-web',clientId:client.clientId,redirectUri:callback,at:1,nonce:'n',verifier:'v'};
  assert.equal((await h.call(PARTNER_CALLBACK_PATH+'?state='+'s'.repeat(43)+'&code=x')).r.status,400);
  assert.equal(h.calls.exchange,0);
});
test('provider error consumes pending state and returns safe error',async()=>{
  const h=harness();await h.call(PARTNER_LOGIN_PATH);
  assert.equal((await h.call(PARTNER_CALLBACK_PATH+'?state='+'s'.repeat(43)+'&error=access_denied')).r.status,400);
  assert.equal(h.s.pending['s'.repeat(43)],undefined);
  assert.equal(h.calls.exchange,0);
});
test('failed ID token signature never creates session',async()=>{
  const h=harness({verified:false});await h.call(PARTNER_LOGIN_PATH);
  assert.equal((await h.call(PARTNER_CALLBACK_PATH+'?state='+'s'.repeat(43)+'&code=x')).r.status,403);
  assert.equal(h.s.partnerPortalLogin,undefined);
});
test('inactive WSO2 access token never creates session',async()=>{
  const h=harness({active:false});await h.call(PARTNER_LOGIN_PATH);
  assert.equal((await h.call(PARTNER_CALLBACK_PATH+'?state='+'s'.repeat(43)+'&code=x')).r.status,403);
  assert.equal(h.s.partnerPortalLogin,undefined);
});
test('foreign tenant and consumer-client reuse are always refused',async()=>{
  for (const change of [{issuer:'https://localhost:9444/t/brisa.identity.test/oauth2/token'},
                          {clientId:clients['aurora-web'].clientId}]){
    const h=harness({loaded:{...client,...change}});
    assert.equal((await h.call(PARTNER_LOGIN_PATH)).r.status,503);
    assert.equal(h.calls.exchange,0);
  }
});
test('production private reader denies absent sharing proof',()=>{
  assert.equal(loadPartnerPortalClient({origin,clients,privateDir:'/nonexistent'}),null);
});
