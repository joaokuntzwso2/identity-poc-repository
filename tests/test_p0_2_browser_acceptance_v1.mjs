import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const source = readFileSync(new URL('../scripts/security/p0_2_browser_acceptance_v1.js', import.meta.url), 'utf8');
const ORIGIN = 'http://127.0.0.1:4400';
function setup({ profile = 200, others = false, origin = ORIGIN } = {}) {
  const bag = new Map();
  const logs = [];
  const window = {};
  const mocks = {
    '/api/identity/me': {s: 200, b: {identitySource:'WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN', authenticated:true,
      clients: {'aurora-web': {authenticated:true}, 'brisa-web':{authenticated:others}, 'aurora-app':{authenticated:false}, 'brisa-app':{authenticated:false}}}},
    '/api/protected/profile?client=aurora-web': {s:profile, b: profile === 200
      ? {allowed:true,authorizedBy:'WSO2_ACTIVE_ACCESS_TOKEN_SCOPE'}
      : profile === 401 ? {allowed:false,error:'access_token_inactive'}
      : profile === 403 ? {allowed:false,error:'wso2_scope_denied'}
      : {allowed:false,error:'wso2_authority_unavailable'}},
    '/api/protected/profile?client=brisa-web': {s:401,b:{allowed:false,error:'authentication_required'}},
    '/api/scenarios': {s:503,b:{error:'blocked'}},
    '/api/consent': {s:503,b:{error:'blocked'}},
  };
  const context = { window, location:{origin}, console:{log:x=>logs.push(x)},
    sessionStorage: {getItem:k=>bag.get(k)??null,setItem:(k,v)=>bag.set(k,v)},
    fetch: async (url,opts) => { assert.equal(opts.method,'GET'); assert.equal(opts.credentials,'same-origin');
      const q=mocks[url.substring(ORIGIN.length)]; if(!q) throw new Error('unexpected url');
      return {status:q.s,text:async()=>JSON.stringify(q.b)}; }, Date, JSON, Error, Object, Number };
  return {context, mocks, bag, window, logs};
}
test('baseline verifies 200 and negative endpoints without secrets', async()=>{
  const env=setup(); vm.runInNewContext(source,env.context); const r=await env.window.CIAMV10Acceptance.baseline();
  assert.equal(r.status,'VERIFIED_BROWSER_BASELINE');assert.equal(r.secretsRead,false);
  assert.equal(r.statuses.crossClient,401);
});
test('wrong origin stops before fetching',()=>{
  const env=setup({origin:'http://localhost:4000'});assert.throws(()=>vm.runInNewContext(source,env.context),/REFUSE_WRONG_ORIGIN/);
});
test('no baseline refuses after call',async()=>{
  const env=setup();vm.runInNewContext(source,env.context);
  await assert.rejects(env.window.CIAMV10Acceptance.after(),/REFUSE_BASELINE_NOT_CAPTURED/);
});
test('cross-client authenticated refuses baseline',async()=>{
  const env=setup({others:true});vm.runInNewContext(source,env.context);
  await assert.rejects(env.window.CIAMV10Acceptance.baseline(),/REFUSE_OTHER_CLIENT_IN_SAME_SESSION/);
});
for(const [code,expected] of [[401,'INACTIVE_TOKEN_DENIED_REVOCATION_CAUSE_UNVERIFIED'],[403,'ACTIVE_TOKEN_SCOPE_DENIED_PERMISSION_CAUSE_UNVERIFIED'],[503,'WSO2_AUTHORITY_UNAVAILABLE_DENIED_NOT_REVOCATION_EVIDENCE'],[200,'NOT_ACCEPTED']]){
 test(`after baseline classifies ${code} without claiming proven revocation`,async()=>{
  const env=setup();vm.runInNewContext(source,env.context);await env.window.CIAMV10Acceptance.baseline();
  env.mocks['/api/protected/profile?client=aurora-web']={s:code,b:code===200?{allowed:true}:
    {allowed:false,error:code===401?'access_token_inactive':code===403?'wso2_scope_denied':'wso2_authority_unavailable'}};
  const r=await env.window.CIAMV10Acceptance.after();assert.equal(r.disposition,expected);
  assert.equal(r.managementWrites,0);
 });
}
