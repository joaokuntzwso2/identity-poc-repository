import test from 'node:test';
import assert from 'node:assert/strict';
import { readOidcUserinfoForClient as check } from '../src/oidc-userinfo-p010.js';
import { verifiedUserinfoClaims } from '../src/live-userinfo.js';
import { inspectAccessToken } from '../src/wso2-authority.js';

const issuer = 'https://localhost:9444/t/aurora.identity.test/oauth2/token';
const client = { issuer, clientId:'aurora-web-id', brand:'aurora' };
const login = { verified:true, accessToken:'never-a-real-token', claims:{
  iss:issuer, sub:'test-sub', aud:client.clientId, exp:4102444800 } };
function attempt(overrides={}) {
  return check({login,client,
    inspect: async () => ({active:true,scopes:['openid','ciam:cases:read']}),
    discovery: async () => ({userinfo_endpoint:'https://localhost:9444/t/aurora.identity.test/oauth2/userinfo'}),
    userinfo: async ({subject}) => verifiedUserinfoClaims({sub:subject, name:'Test subject'},subject),
    ...overrides});
}
test('live openid plus exact UserInfo subject verifies; no raw token or sub exposed', async () => {
  const result = await attempt();
  assert.equal(result.status,200);
  assert.equal(result.body.identitySource,'WSO2_USERINFO');
  assert.equal(result.body.brand,'aurora');
  assert.deepEqual(result.body.attributes,{name:'Test subject'});
  assert.doesNotMatch(JSON.stringify(result),/never-a-real-token|test-sub/);
});
test('no session, wrong issuer, wrong client, expired ID token fail before introspection', async () => {
  for(const candidate of [null,{...login,verified:false},
    {...login,claims:{...login.claims,iss:'https://evil.example'}},
    {...login,claims:{...login.claims,aud:'another-client'}},
    {...login,claims:{...login.claims,exp:1}},
    {...login,claims:{...login.claims,sub:''}}]) {
    const result = await attempt({login:candidate,inspect:async()=>{throw Error('must not introspect');}});
    assert.equal(result.status,401);
  }
});
test('inactive or revoked access token cannot use UserInfo',async()=> {
  assert.equal((await attempt({inspect:async()=>({active:false,scopes:[]})})).status,401);
});
test('missing openid never authorizes UserInfo even with business scopes',async()=> {
  const result=await attempt({inspect:async()=>({active:true,scopes:['ciam:cases:read','ciam:cases:approve']})});
  assert.equal(result.status,403);
});
test('WSO2 outage is 503 and fail closed',async()=> {
  const result=await attempt({inspect:async()=>{throw Error('no authority');}});
  assert.equal(result.status,503);
});
test('UserInfo wrong subject is refused without releasing attributes',async()=> {
  const result=await attempt({userinfo:async({subject})=>verifiedUserinfoClaims({sub:'attacker',email:'private@example.invalid'},subject)});
  assert.equal(result.status,502);
  assert.doesNotMatch(JSON.stringify(result),/private@example.invalid/);
});
test('UserInfo network/discovery outage is 502 and never synthesizes identity',async()=> {
  const result=await attempt({discovery:async()=>{throw Error('bad discovery');}});
  assert.equal(result.status,502);
});
test('cross-brand client substitution cannot produce a verified result',async()=> {
  const result=await attempt({client:{...client,issuer:'https://localhost:9444/t/brisa.identity.test/oauth2/token'}});
  assert.equal(result.status,401);
});

test('real introspection implementation binds the signed ID-token subject before UserInfo',async()=> {
  const clientWithSecret={...client,clientSecret:'not-real-secret'};
  const fake=(sub)=>async()=>({status:200,headers:{get:()=>null},text:async()=>JSON.stringify({
    active:true,client_id:client.clientId,sub,iss:issuer,exp:4102444800,scope:'openid'
  })});
  const inspectFor=(sub)=> (l,c)=> inspectAccessToken(l,{...c,clientSecret:clientWithSecret.clientSecret},{fetcher:fake(sub)});
  const denied=await attempt({inspect:inspectFor('wrong-sub')});
  assert.equal(denied.status,401);
  const verified=await attempt({inspect:inspectFor('test-sub')});
  assert.equal(verified.status,200);
});
