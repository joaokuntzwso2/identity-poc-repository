import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectAccessToken, requireAuthorityForClient, AuthorityUnavailable } from '../src/wso2-authority.js';
import { DemoSessionStore } from '../src/session-store.js';
import { readAuthorizationResponse } from '../src/auth-callback-guards.js';
const issuer = 'https://localhost:9444/t/aurora.identity.test/oauth2/token';
const client = { issuer, clientId: 'aurora-client', clientSecret: 'test-only-secret' };
const exp = 4102444800;
const login = { verified: true, accessToken: 'not-a-real-token',
  claims: { iss: issuer, sub: 'pairwise-aurora-123', aud: 'aurora-client', exp } };
const payload = { active: true, sub: login.claims.sub, client_id: client.clientId,
  exp, scope: 'openid ciam:cases:create ciam:cases:read', aud: 'https://api.example.test/cases' };
const fake = (data, status = 200) => async (url, init) => {
  assert.equal(url, issuer.replace('/oauth2/token', '/oauth2/introspect'));
  assert.equal(init.method, 'POST');
  return { status, headers: { get: () => null }, text: async () => JSON.stringify(data) };
};
test('valid signed session and introspected subject grant matching scopes', async () => {
  const r = await inspectAccessToken(login, client, { fetcher: fake(payload), audience: payload.aud });
  assert.equal(r.active, true);
  assert.ok(r.scopes.includes('ciam:cases:create'));
});
test('subject confusion, missing subject, and wrong issuer/client/audience fail closed', async () => {
  for (const altered of [
    { sub: 'other-user' }, { sub: undefined }, { iss: 'https://wrong.example' },
    { client_id: 'brisa-client' }, { aud: 'other-api' }, { exp: 10 },
  ]) {
    const r = await inspectAccessToken(login, client, {
      fetcher: fake({ ...payload, ...altered }), audience: payload.aud });
    assert.equal(r.active, false, JSON.stringify(Object.keys(altered)));
  }
});
test('session claims cannot be missing, wrong-tenant, wrong-client or expired', async () => {
  const variants = [
    { ...login, claims: undefined },
    { ...login, claims: { ...login.claims, sub: undefined } },
    { ...login, claims: { ...login.claims, iss: 'https://wrong.example' } },
    { ...login, claims: { ...login.claims, aud: 'another-client' } },
    { ...login, claims: { ...login.claims, azp: 'another-client' } },
    { ...login, claims: { ...login.claims, exp: 1 } },
  ];
  for (const candidate of variants) {
    const r = await inspectAccessToken(candidate, client, { fetcher: () => {
      throw new Error('network must not be called for invalid session');
    }});
    assert.equal(r.active, false);
  }
});
test('revoked or unavailable WSO2 authority cannot grant access', async () => {
  assert.equal((await inspectAccessToken(login,client,{fetcher:fake({active:false})})).active,false);
  await assert.rejects(inspectAccessToken(login,client,{fetcher: async () => {throw Error('down');}}), AuthorityUnavailable);
});
test('scope and audience are separate constraints from identity', async () => {
  const denied = await inspectAccessToken(login,client,{
    fetcher:fake({ ...payload, scope:'openid' }), audience:payload.aud });
  assert.equal(denied.active,true);
  assert.ok(!denied.scopes.includes('ciam:cases:approve'));
  const result = await requireAuthorityForClient({ logins: {'aurora-web':login} }, 'aurora-web',
    {'aurora-web':client},'ciam:cases:approve', payload.aud,
    async () => denied);
  assert.equal(result.http,403);
});
test('callback rejects duplicated state/code, ambiguous error and invalid state', () => {
  const state = 'A'.repeat(43);
  const good = path => readAuthorizationResponse(new URL('http://127.0.0.1:4400/auth/aurora-web/callback'+path));
  assert.deepEqual(good(`?state=${state}&code=abc`), {valid:true,state,code:'abc'});
  for (const p of [`?state=${state}&state=${state}&code=a`,
    `?state=${state}&code=a&code=b`, `?state=${state}&code=a&error=access_denied`,
    '?state=weak&code=a', `?state=${state}&code=`]) {
    assert.equal(good(p).valid,false);
  }
});
test('session cookie parser rejects duplicate and malformed IDs', () => {
  const store = new DemoSessionStore();
  const one = 'A'.repeat(43), two = 'B'.repeat(43);
  assert.equal(store.parseCookie({headers:{cookie:`poc_sid=${one}`}}),one);
  assert.equal(store.parseCookie({headers:{cookie:`poc_sid=${one}; poc_sid=${two}`}}),null);
  assert.equal(store.parseCookie({headers:{cookie:'poc_sid=bad!'}}),null);
});
