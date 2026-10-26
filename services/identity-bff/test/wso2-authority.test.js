import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectAccessToken, introspectionUrl, requireAuthorityForClient, AuthorityUnavailable } from '../src/wso2-authority.js';
const client = { clientId: 'rp-client', clientSecret: 'secret', issuer: 'https://localhost:9444/t/aurora.identity.test/oauth2/token' };
const login = { verified: true, accessToken: 'secret-token' };
const fake = (data, status = 200) => async (url, init) => {
  assert.equal(url, 'https://localhost:9444/t/aurora.identity.test/oauth2/introspect');
  assert.equal(init.method, 'POST');
  assert.match(init.body, /token=secret-token/);
  return { status, headers: { get: () => null }, text: async () => JSON.stringify(data) };
};
test('tenant-pinned introspection endpoint', () => {
  assert.equal(introspectionUrl(client.issuer), 'https://localhost:9444/t/aurora.identity.test/oauth2/introspect');
  assert.throws(() => introspectionUrl('https://evil.example/oauth2/authorize'), AuthorityUnavailable);
});
test('issued scopes honored, not invented', async () => {
  const result = await inspectAccessToken(login, client, { fetcher: fake({ active: true, client_id: client.clientId, exp: 4102444800, scope: 'openid ciam:profile:read', aud: 'ciam-api' }) });
  assert.deepEqual(result.scopes, ['openid','ciam:profile:read']);
  assert.equal(result.active, true);
});
test('invalid, wrong-client and expired tokens denied', async () => {
  for (const data of [{active:false}, {active:true,client_id:'other',exp:4102444800}, {active:true,client_id:'rp-client',exp:1}]) {
    const r = await inspectAccessToken(login, client, {fetcher: fake(data)});
    assert.equal(r.active, false);
  }
});
test('WSO2 outage fails closed', async () => {
  await assert.rejects(inspectAccessToken(login, client, {fetcher: async () => { throw Error('offline'); }}), AuthorityUnavailable);
});
test('audience and scope checked for protected requests', async () => {
  const s = { logins: { 'aurora-web': login } }, clients = { 'aurora-web':client };
  const yes = await requireAuthorityForClient(s,'aurora-web',clients,'ciam:profile:read','ciam-api',async()=>({active:true,scopes:['ciam:profile:read']}));
  const noScope = await requireAuthorityForClient(s,'aurora-web',clients,'ciam:profile:read','ciam-api',async()=>({active:true,scopes:[]}));
  const noConfig = await requireAuthorityForClient(s,'aurora-web',clients,'ciam:profile:read','',async()=>({active:true,scopes:['ciam:profile:read']}));
  assert.equal(yes.http,200); assert.equal(noScope.http,403); assert.equal(noConfig.http,503);
});
test('does not report positive scopes after wrong audience', async () => {
  const r = await inspectAccessToken(login,client,{fetcher:fake({active:true,client_id:client.clientId,exp:4102444800,scope:'ciam:profile:read',aud:'not-the-api'}),audience:'ciam-api'});
  assert.equal(r.active,false);
});
