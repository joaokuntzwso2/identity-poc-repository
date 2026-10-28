import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectAccessToken, requireAuthorityForClient } from '../src/wso2-authority.js';

const client = {
  clientId: 'aurora-test-client', clientSecret: 'fixture-only',
  issuer: 'https://localhost:9444/t/aurora.identity.test/oauth2/token'
};
const login = { verified: true, accessToken: 'fixture-token', claims: { iss: client.issuer, sub: 'bound-aurora-user', aud: client.clientId, exp: 4102444800 } };
const audience = 'https://api.ciam-v10.test/profile';
const fake = (data) => async () => ({
  status: 200, headers: { get: () => null }, text: async () => JSON.stringify(data)
});
const active = { active: true, client_id: client.clientId, sub: login.claims.sub, exp: 4102444800,
  scope: 'openid ciam:profile:read', aud: audience };

test('URI audience is accepted only when WSO2 returns the exact identifier', async () => {
  const r = await inspectAccessToken(login, client, { fetcher: fake(active), audience });
  assert.equal(r.active, true);
  assert.ok(r.scopes.includes('ciam:profile:read'));
  const session = { logins: { 'aurora-web': login } };
  const clients = { 'aurora-web': client };
  const decision = await requireAuthorityForClient(session, 'aurora-web', clients,
    'ciam:profile:read', audience,
    (l, c, args) => inspectAccessToken(l, c, { ...args, fetcher: fake(active) }));
  assert.equal(decision.http, 200);
});

test('missing, mismatched, and oversized audiences fail closed', async () => {
  for (const aud of [undefined, 'https://api.ciam-v10.test/other',
    'https://api.ciam-v10.test/profile/extra']) {
    const r = await inspectAccessToken(login, client,
      { fetcher: fake({ ...active, aud }), audience });
    assert.equal(r.active, false);
  }
  const huge = await inspectAccessToken(login, client,
    { fetcher: fake(active), audience: 'x'.repeat(513) });
  assert.equal(huge.active, false);
});
