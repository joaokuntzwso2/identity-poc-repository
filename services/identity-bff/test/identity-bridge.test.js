/** HTTP denial tests: these must run without any live WSO2 server. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

// Import the EXISTING BFF with its automatic listener disabled. No synthetic login is issued.
process.env.NODE_ENV = 'test';
process.env.IDENTITY_MODE = 'story-preview';
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:4000';
process.env.ALLOW_INSECURE_LOCAL = 'true';
delete process.env.WSO2_BFF_PRIVATE_MANIFEST;
const { handle } = await import('../src/server.js');

test('anonymous browser is not authenticated and cannot spoof WSO2 identity', async t => {
  const server = createServer(handle);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => server.close(r)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const me = await fetch(`${base}/api/identity/me`);
  assert.equal(me.status, 200);
  const record = await me.json();
  assert.equal(record.authenticated, false);
  assert.equal(record.identitySource, 'NO_VERIFIED_IDENTITY');
  assert.equal(record.capabilities.b2bAdministration, false);
  assert.equal(Object.values(record.clients).filter(c => c.authenticated).length, 0);
  assert.equal(JSON.stringify(record).includes('clientSecret'), false);
  const cookie = me.headers.get('set-cookie').split(';')[0];
  const forged = await fetch(`${base}/auth/aurora-mobile/callback?state=attacker&code=attacker`, {headers: {cookie}});
  assert.equal(forged.status, 400);
  assert.equal((await forged.json()).error, 'invalid_or_expired_oauth_state');
  const syntheticWrite = await fetch(`${base}/api/experience/consents/mock`, {
    method: 'POST', headers: { cookie, origin:'http://127.0.0.1:4000', 'x-experience-preview':'yes' }, body: '{}'
  });
  assert.equal(syntheticWrite.status, 403);
  const logout = await fetch(`${base}/api/logout`, {method:'POST', headers:{cookie, origin:'http://127.0.0.1:4000'}});
  assert.equal(logout.status, 403);
});
