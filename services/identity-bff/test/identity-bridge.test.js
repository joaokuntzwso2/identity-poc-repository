/** HTTP identity boundary test using an isolated live-only BFF, never story-preview. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { startIsolatedLiveBff } from './helpers/live-test-harness.js';

test('anonymous browser cannot spoof WSO2 identity or invoke removed preview actions', async t => {
  const { base } = await startIsolatedLiveBff(t);
  const me = await fetch(`${base}/api/identity/me`);
  assert.equal(me.status, 200);
  const record = await me.json();
  assert.equal(record.authenticated, false);
  assert.equal(record.identitySource, 'NO_VERIFIED_IDENTITY');
  assert.equal(record.capabilities.b2bAdministration, false);
  assert.equal(Object.values(record.clients).filter(c => c.authenticated).length, 0);
  assert.equal(JSON.stringify(record).includes('clientSecret'), false);
  const cookie = me.headers.get('set-cookie')?.split(';')[0];
  assert.ok(cookie, 'Identity endpoint must allocate a local anonymous session');
  const forged = await fetch(`${base}/auth/aurora-app/callback?state=attacker&code=attacker`, { headers: { cookie } });
  assert.equal(forged.status, 400);
  assert.equal((await forged.json()).error, 'invalid_oidc_callback_parameters');
  const syntheticWrite = await fetch(`${base}/api/experience/consents/mock`, {
    method: 'POST', headers: { cookie, origin: base, 'x-experience-preview': 'yes' }, body: '{}'
  });
  assert.equal(syntheticWrite.status, 503);
  assert.equal((await syntheticWrite.json()).syntheticFallback, false);
  const logout = await fetch(`${base}/api/logout`, { method: 'POST', headers: { cookie, origin: base } });
  assert.equal(logout.status, 403);
});
