import test from 'node:test';
import assert from 'node:assert/strict';
import { startIsolatedLiveBff } from './helpers/live-test-harness.js';

let base, close;
test.before(async () => { ({ base, close } = await startIsolatedLiveBff()); });
test.after(async () => { await close?.(); });

test('health works and synthetic scenario metadata remains disabled over HTTP', async () => {
  const health = await fetch(`${base}/api/health`).then(r => r.json());
  assert.equal(health.status, 'UP');
  const scenarios = await fetch(`${base}/api/scenarios`);
  assert.equal(scenarios.status, 503);
  assert.deepEqual(await scenarios.json(), { error: 'wso2_authoritative_integration_not_available', allowed: false, syntheticFallback: false });
});
test('both brand sector documents retain independent registered callback URIs', async () => {
  for (const brand of ['aurora', 'brisa']) {
    const response = await fetch(`${base}/oidc/sector/${brand}.json`);
    assert.equal(response.status, 200);
    const uris = await response.json();
    assert.deepEqual(uris, [`${base}/auth/${brand}-web/callback`, `${base}/auth/${brand}-app/callback`]);
  }
});
test('operator-only M2M remains disabled over live HTTP even for anonymous POST', async () => {
  const r = await fetch(`${base}/api/m2m/client-credentials`, { method: 'POST' });
  assert.equal(r.status, 503);
  assert.equal((await r.json()).allowed, false);
});
test('unproven OIDC callback cannot establish a session', async () => {
  const r = await fetch(`${base}/auth/aurora-web/callback?state=attacker&code=attacker`, { redirect: 'manual' });
  assert.equal(r.status, 400);
  assert.notEqual(r.headers.get('location')?.includes('authenticated=1'), true);
});
test('anonymous identity response discloses no bearer token or verified identity', async () => {
  const r = await fetch(`${base}/api/identity/me`);
  assert.equal(r.status, 200);
  const result = await r.json();
  assert.equal(result.identitySource, 'NO_VERIFIED_IDENTITY');
  assert.equal(result.authenticated, false);
  assert.ok(Object.values(result.clients).every(x => x.authenticated === false));
  assert.equal(JSON.stringify(result).includes('never-real-test-only'), false);
});
test('public health and sector endpoints allocate no session cookie', async () => {
  for (const path of ['/api/health', '/oidc/sector/aurora.json', '/oidc/sector/brisa.json']) {
    const r = await fetch(base + path);
    assert.equal(r.headers.get('set-cookie'), null, `Public endpoint set a cookie: ${path}`);
  }
});
test('preview consent mutation is disabled independently of CSRF or identity', async () => {
  const r = await fetch(`${base}/api/consent`, { method: 'POST', headers: { origin: base, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(r.status, 503);
  const result = await r.json();
  assert.equal(result.allowed, false);
  assert.equal(result.syntheticFallback, false);
});
