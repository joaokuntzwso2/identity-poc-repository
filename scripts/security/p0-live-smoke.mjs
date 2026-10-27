/** Read-only anonymous HTTP smoke test against the existing BFF.
 * Does NOT stop WSO2, authenticate, create stateful resources, or send secrets.
 * It cannot prove a live outage or successful authenticated access by itself.
 */
import assert from 'node:assert/strict';

const base = process.env.P0_BFF_ORIGIN || 'http://127.0.0.1:4400';
const url = new URL(base);
if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname) ||
    url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
  throw new Error('P0_BFF_ORIGIN must be a plain loopback HTTP origin');
}
const neverSuccess = [
  '/api/scenarios', '/api/session', '/api/subjects/compare',
  '/api/consent', '/api/consent/check', '/api/identity/consent/record',
  '/api/identity/consent/check', '/api/experience/customer',
  '/api/retail/orders', '/api/m2m/client-credentials', '/api/operator'
];
let passed = 0;
async function get(path, method = 'GET') {
  const res = await fetch(new URL(path, base), { method, redirect:'manual', cache:'no-store', signal: AbortSignal.timeout(5000), headers: {'accept':'application/json'} });
  let data = null;
  try { data = await res.json(); } catch { throw new Error(`NON_JSON_RESPONSE ${method} ${path} HTTP ${res.status}`); }
  return { status: res.status, data };
}
for (const path of neverSuccess) {
  for (const method of ['GET','POST']) {
    const {status, data} = await get(path, method);
    assert.equal(status, 503, `${method} ${path} must be disabled in live mode`);
    assert.equal(data?.allowed, false);
    assert.equal(data?.syntheticFallback, false);
    passed++;
  }
}
for (const path of ['/api/protected/profile?client=aurora-web','/api/protected/profile?client=brisa-web']) {
  const { status, data } = await get(path);
  assert.ok([401,403,503].includes(status), `anonymous protected route ${path} returned ${status}`);
  assert.notEqual(data?.allowed, true);
  passed++;
}
const me = await get('/api/identity/me');
assert.equal(me.status, 200, 'anonymous status endpoint must remain usable');
assert.equal(me.data?.authenticated, false);
assert.equal(me.data?.operator, false);
assert.ok(Object.values(me.data?.clients || {}).every(v => !v.authenticated && (v.permissions || []).length === 0));
passed++;
for (const path of ['/aurora.html','/b2b.html','/app/fallback.js']) {
  const r = await fetch(new URL(path, base), {redirect:'manual',signal:AbortSignal.timeout(5000)});
  assert.equal(r.status, 404, `fixture UI exposed: ${path}`);
  passed++;
}
const logout = await get('/api/logout');
assert.equal(logout.status, 405);
passed++;
console.log(JSON.stringify({stage:'P0_LIVE_ANONYMOUS_SMOKE',status:'VERIFIED_LIVE_ANONYMOUS_ONLY',passed,
  noCredentialsUsed:true, wso2ShutdownPerformed:false, authorityOutageAuthenticatedTest:'NOT_VERIFIED',
  realLoginAndProtectedHttp200:'NOT_VERIFIED_BY_THIS_PROBE', consentV2:'BLOCKED'},null,2));
