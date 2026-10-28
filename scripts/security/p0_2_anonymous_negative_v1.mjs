#!/usr/bin/env node
// Strictly anonymous GET checks against BFF 127.0.0.1:4400. No cookies or credentials.
const root = 'http://127.0.0.1:4400';
const probes = [
  ['/api/protected/profile?client=aurora-web', [401]],
  ['/api/protected/profile?client=brisa-web', [401]],
  ['/api/scenarios', [503]],
  ['/api/consent', [503]],
  ['/api/identity/consent/demo', [503]],
  ['/api/retail/catalog', [503]],
  ['/api/experience/demo', [503]],
  ['/api/identity/me', [200]],
];
const results = [];
for (const [path, expected] of probes) {
  let response, payload;
  try {
    response = await fetch(root + path, {method: 'GET', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'accept': 'application/json' }});
    payload = await response.json();
  } catch {
    results.push({path, status: 'REQUEST_FAILED', passed: false});
    continue;
  }
  let passed = expected.includes(response.status);
  if (path === '/api/identity/me') passed &&= payload?.authenticated === false && payload?.operator === false;
  if (path.startsWith('/api/protected/')) passed &&= payload?.allowed !== true;
  if (path !== '/api/identity/me') passed &&= payload?.allowed !== true;
  results.push({path, http: response.status, passed});
}
const passed = results.every(x => x.passed);
console.log(JSON.stringify({stage: 'CIAM_V10_P0_2_ANONYMOUS_NEGATIVE',
  status: passed ? 'VERIFIED_LIVE_ANONYMOUS_ONLY' : 'NOT_VERIFIED',
  checks: results, secretsUsed: false, writes: 0}, null, 2));
if (!passed) process.exitCode = 1;
