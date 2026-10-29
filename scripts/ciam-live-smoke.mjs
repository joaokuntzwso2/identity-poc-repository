#!/usr/bin/env node
/** Read-only HTTP smoke checks. Does not authenticate users or create requests. */
const ORIGIN = 'http://127.0.0.1:4400';
const KEYS = ['aurora-web', 'aurora-app', 'brisa-web', 'brisa-app'];
async function json(path) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 7000);
  try {
    const res = await fetch(ORIGIN + path, { signal: ctrl.signal, redirect: 'manual', headers: { accept: 'application/json' } });
    if (!res.ok) throw Error(`HTTP_${res.status} at ${path}`);
    return await res.json();
  } finally { clearTimeout(t); }
}
try {
  const health = await json('/api/health');
  if (health.status !== 'UP') throw Error('HEALTH_NOT_UP');
  const discovery = await json('/api/wso2-status');
  if (discovery.identityMode !== 'live-wso2') throw Error('WRONG_IDENTITY_MODE');
  const actual = new Map(discovery.statuses?.map(s => [s.key, s.discovery]) || []);
  for (const key of KEYS) if (actual.get(key) !== true) throw Error(`DISCOVERY_NOT_READY_${key}`);
  console.log('PASS: BFF up; four exact OIDC clients discoverable; live-wso2');
  console.log('NOTE: This is not a login, MFA, persistence or authorization test.');
} catch (error) { console.error('CIAM_SMOKE_FAILED:', error.message); process.exitCode = 1; }
