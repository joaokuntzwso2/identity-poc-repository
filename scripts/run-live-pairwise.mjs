/**
 * Interactive test against REAL WSO2 7.3. No fixture issuer or scripted pass.
 * Needs: npm install, npx playwright install chromium, running BFF/React,
 * four actual OIDC registrations, actual user login in the visible browser.
 * This verifies signed-token predicate only. Canonical identity is SEPARATE.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
const origin = process.env.E2E_BASE_URL || 'http://localhost:5173';
const required = ['aurora-web', 'aurora-app', 'brisa-web', 'brisa-app'];
if (!process.env.CONFIRM_REAL_WSO2 || process.env.CONFIRM_REAL_WSO2 !== 'yes') {
  throw new Error('Explicitly set CONFIRM_REAL_WSO2=yes after verifying a real WSO2 IS 7.3 instance is running');
}
const started = new Date().toISOString();
const browser = await chromium.launch({ headless: false });
let proof;
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: false });
  const page = await context.newPage();
  const health = await context.request.get(`${origin}/api/wso2-status`);
  if (!health.ok()) throw new Error('BFF /api/wso2-status is unavailable');
  const statuses = (await health.json()).statuses;
  if (statuses.length !== 4 || statuses.some(s => s.status !== 'DISCOVERY_REACHABLE' || !s.pairwiseAdvertised)) {
    throw new Error('Four pairwise OIDC clients must have reachable discovery before executing the browser proof');
  }
  for (const key of required) {
    console.log(`\nACTION: Authenticate the SAME synthetic customer in the visible WSO2 browser for ${key}.`);
    await page.goto(`${origin}/auth/${key}/login`, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForURL(url => url.origin === new URL(origin).origin && url.searchParams.get('client') === key, { timeout: 240000 });
    const s = await context.request.get(`${origin}/api/session`).then(r => r.json());
    if (!s.logins?.[key]?.verified) throw new Error(`No validated signed OIDC login for ${key}`);
    console.log(`Signed ID token received and validated for ${key}; sub fingerprint: ${s.logins[key].fingerprint}`);
  }
  const session = await context.request.get(`${origin}/api/session`).then(r => r.json());
  const predicate = session.pairwise;
  proof = {
    checkedAt: new Date().toISOString(), started, mode: 'LIVE_WSO2_BROWSER_LOGIN', origin,
    predicate: predicate.predicate, identifierStatus: predicate.status, checks: predicate.checks || {},
    canonicalPerson: 'NOT_VERIFIED', RFP_B01_B02: 'NOT_VERIFIED',
    evidence: required.map(key => ({ client: key, issuer: session.logins?.[key]?.issuer || null, clientId: session.logins?.[key]?.clientId || null, subjectFingerprint: session.logins?.[key]?.fingerprint || null, verified: session.logins?.[key]?.verified === true })),
    warning: 'This cannot establish the same canonical human across pairwise subjects or demonstrate admin-side sector registration.'
  };
  await mkdir('evidence', { recursive: true });
  await writeFile('evidence/live-pairwise-identifier-predicate.json', JSON.stringify(proof, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ identifierStatus: proof.identifierStatus, canonicalPerson: proof.canonicalPerson, report: 'evidence/live-pairwise-identifier-predicate.json' }, null, 2));
  if (predicate.status !== 'IDENTIFIER_PREDICATE_MET') process.exitCode = 2;
  else console.log('Identifier predicate met. STILL REQUIRED: independently attest that all four logins are the SAME canonical person and verify actual WSO2 sector assignments.');
} finally { await browser.close(); }
