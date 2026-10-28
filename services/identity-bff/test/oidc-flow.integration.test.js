/** Test-only OIDC over HTTPS; never WSO2 live credentials or preview persona mode. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpsServer } from 'node:https';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startIsolatedLiveBff } from './helpers/live-test-harness.js';

const sub = 'pairwise-signed-oidc-test-user';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = keys.publicKey.export({ format: 'jwk' });
Object.assign(jwk, { kid: 'test-only-jwk', use: 'sig', alg: 'RS256' });
function signIdToken(issuer, clientId, nonce) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ kid: jwk.kid, alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ iss: issuer, aud: clientId, sub, nonce, iat: now, exp: now + 300 })).toString('base64url');
  const signature = sign('RSA-SHA256', Buffer.from(`${header}.${body}`), keys.privateKey).toString('base64url');
  return `${header}.${body}.${signature}`;
}
async function httpsFixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'ciam-v10-oidc-test-'));
  const key = join(dir, 'local-test.key');
  const cert = join(dir, 'local-test.crt');
  const cfg = join(dir, 'local-test.cnf');
  const config = '[req]\ndistinguished_name=dn\nx509_extensions=v3_req\nprompt=no\n[dn]\nCN=127.0.0.1\n[v3_req]\nbasicConstraints=CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n';
  await writeFile(cfg, config, { mode: 0o600 });
  execFileSync('openssl', ['req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-keyout', key,
    '-out', cert, '-days', '1', '-config', cfg, '-extensions', 'v3_req'], { stdio: 'ignore' });
  await chmod(key, 0o600);
  let origin;
  let challenge = null, nonce = null, mismatchSub = false, introspections = 0;
  const provider = createHttpsServer({ key: await readFile(key), cert: await readFile(cert) }, async (req, res) => {
    const u = new URL(req.url, origin);
    const match = /^\/t\/(aurora|brisa)\.identity\.test\/oauth2\/(.+)$/.exec(u.pathname);
    const brand = match?.[1];
    const action = match?.[2];
    if (!brand) { res.writeHead(404); return res.end('{}'); }
    const issuer = `${origin}/t/${brand}.identity.test/oauth2/token`;
    const clientId = `${brand}-web-offline-test-only`;
    const clientSecret = `${brand}-web-never-real-test-only`;
    const respond = (status, data) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(data));
    };
    if (action === 'token/.well-known/openid-configuration' && req.method === 'GET') {
      return respond(200, { issuer, authorization_endpoint: `${origin}/t/${brand}.identity.test/oauth2/authorize`,
        token_endpoint: issuer, jwks_uri: `${origin}/t/${brand}.identity.test/oauth2/jwks` });
    }
    if (action === 'jwks' && req.method === 'GET') return respond(200, { keys: [jwk] });
    if (action === 'token' && req.method === 'POST') {
      let body = ''; for await (const c of req) body += c;
      const f = new URLSearchParams(body);
      const pkce = createHash('sha256').update(f.get('code_verifier') || '').digest('base64url');
      const authorization = req.headers.authorization;
      if (brand !== 'aurora' || f.get('code') !== 'signed-fixture-code' ||
          pkce !== challenge || !nonce ||
          authorization !== `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`) {
        return respond(400, { error: 'invalid_grant' });
      }
      return respond(200, { access_token: 'local-opaque-test-token', id_token: signIdToken(issuer, clientId, nonce),
        token_type: 'Bearer', expires_in: 300 });
    }
    if (action === 'introspect' && req.method === 'POST') {
      introspections += 1;
      return respond(200, { active: true, client_id: clientId, iss: issuer,
        sub: mismatchSub ? 'wrong-test-subject' : sub,
        exp: Math.floor(Date.now()/1000)+300, scope: 'openid', aud: clientId });
    }
    return respond(404, { error: 'unknown_mock_endpoint' });
  });
  await new Promise((resolve, reject) => provider.once('error', reject).listen(0, '127.0.0.1', resolve));
  origin = `https://127.0.0.1:${provider.address().port}`;
  t.after(async () => {
    await new Promise(resolve => provider.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });
  return { origin, caCert: cert, expectAuthorization(c, n) { challenge = c; nonce = n; },
    setMismatch() { mismatchSub = true; }, introspectionCount: () => introspections };
}

test('isolated HTTPS OIDC signed callback binds subject and rejects preview consent and subject confusion', async t => {
  const idp = await httpsFixture(t);
  const { base } = await startIsolatedLiveBff(t, { idpOrigin: idp.origin, caCert: idp.caCert });
  const start = await fetch(`${base}/auth/aurora-web/login`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const beforeCookie = start.headers.get('set-cookie')?.split(';')[0];
  assert.ok(beforeCookie);
  const url = new URL(start.headers.get('location'));
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  idp.expectAuthorization(url.searchParams.get('code_challenge'), url.searchParams.get('nonce'));
  const state = url.searchParams.get('state');
  const callback = await fetch(`${base}/auth/aurora-web/callback?code=signed-fixture-code&state=${encodeURIComponent(state)}`, {
    headers: { cookie: beforeCookie }, redirect: 'manual'
  });
  assert.equal(callback.status, 302);
  const afterCookie = callback.headers.get('set-cookie')?.split(';')[0];
  assert.ok(afterCookie);
  assert.notEqual(afterCookie, beforeCookie, 'Verified login must rotate cookie');
  assert.equal(callback.headers.get('referrer-policy'), 'no-referrer');
  const old = await fetch(`${base}/api/identity/me`, { headers: { cookie: beforeCookie } }).then(r => r.json());
  assert.equal(old.authenticated, false);
  const current = await fetch(`${base}/api/identity/me`, { headers: { cookie: afterCookie } }).then(r => r.json());
  assert.equal(current.authenticated, true);
  assert.equal(current.clients['aurora-web'].authenticated, true);
  assert.equal(current.clients['brisa-web'].authenticated, false);
  assert.ok(idp.introspectionCount() > 0);
  assert.ok(!JSON.stringify(current).includes('local-opaque-test-token'));
  const consent = await fetch(`${base}/api/consent`, { method: 'POST',
    headers: { cookie: afterCookie, origin: base, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(consent.status, 503);
  assert.equal((await consent.json()).syntheticFallback, false);
  const crossTenant = await fetch(`${base}/api/brands/brisa/profile?client=aurora-web`, { headers: { cookie: afterCookie } });
  assert.equal(crossTenant.status, 403);
  idp.setMismatch();
  const confused = await fetch(`${base}/api/identity/me`, { headers: { cookie: afterCookie } }).then(r => r.json());
  assert.equal(confused.authenticated, false, 'Introspection with different sub cannot authorize');
});
