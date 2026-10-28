import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { liveApiDenial, LIVE_API_ALLOWLIST } from '../src/live-api-policy.js';
import { inspectAccessToken, requireAuthorityForClient, AuthorityUnavailable } from '../src/wso2-authority.js';
import { validateJwtClaims } from '../src/oidc.js';

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, '../src/server.js'), 'utf8');
const client = { clientId: 'fake-rp', clientSecret: 'not-a-real-secret', issuer: 'https://localhost:9444/t/aurora.identity.test/oauth2/token' };
const session = { logins: { 'aurora-web': { verified: true, accessToken: 'mock-opaque-not-a-real-token', claims: { iss: client.issuer, sub: 'bound-fixture-sub', aud: client.clientId, exp: 4102444800 } } } };
const scope = 'ciam:profile:read';
const aud = 'https://api.ciam-v10.test/profile';
const response = (v, status = 200) => async () => ({ status, headers: { get: () => null }, text: async () => JSON.stringify(v) });

test('live BFF enforces default-deny before dispatch and never starts preview mode', () => {
  assert.match(src, /import\s*\{\s*liveApiDenial\s*\}\s*from\s*['"]\.\/live-api-policy\.js['"]/);
  assert.match(src, /LIVE_WSO2_REQUIRED_NO_SYNTHETIC_MODE/);
  const handle = src.indexOf('async function handle(req, res) {');
  const gate = src.indexOf('liveApiDenial(u.pathname, req.method)', handle);
  const dispatch = src.indexOf('return await api(req, res, u, s)', handle);
  assert.ok(handle >= 0 && gate > handle && dispatch > gate, 'default-deny must precede API dispatch');
  assert.match(src, /const current = await inspectAccessToken\(login, c\)/);
  assert.match(src, /requireAuthorityForClient\(s, key, clients/);
  assert.match(src, /sessionStore\.destroy\(s, res\)/);
  assert.match(src, /exchangeAuthorizationCode\(doc,/);
  assert.match(src, /verifyIdToken\(tokens\.id_token,/);
  assert.match(src, /live-wso2\.html/);
});
test('only five known endpoint/method pairs can enter existing live handlers', () => {
  assert.deepEqual([...LIVE_API_ALLOWLIST].sort(), ['/api/health','/api/wso2-status','/api/identity/me','/api/protected/profile','/api/logout'].sort());
  for (const [path, method] of [
    ['/api/health','GET'], ['/api/wso2-status','GET'], ['/api/identity/me','GET'],
    ['/api/protected/profile','GET'], ['/api/logout','POST']
  ]) assert.equal(liveApiDenial(path, method), null);
});

test('live policy disables synthetic identity, operator, consent, retail, scenarios and fixtures', () => {
  const forbidden = [
    '/api/scenarios', '/api/session', '/api/subjects/compare', '/api/consent',
    '/api/consent/check', '/api/identity/consent', '/api/identity/consent/record',
    '/api/identity/consent/check', '/api/experience/customer', '/api/retail/orders',
    '/api/m2m/client-credentials', '/api/operator', '/api/b2b/delegate',
    '/api/identity/personas', '/api/identity/impersonate', '/api/unknown'
  ];
  for (const path of forbidden) for (const method of ['GET','POST','PUT','PATCH','DELETE']) {
    const denied = liveApiDenial(path, method);
    assert.equal(denied.status, 503, `${method} ${path}`);
    assert.equal(denied.body.allowed, false);
    assert.equal(denied.body.syntheticFallback, false);
  }
});

test('unsupported methods fail closed on allowed live paths', () => {
  for (const path of LIVE_API_ALLOWLIST) {
    const wrong = path === '/api/logout' ? 'GET' : 'POST';
    assert.equal(liveApiDenial(path, wrong)?.status, 405);
  }
});

test('fixtures cannot turn into a token or permission decision during WSO2 outage', async () => {
  const fixtureLogin = { verified: true, claims: { iss: client.issuer, sub: 'demo-persona', aud: client.clientId, exp: 4102444800 }, accessToken: 'fixture-token' };
  await assert.rejects(inspectAccessToken(fixtureLogin, client,
    { fetcher: async () => { throw Error('WSO2_UNAVAILABLE'); }, audience: aud }), AuthorityUnavailable);
  const checked = await requireAuthorityForClient({ logins: { 'aurora-web': fixtureLogin } },
    'aurora-web', { 'aurora-web': client }, scope, aud,
    async () => { throw Error('WSO2_UNAVAILABLE'); });
  assert.deepEqual(checked, { http: 503, reason: 'wso2_authority_unavailable' });
});

test('invalid, revoked, expired, wrong-client, and wrong-audience tokens deny', async () => {
  for (const data of [
    {active:false},
    {active:true,client_id:'other-client',exp:4102444800,scope,aud},
    {active:true,client_id:client.clientId,exp:1,scope,aud},
    {active:true,client_id:client.clientId,exp:4102444800,scope,aud:'client-only'}
  ]) {
    const result = await inspectAccessToken(session.logins['aurora-web'], client,
      { fetcher: response(data), audience: aud });
    assert.equal(result.active, false);
  }
});

test('anonymous and cross-tenant requests never authorize', async () => {
  const clients = { 'aurora-web': client, 'brisa-web': {...client, clientId:'brisa'} };
  const never = async () => { throw new Error('must not introspect anonymous/cross-tenant'); };
  assert.equal((await requireAuthorityForClient({ logins: {} }, 'aurora-web', clients, scope, aud, never)).http, 401);
  assert.equal((await requireAuthorityForClient(session, 'brisa-web', clients, scope, aud, never)).http, 401);
});

test('active token with no scope cannot authorize a protected action', async () => {
  const r = await requireAuthorityForClient(session, 'aurora-web', { 'aurora-web': client }, scope, aud,
    async () => ({active:true,scopes:[]}));
  assert.deepEqual(r, {http:403,reason:'wso2_scope_denied'});
});

test('no operator or consent success is available through default-deny policy', () => {
  for (const p of ['/api/m2m/client-credentials','/api/consent','/api/consent/check','/api/identity/consent/record']) {
    assert.equal(liveApiDenial(p, 'POST')?.body?.allowed, false);
  }
});


test('business API audience URI is accepted only when WSO2 introspection actually returns it', async () => {
  assert.equal(aud.length, 33);
  const data = {active:true, client_id:client.clientId, sub:session.logins['aurora-web'].claims.sub, iss:client.issuer, exp:4102444800,
    scope:'openid ciam:profile:read', aud:[client.clientId,aud]};
  const result = await inspectAccessToken(session.logins['aurora-web'], client,
    {fetcher:response(data), audience:aud});
  assert.equal(result.active, true, 'regression: valid 33-character API audience must be accepted');
  assert.ok(result.scopes.includes(scope));
});

test('issuer binding rejects cross-tenant introspection even with correct scope/audience', async () => {
  const data = {active:true, client_id:client.clientId,
    iss:'https://localhost:9444/t/brisa.identity.test/oauth2/token', exp:4102444800,
    scope, aud};
  const result = await inspectAccessToken(session.logins['aurora-web'], client,
    {fetcher:response(data), audience:aud});
  assert.equal(result.active, false);
});

test('local persona or fabricated unsigned claims cannot validate as WSO2 ID-token identity', () => {
  const c = {iss:client.issuer, aud:client.clientId, sub:'fixture-customer',
    exp:4102444800,iat:1700000000,nonce:'actual-nonce'};
  assert.throws(() => validateJwtClaims({...c, iss:'https://example.invalid'},
    {issuer:client.issuer, clientId:client.clientId, nonce:'actual-nonce',now:1700000010}));
  assert.throws(() => validateJwtClaims({...c, nonce:'persona-nonce'},
    {issuer:client.issuer, clientId:client.clientId, nonce:'actual-nonce',now:1700000010}));
  assert.throws(() => validateJwtClaims({...c, exp:1699999999},
    {issuer:client.issuer, clientId:client.clientId, nonce:'actual-nonce',now:1700000010}));
});
