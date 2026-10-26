import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validatePrivateClients, loadPrivateWso2Clients } from '../src/wso2-private.js';

const origin = 'http://127.0.0.1:4000';
const fixture = () => ({ clients: Object.fromEntries(['aurora-web','aurora-mobile','brisa-web','brisa-mobile'].map(k => {
  const brand = k.split('-')[0];
  return [k, { tenantDomain: `${brand}.identity.test`, clientId: `oidc-${k}`, clientSecret: `local-test-only-${k}`,
    issuer: `https://127.0.0.1:9443/t/${brand}.identity.test/oauth2/token`, callback: `${origin}/auth/${k}/callback` }];
})) });
test('four explicit clients map mobile callbacks to app keys without exposing tokens', () => {
  const result = validatePrivateClients(fixture(), { origin });
  assert.deepEqual(Object.keys(result).sort(), ['aurora-app','aurora-web','brisa-app','brisa-web']);
  assert.equal(result['aurora-app'].redirectUri, `${origin}/auth/aurora-mobile/callback`);
});
test('rejects cross-tenant issuer and callback substitution and duplicate client IDs', () => {
  const f = fixture(); f.clients['brisa-web'].issuer = f.clients['aurora-web'].issuer;
  assert.throws(() => validatePrivateClients(f, { origin }), /TENANT_MISMATCH/);
  const c = fixture(); c.clients['brisa-web'].callback = `${origin}/auth/aurora-web/callback`;
  assert.throws(() => validatePrivateClients(c, { origin }), /CALLBACK_MISMATCH/);
  const d = fixture(); d.clients['brisa-web'].clientId = d.clients['aurora-web'].clientId;
  assert.throws(() => validatePrivateClients(d, { origin }), /IDS_NOT_UNIQUE/);
});
test('adapts explicitly named nested and list manifests, while rejecting conflicting layouts', () => {
  const f = fixture();
  const bff = { bff: { clients: Object.entries(f.clients).map(([key, v]) => ({ key, ...v })) } };
  assert.equal(validatePrivateClients(bff, { origin })['brisa-app'].clientId, 'oidc-brisa-mobile');
  const brands = { brands: {} };
  for (const [brand, domain] of [['aurora','aurora.identity.test'], ['brisa','brisa.identity.test']]) {
    brands.brands[brand] = { domain, issuer: f.clients[`${brand}-web`].issuer,
      web: { ...f.clients[`${brand}-web`], issuer: undefined, tenantDomain: undefined },
      mobile: { ...f.clients[`${brand}-mobile`], issuer: undefined, tenantDomain: undefined } };
  }
  assert.equal(validatePrivateClients(brands, { origin })['aurora-app'].clientId, 'oidc-aurora-mobile');
  assert.throws(() => validatePrivateClients({ clients: f.clients, registrations: f.clients }, { origin }), /AMBIGUOUS_CLIENT_COLLECTION/);
  assert.throws(() => validatePrivateClients({ nonsense: f.clients }, { origin }), /CLIENT_COLLECTION_MISSING/);
});
test('unknown private brand client keys map only by exact four registered callback URIs', () => {
  const f = fixture();
  const brands = { brands: {} };
  for (const brand of ['aurora', 'brisa']) {
    const web = f.clients[`${brand}-web`], mobile = f.clients[`${brand}-mobile`];
    brands.brands[brand] = { issuer: web.issuer, clients: {
      opaqueRegisteredClientX: { ...mobile, issuer: undefined, tenantDomain: undefined },
      opaqueRegisteredClientY: { ...web, issuer: undefined, tenantDomain: undefined },
    } };
  }
  const clients = validatePrivateClients(brands, { origin });
  assert.equal(clients['aurora-web'].clientId, 'oidc-aurora-web');
  assert.equal(clients['aurora-app'].clientId, 'oidc-aurora-mobile');
  assert.equal(clients['brisa-web'].clientId, 'oidc-brisa-web');
  assert.equal(clients['brisa-app'].clientId, 'oidc-brisa-mobile');
  assert.equal(clients['brisa-app'].issuer, f.clients['brisa-web'].issuer);
});
test('unknown keys fail closed on missing, duplicated or substituted callbacks', () => {
  const f = fixture();
  function make() {
    return { brands: Object.fromEntries(['aurora', 'brisa'].map(brand => [brand, {
      issuer: f.clients[`${brand}-web`].issuer,
      clients: { mystery1: { ...f.clients[`${brand}-web`] }, mystery2: { ...f.clients[`${brand}-mobile`] } },
    }])) };
  }
  const noCb = make(); delete noCb.brands.aurora.clients.mystery2.callback;
  assert.throws(() => validatePrivateClients(noCb, { origin }), /UNRECOGNIZED_CHANNEL_CALLBACK/);
  const duplicate = make(); duplicate.brands.brisa.clients.mystery2.callback = duplicate.brands.brisa.clients.mystery1.callback;
  assert.throws(() => validatePrivateClients(duplicate, { origin }), /UNRECOGNIZED_CHANNEL_CALLBACK/);
  const substitute = make(); substitute.brands.aurora.clients.mystery1.callback = `${origin}/auth/brisa-web/callback`;
  assert.throws(() => validatePrivateClients(substitute, { origin }), /UNRECOGNIZED_CHANNEL_CALLBACK/);
  const extra = make(); extra.brands.brisa.clients.mystery3 = { ...f.clients['brisa-web'] };
  assert.throws(() => validatePrivateClients(extra, { origin }), /BRAND_CLIENT_SHAPE_INVALID/);
  const conflicting = make(); conflicting.brands.aurora.clients.mystery1.oauth = { redirectUri: `${origin}/auth/aurora-mobile/callback` };
  assert.throws(() => validatePrivateClients(conflicting, { origin }), /CONFLICTING/);
});
test('fail closed for missing, group-readable, and symlink files; preview fallback isolated', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ciam-private-test-'));
  try {
    mkdirSync(join(dir, 'var/wso2'), { recursive: true });
    const file = join(dir, 'var/wso2/identity-bff-wso2.private.json');
    const env = { IDENTITY_MODE: 'live-wso2', PUBLIC_ORIGIN: origin };
    assert.throws(() => loadPrivateWso2Clients({ env, projectRoot: dir }), /ENOENT/);
    writeFileSync(file, JSON.stringify(fixture())); chmodSync(file, 0o644);
    assert.throws(() => loadPrivateWso2Clients({ env, projectRoot: dir }), /PERMISSIONS_REQUIRE_0600/);
    chmodSync(file, 0o600);
    assert.equal(loadPrivateWso2Clients({ env, projectRoot: dir })['brisa-app'].clientId, 'oidc-brisa-mobile');
    writeFileSync(file, '{"clientSecret":"TEST-SECRET-NEVER-PRINT"');
    assert.throws(() => loadPrivateWso2Clients({ env, projectRoot: dir }), e => e.message === 'WSO2_PRIVATE_MALFORMED_JSON');
    writeFileSync(file, JSON.stringify(fixture())); chmodSync(file, 0o600);
    symlinkSync(file, join(dir, 'var/wso2/alias.json'));
    assert.throws(() => loadPrivateWso2Clients({ env: { ...env, WSO2_BFF_PRIVATE_MANIFEST: join(dir, 'var/wso2/alias.json') }, projectRoot: dir }), /FILE_UNSAFE/);
    assert.equal(loadPrivateWso2Clients({ env: {}, fallback: { demo: 1 }, projectRoot: dir }).demo, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('original -app callback registrations remain first-class and preserve exact redirect URI', () => {
  const f = fixture();
  for (const brand of ['aurora', 'brisa']) {
    f.clients[`${brand}-mobile`].callback = `${origin}/auth/${brand}-app/callback`;
  }
  const clients = validatePrivateClients(f, { origin });
  assert.equal(clients['aurora-app'].redirectUri, `${origin}/auth/aurora-app/callback`);
  assert.equal(clients['brisa-app'].redirectUri, `${origin}/auth/brisa-app/callback`);
});

test('unknown brand client keys map correctly using original -app callbacks with independent issuers', () => {
  const f = fixture();
  const brands = { brands: {} };
  for (const brand of ['aurora', 'brisa']) {
    const web = f.clients[`${brand}-web`];
    const app = f.clients[`${brand}-mobile`];
    brands.brands[brand] = { issuer: web.issuer, clients: {
      generatedRegistrationAlpha: { ...app, callback: `${origin}/auth/${brand}-app/callback`, issuer: undefined, tenantDomain: undefined },
      generatedRegistrationBeta: { ...web, issuer: undefined, tenantDomain: undefined },
    } };
  }
  const clients = validatePrivateClients(brands, { origin });
  assert.equal(clients['aurora-web'].redirectUri, `${origin}/auth/aurora-web/callback`);
  assert.equal(clients['aurora-app'].redirectUri, `${origin}/auth/aurora-app/callback`);
  assert.equal(clients['brisa-app'].redirectUri, `${origin}/auth/brisa-app/callback`);
  assert.notEqual(clients['aurora-app'].issuer, clients['brisa-app'].issuer);
});

test('redirect callback validation refuses unrecorded alias, foreign origin, missing or duplicate evidence', () => {
  const f = fixture();
  delete f.clients['aurora-mobile'].callback;
  assert.throws(() => validatePrivateClients(f, { origin }), /CALLBACK_MISMATCH/);
  const wrong = fixture();
  wrong.clients['aurora-mobile'].callback = 'http://localhost:4000/auth/aurora-app/callback';
  assert.throws(() => validatePrivateClients(wrong, { origin }), /CALLBACK_MISMATCH/);
  const mixed = fixture();
  mixed.clients['brisa-mobile'].callback = `${origin}/auth/aurora-app/callback`;
  assert.throws(() => validatePrivateClients(mixed, { origin }), /CALLBACK_MISMATCH/);
  const conflicting = fixture();
  conflicting.clients['brisa-mobile'].oidc = { redirectUri: `${origin}/auth/brisa-app/callback` };
  assert.throws(() => validatePrivateClients(conflicting, { origin }), /CONFLICTING/);
  const encoded = fixture();
  encoded.clients['brisa-mobile'].callback = `${origin}/auth/brisa-%61pp/callback`;
  assert.throws(() => validatePrivateClients(encoded, { origin }), /CALLBACK_MISMATCH/);
});
