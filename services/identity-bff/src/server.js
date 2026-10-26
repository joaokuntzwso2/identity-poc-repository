import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { random, fingerprint, discover, makeAuthorizationUrl, exchangeAuthorizationCode, verifyIdToken, sanitizedClaims, safeEqual } from './oidc.js';
import { DemoSessionStore } from './session-store.js';
import { appConfig, brands, clients } from './config.js';
import { evaluatePairwise } from './pairwise.js';
import { ConsentLedger } from './audit.js';
import { handleDurableConsent } from './identity/consent-api.js'; // IDENTITY_CORRECTIONS_V1

const ledger = new ConsentLedger();
const sessionStore = new DemoSessionStore({
  maxSessions: appConfig.maxSessions, secure: appConfig.origin.startsWith('https:')
});
const consentPilotEnabled = appConfig.environment !== 'production' && process.env.ENABLE_EPHEMERAL_CONSENT === 'true';
const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const fixturePath = join(projectRoot, 'config', 'scenario-catalog.json');
const distPath = join(projectRoot, 'apps/experience-center/dist');
const allowedOrigin = new URL(appConfig.origin);
if (!['http:', 'https:'].includes(allowedOrigin.protocol)) throw new Error('Invalid PUBLIC_ORIGIN');
if (appConfig.environment === 'production' && allowedOrigin.protocol !== 'https:') throw new Error('Production requires PUBLIC_ORIGIN with HTTPS');
if (allowedOrigin.protocol === 'http:' && !appConfig.allowInsecureLocal) throw new Error('Explicit ALLOW_INSECURE_LOCAL=true required for local HTTP');
if (allowedOrigin.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(allowedOrigin.hostname)) throw new Error('Plain HTTP permitted on loopback only');

function reply(res, status, value, headers = {}) {
  const body = JSON.stringify(value); res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY', ...headers }); res.end(body);
}
function redirect(res, target, headers = {}) { res.writeHead(302, { location: target, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff', ...headers }); res.end(); }
function ensureSession(req, res) {
  const s = sessionStore.ensure(req, res);
  if (s) for (const [key, login] of Object.entries(s.logins)) {
    // A BFF cookie cannot extend an ID token's lifetime.
    if (login?.verified !== true || !Number.isSafeInteger(login.claims?.exp) ||
        login.claims.exp <= Math.floor(Date.now() / 1000) ||
        login.claims.iss !== clients[key]?.issuer ||
        !(typeof login.claims.aud === 'string' ? [login.claims.aud] : login.claims.aud)?.includes(clients[key]?.clientId)) {
      delete s.logins[key];
    }
  }
  return s;
}
// Pairwise subjects are scoped to their brand; never silently treat the first
// authentication as a globally resolvable customer identifier.
function sessionIdentityForClient(s, clientKey) {
  const login = s.logins[clientKey];
  return login?.verified ? `${login.claims.iss}|${login.claims.sub}` : null;
}
function loggedInSubjects(s) {
  return new Set(Object.values(s.logins).filter(x => x.verified).map(x => `${x.claims.iss}|${x.claims.sub}`));
}
function hasAuth(s) { return Object.values(s.logins).some(v => v.verified === true); }
function operator(s) { const identities = Object.values(s.logins).filter(v => v.verified === true).map(v => `${v.claims.iss}|${v.claims.sub}`); return identities.some(v => appConfig.adminAllowlist.includes(v)); }
function requirePost(req, res, s, { operatorOnly = false } = {}) {
  if (req.method !== 'POST') { reply(res, 405, { error: 'method_not_allowed' }); return false; }
  const origin = req.headers.origin;
  if (!origin || origin !== appConfig.origin) { reply(res, 403, { error: 'origin_denied' }); return false; }
  if (!req.headers['x-csrf-token'] || !safeEqual(req.headers['x-csrf-token'], s.csrf)) { reply(res, 403, { error: 'csrf_denied' }); return false; }
  if (!hasAuth(s)) { reply(res, 401, { error: 'authentication_required' }); return false; }
  if (operatorOnly && !operator(s)) { reply(res, 403, { error: 'operator_not_authorized' }); return false; }
  return true;
}
async function bodyJson(req) {
  let size = 0; let text = ''; for await (const chunk of req) { size += chunk.length; if (size > 15000) { const e = new Error('request_body_too_large'); e.statusCode = 413; throw e; } text += chunk; }
  try { return JSON.parse(text || '{}'); } catch { const e = new Error('invalid_json'); e.statusCode = 400; throw e; }
}
async function clientHealth(c) {
  if (!c.clientId || !c.issuer) return { client: c.name, status: 'NOT_CONFIGURED' };
  try { const metadata = await discover(c.issuer); return { client: c.name, status: 'DISCOVERY_REACHABLE', issuer: metadata.issuer, pairwiseAdvertised: (metadata.subject_types_supported || []).includes('pairwise') }; }
  catch (e) { return { client: c.name, status: 'DISCOVERY_ERROR', reason: e.message }; }
}
async function metadata() {
  const statuses = await Promise.all(Object.values(clients).map(clientHealth));
  return { statuses, product: 'WSO2 IS 7.3 (configured target)', deploymentVerified: false };
}
function describeLogins(s) {
  return Object.fromEntries(Object.entries(s.logins).map(([key, value]) => [key, { verified: value.verified, verifiedAt: value.verifiedAt, issuer: value.claims.iss, sector: value.sector, clientId: clients[key].clientId, claims: { ...sanitizedClaims(value.claims), sub: '[REDACTED]' }, fingerprint: fingerprint(value.claims.sub) }]));
}
// CIAM_REGISTERED_CALLBACK_V5: redirect URI must match the WSO2 registration.
function callbackUrl(name) {
  const registered = clients[name]?.redirectUri;
  if (process.env.IDENTITY_MODE === 'live-wso2' && !registered) throw new Error('WSO2_CALLBACK_NOT_REGISTERED');
  return registered || new URL(`/auth/${name.replace(/-app$/, '-mobile')}/callback`, appConfig.origin).toString();
}
function actualSectorUri(brand) { return process.env[`SECTOR_${brand.toUpperCase()}_URI`] || null; }
function safeBrand(brand) { return Object.hasOwn(brands, brand); }

const apiHandler = async (req, res, u, s) => {
  if (u.pathname === '/api/identity/me' && req.method === 'GET') {
    const entries = Object.fromEntries(Object.entries(clients).map(([key, c]) => {
      const login = s.logins[key];
      return [key, {
        configured: Boolean(c.clientId && c.issuer),
        authenticated: login?.verified === true,
        issuer: login?.verified === true ? login.claims.iss : null,
        subjectFingerprint: login?.verified === true ? fingerprint(login.claims.sub) : null,
        verifiedAt: login?.verified === true ? login.verifiedAt : null,
        // Authorization is deliberately conservative: no entitlement invented from a persona.
        permissions: login?.verified === true ? ['session:read', 'profile:self:read'] : [],
      }];
    }));
    return reply(res, 200, {
      identitySource: hasAuth(s) ? 'WSO2_SIGNED_ID_TOKEN' : 'NO_VERIFIED_IDENTITY', authenticated: hasAuth(s),
      clients: entries, operator: operator(s), csrf: s.csrf,
      capabilities: { b2bAdministration: false, crossTenantSso: false, federation: false,
        wso2RpLogoutVerified: false, delegatedAuthorizationVerified: false },
      evidence: hasAuth(s) ? 'BFF_VALIDATED_SIGNED_ID_TOKEN' : 'BROWSER_CALLBACK_REQUIRED', demoPersonasAreIdentities: false,
    });
  }
  // Read-only preview data may be displayed, but cannot grant real identities or permissions.
  // Never pass the browser's cookies or authorization headers to the synthetic API.
  if (/^\/api\/(experience|retail)\//.test(u.pathname)) {
    if (req.method !== 'GET') return reply(res, 403, { error: 'synthetic_writes_disabled_on_live_identity_origin' });
    const upstream = new URL(u.pathname + u.search, 'http://127.0.0.1:4317');
    try {
      const response = await fetch(upstream, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!response.ok) return reply(res, 502, { error: 'synthetic_preview_unavailable', upstreamStatus: response.status });
      const bytes = await response.text();
      if (bytes.length > 512_000) return reply(res, 502, { error: 'synthetic_preview_too_large' });
      return reply(res, 200, JSON.parse(bytes), { 'x-identity-evidence': 'synthetic-preview-not-authoritative' });
    } catch { return reply(res, 502, { error: 'synthetic_preview_unavailable' }); }
  }
  if (u.pathname.startsWith('/api/identity/consent/')) return handleDurableConsent({ req, res, u, s, reply, requirePost, bodyJson, subjectOf: sessionIdentityForClient, clients });
  if (u.pathname === '/api/session' && req.method === 'GET') return reply(res, 200, { csrf: s.csrf, authenticated: hasAuth(s), operator: operator(s), capabilities: { ephemeralConsentPilot: consentPilotEnabled }, logins: describeLogins(s), pairwise: evaluatePairwise(s.logins), limitations: ['A valid four-token result does not independently prove canonical-person linkage.', 'Local consent ledger is ephemeral and does not meet D-01/D-07 persistence requirements.'] });
  if (u.pathname === '/api/scenarios' && req.method === 'GET') return reply(res, 200, JSON.parse(await readFile(fixturePath, 'utf8')));
  if (u.pathname === '/api/health' && req.method === 'GET') return reply(res, 200, { service: 'POC-identity-bff', status: 'UP', timestamp: new Date().toISOString(), configuredClients: Object.values(clients).filter(c => c.clientId && c.issuer).length });
  if (u.pathname === '/api/wso2-status' && req.method === 'GET') return reply(res, 200, await metadata());
  if (u.pathname === '/api/subjects/compare' && req.method === 'GET') return reply(res, 200, evaluatePairwise(s.logins));
  if (u.pathname === '/api/consent' && req.method === 'GET') { if (!hasAuth(s)) return reply(res, 401, { error: 'authentication_required' }); return reply(res, 200, { events: consentPilotEnabled ? ledger.events.filter(e => loggedInSubjects(s).has(e.subject)).map(({ subject, ...event }) => event) : [], chainValid: consentPilotEnabled ? ledger.verifyChain() : false, mode: consentPilotEnabled ? 'EPHEMERAL_EXTENSION_PILOT' : 'DISABLED_NOT_COMPLIANT' }); }
  if (u.pathname === '/api/consent' && req.method === 'POST') {
    if (!requirePost(req, res, s)) return;
    if (!consentPilotEnabled) return reply(res, 503, { error: 'ephemeral_consent_pilot_disabled' });
    const d = await bodyJson(req);
    if (!safeBrand(d.origin) || !safeBrand(d.target) || !['delivery', 'customer-support'].includes(d.purpose) || !Object.hasOwn(clients, d.client)) return reply(res, 400, { error: 'invalid_consent_dimensions' });
    if (clients[d.client].brand !== d.origin) return reply(res, 403, { error: 'origin_client_mismatch' });
    if (!['GRANTED', 'REVOKED'].includes(d.action)) return reply(res, 400, { error: 'invalid_action' });
    const subject = sessionIdentityForClient(s, d.client);
    if (!subject) return reply(res, 403, { error: 'origin_client_authentication_required' });
    const event = ledger.write({ subject, origin: d.origin, target: d.target, purpose: d.purpose, client: d.client, action: d.action });
    return reply(res, 201, { eventId: event.eventId, action: event.action, hash: event.hash, mode: 'EPHEMERAL_EXTENSION_PILOT' });
  }
  if (u.pathname === '/api/consent/check' && req.method === 'POST') {
    if (!requirePost(req, res, s)) return;
    if (!consentPilotEnabled) return reply(res, 503, { error: 'ephemeral_consent_pilot_disabled' });
    const d = await bodyJson(req);
    if (!safeBrand(d.origin) || !safeBrand(d.target) || !Object.hasOwn(clients, d.client)) return reply(res, 400, { error: 'invalid_dimensions' });
    if (clients[d.client].brand !== d.origin) return reply(res, 403, { error: 'origin_client_mismatch' });
    const subject = sessionIdentityForClient(s, d.client);
    if (!subject) return reply(res, 403, { error: 'origin_client_authentication_required' });
    if (!['delivery', 'customer-support'].includes(d.purpose)) return reply(res, 400, { error: 'invalid_purpose' });
    const verdict = ledger.decision({ subject, origin: d.origin, target: d.target, client: d.client, purpose: d.purpose });
    return reply(res, verdict.allow ? 200 : 403, { decision: verdict.allow ? 'ALLOW' : 'DENY', auditId: verdict.auditId, mode: 'EPHEMERAL_EXTENSION_PILOT' });
  }
  if (u.pathname === '/api/m2m/client-credentials' && req.method === 'POST') {
    if (!requirePost(req, res, s, { operatorOnly: true })) return;
    const id = process.env.M2M_CLIENT_ID, secret = process.env.M2M_CLIENT_SECRET, issuer = process.env.M2M_ISSUER || process.env.OIDC_ISSUER;
    if (!id || !secret || !issuer) return reply(res, 503, { error: 'm2m_client_not_configured' });
    const disc = await discover(issuer);
    const form = new URLSearchParams({ grant_type: 'client_credentials', scope: process.env.M2M_SCOPES || 'catalog.read' });
    const start = Date.now();
    const response = await fetch(disc.token_endpoint, { method: 'POST', headers: { authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`, 'content-type': 'application/x-www-form-urlencoded' }, body: form, signal: AbortSignal.timeout(12000), redirect: 'error' });
    const data = await response.json();
    if (!response.ok) return reply(res, 502, { error: 'm2m_token_request_failed', oauthError: data.error || 'unknown' });
    if (!data.access_token) return reply(res, 502, { error: 'no_access_token' });
    return reply(res, 200, { status: 'TOKEN_ISSUED_BY_WSO2', latencyMs: Date.now() - start, tokenType: data.token_type, expiresIn: data.expires_in, scope: data.scope || form.get('scope'), fingerprint: fingerprint(data.access_token), warning: 'Token not exposed in the browser. Signature/entitlement assertions require separate resource-server test.' });
  }
  if (u.pathname === '/api/logout' && req.method === 'POST') { if (!requirePost(req, res, s)) return; sessionStore.destroy(s, res); return reply(res, 200, { status: 'LOCAL_DEMO_SESSION_CLEARED', note: 'This does not invoke WSO2 RP-initiated logout; WSO2 IdP session may persist.' }); }
  return reply(res, 404, { error: 'route_not_found' });
};

// CIAM_LIVE_STATIC_BRIDGE_V1: same-origin BFF entrypoint for verified identity.
async function serveBuiltApp(pathname, res) {
  const candidate = pathname === '/' ? 'index.html' : pathname.slice(1);
  if (['identity-bridge.js', 'identity-bridge.css'].includes(candidate)) {
    const file = await readFile(join(dirname(fileURLToPath(import.meta.url)), candidate));
    res.writeHead(200, { 'content-type': candidate.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    res.end(file); return true;
  }
  const entries = new Set(['index.html', 'aurora.html', 'brisa.html', 'aurora-mobile.html', 'brisa-mobile.html', 'provider.html', 'b2b.html', 'onboarding.html', 'authorization.html', 'operations.html', 'evidence-lab.html', 'wso2-lab.html']);
  if (!entries.has(candidate) && !/^assets\/[A-Za-z0-9_.-]+\.(js|css|svg|png|webp|ico|woff2)$/.test(candidate)) return false;
  const filename = join(distPath, candidate);
  try {
    let file = await readFile(filename);
    const html = candidate.endsWith('.html');
    if (html) {
      const source = file.toString('utf8');
      if (!source.includes('</body>')) throw new Error('Built laboratory HTML has no body closing tag');
      file = Buffer.from(source.replace('</body>', '<link rel="stylesheet" href="/identity-bridge.css"><script src="/identity-bridge.js" defer></script></body>'));
    }
    const ct = html ? 'text/html; charset=utf-8' : candidate.endsWith('.css') ? 'text/css; charset=utf-8' : candidate.endsWith('.js') ? 'application/javascript' : candidate.endsWith('.svg') ? 'image/svg+xml' : candidate.endsWith('.woff2') ? 'font/woff2' : candidate.endsWith('.png') ? 'image/png' : 'application/octet-stream';
    res.writeHead(200, { 'content-type': ct, 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'cache-control': html ? 'no-store' : 'public,max-age=300', 'content-security-policy': "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" });
    res.end(file); return true;
  } catch (e) { if (e.code === 'ENOENT') return false; throw e; }
}

async function handle(req, res) {
  const u = new URL(req.url, appConfig.origin);
  // Public, frequently polled endpoints do not allocate anonymous sessions.
  const publicRoutes = new Set(['/api/health', '/api/scenarios', '/api/wso2-status']);
  const isSector = /^\/oidc\/sector\/(aurora|brisa)\.json$/.test(u.pathname);
  const s = (publicRoutes.has(u.pathname) || isSector) ? null : ensureSession(req, res);
  if (!s && !publicRoutes.has(u.pathname) && !isSector) return reply(res, 503, { error: 'session_capacity_reached' });
  try {
    if (u.pathname.startsWith('/api/')) return await apiHandler(req, res, u, s);
    const sector = /^\/oidc\/sector\/(aurora|brisa)\.json$/.exec(u.pathname);
    if (sector) { const name = sector[1]; const list = ['web', 'app'].map(ch => callbackUrl(`${name}-${ch}`)); return reply(res, 200, list, { 'access-control-allow-origin': '*' }); }
    const login = /^\/auth\/(aurora|brisa)-(web|mobile|app)\/login$/.exec(u.pathname);
    if (login) {
      const key = `${login[1]}-${login[2] === 'mobile' ? 'app' : login[2]}`; const c = clients[key]; if (!c.clientId || !c.issuer) return reply(res, 503, { error: 'oidc_client_not_configured', client: key });
      const doc = await discover(c.issuer); const state = random(32), nonce = random(24), verifier = random(32);
      const now = Date.now(); for (const [k, pending] of Object.entries(s.pending)) { if (now - pending.at > 300_000) delete s.pending[k]; }
      if (Object.keys(s.pending).length >= 8) return reply(res, 429, { error: 'too_many_pending_authorizations' });
      s.pending[state] = { key, nonce, verifier, at: now };
      return redirect(res, makeAuthorizationUrl(doc, { clientId: c.clientId, redirectUri: callbackUrl(key), state, nonce, verifier, scope: c.scope, acrValues: u.searchParams.get('acr') || undefined }));
    }
    const cb = /^\/auth\/(aurora|brisa)-(web|mobile|app)\/callback$/.exec(u.pathname);
    if (cb) {
      const key = `${cb[1]}-${cb[2] === 'mobile' ? 'app' : cb[2]}`; const state = u.searchParams.get('state'), code = u.searchParams.get('code'); const p = state && s.pending[state];
      // In live mode an alternate alias must not accept a callback for this client.
      if (process.env.IDENTITY_MODE === 'live-wso2' &&
          u.pathname !== new URL(callbackUrl(key)).pathname)
        return reply(res, 400, { error: 'unregistered_callback_alias' });
      if (!p || p.key !== key || Date.now() - p.at > 300_000) { return reply(res, 400, { error: 'invalid_or_expired_oauth_state' }); }
      delete s.pending[state]; if (u.searchParams.has('error')) return reply(res, 400, { error: 'oidc_provider_error', code: u.searchParams.get('error') });
      if (!code) return reply(res, 400, { error: 'authorization_code_missing' });
      const c = clients[key], doc = await discover(c.issuer);
      const tokens = await exchangeAuthorizationCode(doc, { clientId: c.clientId, clientSecret: c.clientSecret, redirectUri: callbackUrl(key), code, verifier: p.verifier });
      const claims = await verifyIdToken(tokens.id_token, { issuer: c.issuer, clientId: c.clientId, nonce: p.nonce });
      s.logins[key] = { claims, verified: true, verifiedAt: new Date().toISOString(), sector: actualSectorUri(c.brand) };
      sessionStore.rotate(s, res);
      return redirect(res, `/?client=${encodeURIComponent(key)}&authenticated=1`);
    }
    if (await serveBuiltApp(u.pathname, res)) return;
    if (u.pathname === '/') return redirect(res, '/app/');
    // Serve an intentionally simple diagnostic page until the Vite frontend is built.
    if (u.pathname === '/app/' || u.pathname === '/app/index.html') {
      const html = await readFile(join(dirname(fileURLToPath(import.meta.url)), '../../../apps/experience-center/fallback.html'), 'utf8');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" }); res.end(html); return;
    }
    if (u.pathname === '/app/fallback.js' || u.pathname === '/app/fallback.css') {
      const file = u.pathname.endsWith('.js') ? 'fallback.js' : 'fallback.css';
      const text = await readFile(join(dirname(fileURLToPath(import.meta.url)), '../../../apps/experience-center', file));
      res.writeHead(200, { 'content-type': file.endsWith('js') ? 'application/javascript' : 'text/css', 'x-content-type-options': 'nosniff', 'cache-control': 'no-store' }); res.end(text); return;
    }
    return reply(res, 404, { error: 'not_found' });
  } catch (e) { console.error(JSON.stringify({ event: 'REQUEST_FAILURE', route: u.pathname, error: e.message })); return reply(res, e.statusCode || 500, { error: e.statusCode ? e.message : 'request_failed', reason: appConfig.environment === 'production' ? undefined : e.message }); }
}

if (process.env.NODE_ENV !== 'test') createServer(handle).listen(appConfig.port, process.env.BIND_HOST || '127.0.0.1', () => console.log(`POC identity BFF listening on ${appConfig.origin}`));
export { handle };
