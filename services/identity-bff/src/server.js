import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { random, fingerprint, discover, makeAuthorizationUrl, exchangeAuthorizationCode, verifyIdToken, safeEqual } from './oidc.js';
import { DemoSessionStore } from './session-store.js';
import { readAuthorizationResponse } from './auth-callback-guards.js';
import { appConfig, clients } from './config.js';
import { inspectAccessToken, requireAuthorityForClient } from './wso2-authority.js';
import { verifyAndRecordBinding } from './binding-acceptance.js';
import { liveApiDenial } from './live-api-policy.js';
import { readVerifiedUserinfo } from './live-userinfo.js';
import { readOidcUserinfoForClient } from './oidc-userinfo-p010.js';
import { handleCases } from './live-cases-v4.js';
import { beginApprovalChallenge, verifyApprovalResponse, totpPolicy } from './approval-stepup-p010.js';
import { commitApprovedCase } from './case-approval-p010.js';

// Zero-mock deployment: no preview mode, local entitlements, persona selection or consent ledger.
if (process.env.IDENTITY_MODE !== 'live-wso2')
  throw new Error('LIVE_WSO2_REQUIRED_NO_SYNTHETIC_MODE');
const sessionStore = new DemoSessionStore({
  maxSessions: appConfig.maxSessions, secure: appConfig.origin.startsWith('https:')
});
const origin = new URL(appConfig.origin);
if (!['https:', 'http:'].includes(origin.protocol)) throw new Error('INVALID_PUBLIC_ORIGIN');
if (origin.protocol === 'http:' &&
    (!appConfig.allowInsecureLocal || !['localhost', '127.0.0.1'].includes(origin.hostname)))
  throw new Error('LOCAL_HTTP_NOT_EXPLICITLY_ALLOWED');
if (appConfig.environment === 'production' && origin.protocol !== 'https:')
  throw new Error('HTTPS_REQUIRED_FOR_PRODUCTION');

function reply(res, status, data) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer'
  });
  res.end(JSON.stringify(data));
}
function redirect(res, target) {
  res.writeHead(302, { location: target, 'cache-control': 'no-store',
    'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' });
  res.end();
}
function validLogin(login, client) {
  if (login?.verified !== true || !Number.isSafeInteger(login.claims?.exp) ||
      login.claims.exp <= Math.floor(Date.now() / 1000) ||
             login.claims.iss !== client?.issuer ||
       typeof login.claims.sub !== 'string' || !login.claims.sub ||
       (login.claims.azp !== undefined && login.claims.azp !== client?.clientId)) return false;
  const aud = typeof login.claims.aud === 'string' ? [login.claims.aud] : login.claims.aud;
  return Array.isArray(aud) && aud.includes(client.clientId);
}
function ensureSession(req, res) {
  const s = sessionStore.ensure(req, res);
  if (s) for (const [key, login] of Object.entries(s.logins)) {
    if (!validLogin(login, clients[key])) delete s.logins[key];
  }
  return s;
}
function callbackUrl(key) {
  const registered = clients[key]?.redirectUri;
  if (!registered) throw new Error('WSO2_CALLBACK_NOT_REGISTERED');
  return registered;
}
function safeClaims(claims) {
  const result = {};
  for (const k of ['name','given_name','family_name','preferred_username','email']) {
    if (typeof claims[k] === 'string' && claims[k].length <= 256) result[k] = claims[k];
  }
  return result;
}
function tokenRoles(claims) {
  // Display only if the role claim is explicitly in the SIGNATURE-VERIFIED ID token.
  // Never turn a role name into a permission. Do not infer roles from email/persona.
  const roles = Array.isArray(claims.roles) ? claims.roles : [];
  return roles.filter(v => typeof v === 'string' && v.length <= 128).slice(0, 25);
}
async function sessionState(s) {
  const status = {};
  let unavailable = false;
  for (const [key, c] of Object.entries(clients)) {
    const login = s.logins[key];
    const entry = { configured: Boolean(c.clientId && c.issuer), authenticated: false,
      issuer: null, subjectFingerprint: null, verifiedAt: null, permissions: [],
      claimsFromVerifiedIdToken: {}, rolesFromVerifiedIdToken: [] };
    if (login?.verified) {
      try {
        const current = await inspectAccessToken(login, c);
        if (!current.active) delete s.logins[key];
        else {
          entry.authenticated = true;
          entry.issuer = login.claims.iss;
          entry.subjectFingerprint = fingerprint(login.claims.sub);
          entry.verifiedAt = login.verifiedAt;
          entry.permissions = current.scopes.filter(x => x.startsWith('ciam:'));
          entry.claimsFromVerifiedIdToken = safeClaims(login.claims);
          entry.rolesFromVerifiedIdToken = tokenRoles(login.claims);
          entry.acrFromVerifiedIdToken = typeof login.claims.acr === 'string' ? login.claims.acr : null;
          entry.amrFromVerifiedIdToken = Array.isArray(login.claims.amr) ?
            login.claims.amr.filter(x => typeof x === 'string').slice(0, 8) : [];
        }
      } catch { unavailable = true; }
    }
    status[key] = entry;
  }
  return { status, unavailable };
}
async function protectedDecision(s, key) {
  return requireAuthorityForClient(s, key, clients,
    'ciam:profile:read', process.env.WSO2_BUSINESS_API_AUDIENCE);
}
async function api(req, res, u, s) {
  // CIAM_V4_REAL_CASES_ROUTER: WSO2 scope checks precede persistent business operations.
  if (await handleCases(req, res, u, s, {
    clients,
    authorize: (session, key, scope) => process.env.WSO2_CASES_API_AUDIENCE
      ? requireAuthorityForClient(session, key, clients, scope, process.env.WSO2_CASES_API_AUDIENCE)
      : Promise.resolve({ http: 503, reason: 'cases_audience_not_configured' }),
    sameOrigin: request => request.headers.origin === appConfig.origin,
    safeCsrf: (request, session) => Boolean(request.headers['x-csrf-token']) &&
      safeEqual(request.headers['x-csrf-token'], session.csrf),
    beginApproval: async ({ session, key, brand, caseId }) => {
      const policy = totpPolicy();
      const c = clients[key], doc = await discover(c.issuer);
      return beginApprovalChallenge({session,key,brand,caseId,client:c,discovery:doc,policy});
    }
  })) return;
  if (u.pathname === '/api/health' && req.method === 'GET')
    return reply(res, 200, { service: 'WSO2-live-identity-bff', status: 'UP' });
  if (u.pathname === '/api/wso2-status' && req.method === 'GET') {
    const statuses = await Promise.all(Object.entries(clients).map(async ([key, c]) => {
      try { const md = await discover(c.issuer); return { key, discovery: md.issuer === c.issuer }; }
      catch { return { key, discovery: false }; }
    }));
    return reply(res, 200, { statuses, identityMode: 'live-wso2' });
  }
  if (u.pathname === '/api/identity/me' && req.method === 'GET') {
    const { status, unavailable } = await sessionState(s);
    if (unavailable) return reply(res, 503, { identitySource: 'WSO2_UNAVAILABLE',
      authenticated: false, error: 'wso2_authority_unavailable' });
    const active = Object.values(status).some(x => x.authenticated);
    return reply(res, 200, {
      identitySource: active ? 'WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN' : 'NO_VERIFIED_IDENTITY',
      authenticated: active, clients: status, operator: false, csrf: s.csrf,
      evidence: 'LIVE_INTROSPECTION_PER_REQUEST', demoPersonasAreIdentities: false,
      capabilities: { profileUserinfo: true, b2bAdministration: false, crossTenantSso: false,
        federation: false, wso2RpLogoutVerified: false, delegatedAuthorizationVerified: false,
        mfaPolicyVerified: false }
    });
  }
  // First-party OIDC UserInfo is scoped to `openid`, not the independent
  // `ciam:profile:read` business API permission. Live introspection must bind
  // the access token to the signature-verified ID token subject before use.
  if (u.pathname === '/api/oidc/userinfo') {
    if (req.method !== 'GET') return reply(res, 405, {error:'method_not_allowed'});
    const key=u.searchParams.get('client');
    if (!key || !Object.hasOwn(clients,key)) return reply(res,400,{error:'invalid_client'});
    const outcome=await readOidcUserinfoForClient({
      login:s.logins[key],client:clients[key],inspect:inspectAccessToken,
      discovery:discover,userinfo:readVerifiedUserinfo
    });
    return reply(res,outcome.status,outcome.body);
  }
  const brandProfile = /^\/api\/brands\/(aurora|brisa)\/profile$/.exec(u.pathname);
  if (u.pathname === '/api/protected/profile' || brandProfile) {
    if (req.method !== 'GET') return reply(res, 405, { error: 'method_not_allowed' });
    const key = u.searchParams.get('client');
    if (!Object.hasOwn(clients, key || '')) return reply(res, 400, { error: 'invalid_client' });
    if (brandProfile && clients[key].brand !== brandProfile[1])
      return reply(res, 403, { error: 'tenant_brand_mismatch', allowed: false });
    const decision = await protectedDecision(s, key);
    if (decision.http !== 200) return reply(res, decision.http, { error: decision.reason, allowed: false });
    const login = s.logins[key];
    if (!login?.verified) return reply(res, 401, { error: 'authentication_required', allowed: false });
    if (!brandProfile) return reply(res, 200, { allowed: true,
      authorizedBy: 'WSO2_ACTIVE_ACCESS_TOKEN_SCOPE', issuer: login.claims.iss,
      subjectFingerprint: fingerprint(login.claims.sub) });
    try {
      const discovery = await discover(clients[key].issuer);
      const attributes = await readVerifiedUserinfo({
        discovery, issuer: clients[key].issuer, accessToken: login.accessToken,
        subject: login.claims.sub
      });
      return reply(res, 200, { allowed: true, identitySource: 'WSO2_USERINFO',
        authorizedBy: 'WSO2_ACTIVE_ACCESS_TOKEN_SCOPE', brand: brandProfile[1],
        client: key, issuer: login.claims.iss,
        subjectFingerprint: fingerprint(login.claims.sub), attributes,
        note: Object.keys(attributes).length ? 'Only WSO2-released user attributes' :
          'WSO2 returned sub only; configure OIDC profile/email scopes and attribute sharing' });
    } catch (e) {
      console.error(JSON.stringify({ event: 'USERINFO_CHECK_FAILED', code: e.message }));
      return reply(res, 502, { error: 'wso2_userinfo_not_verified', allowed: false });
    }
  }
  if (u.pathname === '/api/logout') {
    if (req.method !== 'POST') return reply(res, 405, { error: 'method_not_allowed' });
    if (req.headers.origin !== appConfig.origin || !req.headers['x-csrf-token'] ||
        !safeEqual(req.headers['x-csrf-token'], s.csrf))
      return reply(res, 403, { error: 'csrf_or_origin_denied' });
    sessionStore.destroy(s, res);
    return reply(res, 200, { status: 'BFF_SESSION_DESTROYED',
      wso2Session: 'NOT_TERMINATED', accessTokenRevocation: 'NOT_VERIFIED' });
  }
  if (u.pathname.startsWith('/api/experience') || u.pathname.startsWith('/api/retail') ||
      u.pathname.startsWith('/api/consent') || u.pathname.startsWith('/api/identity/consent') ||
      u.pathname.startsWith('/api/scenarios') || u.pathname.startsWith('/api/subjects') ||
      u.pathname.startsWith('/api/session') || u.pathname.startsWith('/api/m2m'))
    return reply(res, 503, { error: 'wso2_authoritative_integration_not_available',
      syntheticFallback: false, allowed: false });
  return reply(res, 404, { error: 'route_not_found' });
}
const STATIC = Object.freeze({
  '/identity-live-v2': 'live-identity-v2.html',
  '/live-identity-v2.js': 'live-identity-v2.js',
  '/live-identity-v2.css': 'live-identity-v2.css',
  '/portal/aurora': 'live-brand-v3.html',
  '/portal/brisa': 'live-brand-v3.html',
  // CIAM_V5_LIVE_LAB: original Experience Center presentation, zero synthetic identity.
  '/lab': 'live-experience-v5.html',
  '/experience': 'live-experience-v5.html',
  '/portal/aurora/web': 'live-experience-v5.html',
  '/portal/aurora/mobile': 'live-experience-v5.html',
  '/portal/brisa/web': 'live-experience-v5.html',
  '/portal/brisa/mobile': 'live-experience-v5.html',
  '/live-experience-v5.js': 'live-experience-v5.js',
  '/live-experience-v5.css': 'live-experience-v5.css',
  '/live-retail-v5.css': 'live-retail-v5.css',
  '/live-brand-v3.js': 'live-brand-v3.js',
  '/live-cases-v4-ui.js': 'live-cases-v4-ui.js',
  '/live-brand-v3.css': 'live-brand-v3.css',
  '/live-wso2-ui.js': 'live-wso2-ui.js',
  '/': 'live-experience-v5.html',
  '/app/': 'live-wso2.html',
  '/app/index.html': 'live-wso2.html'
});
async function serveStatic(u, res) {
  const file = STATIC[u.pathname];
  if (!file) return false;
  const buf = await readFile(join(dirname(fileURLToPath(import.meta.url)), file));
  const ct = file.endsWith('.html') ? 'text/html; charset=utf-8' :
    file.endsWith('.css') ? 'text/css; charset=utf-8' : 'application/javascript; charset=utf-8';
  res.writeHead(200, { 'content-type': ct, 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'" });
  res.end(buf); return true;
}
function destination(key, asked) {
  // CIAM_V5_RETURNTO: explicit local allowlist; never accept external or cross-brand URLs.
  if (asked === '/identity-live-v2' || asked === '/lab' || asked === '/experience') return asked;
  const brand = clients[key].brand;
  if (asked === `/portal/${brand}`) return asked;
  if (asked === `/portal/${brand}/web` && key === `${brand}-web`) return asked;
  if (asked === `/portal/${brand}/mobile` && key === `${brand}-app`) return asked;
  return '/lab';
}
async function handle(req, res) {
  const u = new URL(req.url, appConfig.origin);
  if (u.pathname.startsWith('/api/') && !/^\/api\/brands\/(aurora|brisa)\/profile$/.test(u.pathname) && !/^\/api\/brands\/(aurora|brisa)\/cases(?:\/[0-9a-f-]{36}\/approve)?$/.test(u.pathname)) {
    const denial = liveApiDenial(u.pathname, req.method);
    if (denial) return reply(res, denial.status, denial.body);
  }
  const isSector = /^\/oidc\/sector\/(aurora|brisa)\.json$/.test(u.pathname);
  const publicRoute = isSector || ['/api/health','/api/wso2-status'].includes(u.pathname);
  const s = publicRoute ? null : ensureSession(req, res);
  if (!s && !publicRoute) return reply(res, 503, { error: 'session_capacity_reached' });
  try {
    if (u.pathname.startsWith('/api/')) return await api(req, res, u, s);
    const sector = /^\/oidc\/sector\/(aurora|brisa)\.json$/.exec(u.pathname);
    if (sector) return reply(res, 200,
      ['web','app'].map(channel => callbackUrl(`${sector[1]}-${channel}`)));
    const login = /^\/auth\/(aurora|brisa)-(web|mobile|app)\/login$/.exec(u.pathname);
    if (login) {
      const key = `${login[1]}-${login[2] === 'mobile' ? 'app' : login[2]}`;
      const c = clients[key];
      if (!c.clientId || !c.issuer) return reply(res, 503, { error: 'oidc_client_not_configured' });
      const doc = await discover(c.issuer);
      const state = random(32), nonce = random(24), verifier = random(32);
      const now = Date.now();
      for (const [k,p] of Object.entries(s.pending)) if (now-p.at > 300000) delete s.pending[k];
      if (Object.keys(s.pending).length >= 8)
        return reply(res, 429, { error: 'too_many_pending_authorizations' });
      s.pending[state] = { key, nonce, verifier, at: now,
        returnTo: destination(key, u.searchParams.get('returnTo')) };
      return redirect(res, makeAuthorizationUrl(doc, {
        clientId: c.clientId, redirectUri: callbackUrl(key), state, nonce, verifier,
        scope: process.env.WSO2_CASES_SCOPES_ENABLED === '1' && process.env.WSO2_CASES_API_AUDIENCE ? 
          `${c.scope} ciam:cases:create ciam:cases:read ciam:cases:review ciam:cases:approve` : c.scope
      }));
    }
    const cb = /^\/auth\/(aurora|brisa)-(web|mobile|app)\/callback$/.exec(u.pathname);
    if (cb) {
      const key = `${cb[1]}-${cb[2] === 'mobile' ? 'app' : cb[2]}`;
      if (u.pathname !== new URL(callbackUrl(key)).pathname)
        return reply(res, 400, { error: 'unregistered_callback_alias' });
      const parsed = readAuthorizationResponse(u);
      if (!parsed.valid) return reply(res, 400, { error: 'invalid_oidc_callback_parameters' });
      const { state, code } = parsed;
      const pending = s.pending[state];
      if (!pending || pending.key !== key || Date.now()-pending.at > 300000)
        return reply(res, 400, { error: 'invalid_or_expired_oauth_state' });
      delete s.pending[state];
      if (u.searchParams.has('error'))
        return reply(res, 400, { error: 'oidc_provider_error', code: u.searchParams.get('error') });
      if (!code) return reply(res, 400, { error: 'authorization_code_missing' });
      const c = clients[key], doc = await discover(c.issuer);
      const tokens = await exchangeAuthorizationCode(doc, { clientId: c.clientId,
        clientSecret: c.clientSecret, redirectUri: callbackUrl(key), code, verifier: pending.verifier });
      const claims = await verifyIdToken(tokens.id_token, {
        issuer: c.issuer, clientId: c.clientId, nonce: pending.nonce });
      if (typeof tokens.access_token !== 'string' || !tokens.access_token)
        return reply(res, 502, { error: 'wso2_access_token_missing' });
      if (process.env.WSO2_CIAM_BINDING_PROBE === '1') {
        const bound = await verifyAndRecordBinding({
          key, client: c, login: { verified: true, claims, accessToken: tokens.access_token }
        });
        if (!bound) return reply(res, 502, { error: 'wso2_identity_binding_not_verified' });
      }
      if (pending.kind === 'case-approval') {
        // A different, one-use WSO2 transaction. State was consumed before token exchange.
        // Never approve from old ID-token MFA claims, acr_values request or UI state.
        try {
          const proof = verifyApprovalResponse({session:s,pending,key,client:c,claims,policy:totpPolicy()});
          const candidate = { verified:true, claims, accessToken:tokens.access_token };
          const decision = await requireAuthorityForClient(
            {logins:{[key]:candidate}},key,clients,'ciam:cases:approve',
            process.env.WSO2_CASES_API_AUDIENCE);
          if (decision.http !== 200)
            return reply(res,decision.http,{error:decision.reason,allowed:false});
          // UserInfo sub binding is mandatory even for the step-up callback.
          await readVerifiedUserinfo({discovery:doc,issuer:c.issuer,
            accessToken:tokens.access_token,subject:claims.sub});
          commitApprovedCase({brand:proof.brand,caseId:proof.caseId,
            issuer:proof.issuer,subject:proof.subject,authTime:proof.authTime});
          s.logins[key] = {...candidate,verifiedAt:new Date().toISOString()};
          sessionStore.rotate(s,res);
          return redirect(res,`${proof.returnTo}?client=${encodeURIComponent(key)}&approval=check`);
        } catch (e) {
          // No success redirect and no business write after any failed assurance check.
          return reply(res,e.status||403,{error:e.code||'wso2_stepup_not_verified',allowed:false,...(e.attestationGate?{attestationGate:e.attestationGate}:{})});
        }
      }
      s.logins[key] = { claims, verified: true, accessToken: tokens.access_token,
        verifiedAt: new Date().toISOString() };
      sessionStore.rotate(s, res);
      return redirect(res, `${pending.returnTo || '/'}?client=${encodeURIComponent(key)}&authenticated=1`);
    }
    if (await serveStatic(u, res)) return;
    return reply(res, 404, { error: 'live_wso2_no_fixture_route' });
  } catch (e) {
    console.error(JSON.stringify({ event: 'LIVE_REQUEST_FAILURE', route: u.pathname, error: e.message }));
    return reply(res, e.statusCode || 500, {
      error: e.statusCode ? e.message : 'request_failed',
      reason: appConfig.environment === 'production' ? undefined : e.message
    });
  }
}
if (process.env.NODE_ENV !== 'test') createServer(handle).listen(appConfig.port,
  process.env.BIND_HOST || '127.0.0.1', () =>
    console.log(`WSO2-only identity BFF listening on ${appConfig.origin}`));
export { handle };
