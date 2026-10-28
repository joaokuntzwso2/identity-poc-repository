/** WSO2-authoritative access validation. No local permissions or consent. */
const SCOPE_NAME = /^[A-Za-z0-9:._/-]{1,160}$/;

export class AuthorityUnavailable extends Error {
  constructor() { super('WSO2_AUTHORITY_UNAVAILABLE'); this.name = 'AuthorityUnavailable'; }
}

export function parseGrantedScopes(scope) {
  const values = typeof scope === 'string' ? scope.trim().split(/\s+/).filter(Boolean) : Array.isArray(scope) ? scope : [];
  if (values.length > 100 || values.some(x => typeof x !== 'string' || !SCOPE_NAME.test(x))) throw new AuthorityUnavailable();
  return [...new Set(values)];
}

export function introspectionUrl(issuer) {
  const u = new URL(issuer);
  if (u.search || u.hash || u.username || u.password || !u.pathname.endsWith('/oauth2/token')) throw new AuthorityUnavailable();
  const loopback = ['localhost', '127.0.0.1'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(loopback && u.protocol === 'http:' && process.env.ALLOW_INSECURE_LOCAL === 'true')) throw new AuthorityUnavailable();
  u.pathname = u.pathname.replace(/\/oauth2\/token$/, '/oauth2/introspect');
  return u.toString();
}

/** Validate a token against WSO2 on every decision. No positive caching. */
export async function inspectAccessToken(login, client, { fetcher = fetch, now = () => Math.floor(Date.now() / 1000), audience = null } = {}) {
  if (!login?.verified || !login?.accessToken || typeof login.accessToken !== 'string' || login.accessToken.length > 16000 ||
      !client?.clientId || !client?.clientSecret || !client?.issuer) throw new AuthorityUnavailable();
  // A scope and audience are NOT sufficient without an authenticated subject.
  // WSO2's signed ID-token `sub` and token introspection `sub` must bind to
  // the same tenant/client identity; an unavailable mapping fails closed.
  const claims = login.claims;
  const idAudiences = typeof claims?.aud === 'string' ? [claims.aud] : claims?.aud;
  if (!claims || claims.iss !== client.issuer ||
      typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 1024 ||
      !Array.isArray(idAudiences) || !idAudiences.includes(client.clientId) ||
      (claims.azp !== undefined && claims.azp !== client.clientId) ||
      !Number.isSafeInteger(claims.exp) || claims.exp <= now())
    return { active: false, scopes: [] };
  const target = introspectionUrl(client.issuer);
  const headers = {
    authorization: `Basic ${Buffer.from(`${client.clientId}:${client.clientSecret}`).toString('base64')}`,
    'content-type': 'application/x-www-form-urlencoded', accept: 'application/json'
  };
  let response, data;
  try {
    response = await fetcher(target, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(6000), headers,
      body: new URLSearchParams({ token: login.accessToken, token_type_hint: 'access_token' }).toString() });
    if (response.status !== 200 || Number(response.headers?.get?.('content-length') || 0) > 65536) throw new Error('invalid_http');
    const raw = await response.text();
    if (raw.length > 65536) throw new Error('oversized');
    data = JSON.parse(raw);
  } catch { throw new AuthorityUnavailable(); }
  if (data?.active !== true) return { active: false, scopes: [] };
  // Reject ambiguous identity/client binding; some WSO2 versions omit `iss`, which
  // is acceptable here ONLY because the introspection URL is tenant-pinned.
  if (data.client_id !== client.clientId || (data.iss !== undefined && data.iss !== client.issuer) ||
      typeof data.sub !== 'string' || !data.sub || data.sub !== claims.sub ||
      !Number.isSafeInteger(data.exp) || data.exp <= now()) return { active: false, scopes: [] };
  const scopes = parseGrantedScopes(data.scope);
  const audiences = typeof data.aud === 'string' ? [data.aud] : Array.isArray(data.aud) ? data.aud : [];
  // API resource audiences can be URI identifiers; keep an exact match.
  if (audience !== null && (typeof audience !== 'string' || audience.length < 1 ||
      audience.length > 512 || !audiences.includes(audience)))
    return { active: false, scopes: [] };
  return { active: true, scopes, exp: data.exp };
}

/** Select the client explicitly; cross-tenant sessions cannot satisfy each other. */
export async function requireAuthorityForClient(session, key, clients, scope, audience, inspect = inspectAccessToken) {
  if (!session?.logins?.[key]?.verified || !clients[key]) return { http: 401, reason: 'authentication_required' };
  if (!audience || !scope || !SCOPE_NAME.test(scope)) return { http: 503, reason: 'wso2_api_policy_not_configured' };
  try {
    const result = await inspect(session.logins[key], clients[key], { audience });
    if (!result.active) return { http: 401, reason: 'access_token_inactive' };
    if (!result.scopes.includes(scope)) return { http: 403, reason: 'wso2_scope_denied' };
    return { http: 200, reason: 'wso2_access_token_verified' };
  } catch { return { http: 503, reason: 'wso2_authority_unavailable' }; }
}
