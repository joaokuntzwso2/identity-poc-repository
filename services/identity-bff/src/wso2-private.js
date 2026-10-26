/** Strict, local-only WSO2 OIDC manifest adapter. Never import in frontend code. */
import { readFileSync, lstatSync, realpathSync } from 'node:fs';
import { resolve, relative, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CLIENT_KEYS = Object.freeze(['aurora-web', 'aurora-app', 'brisa-web', 'brisa-app']);
const DOMAINS = Object.freeze({ aurora: 'aurora.identity.test', brisa: 'brisa.identity.test' });
const shape = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const keyAlias = key => key.replace(/-app$/, '-mobile');
const CALLBACK_FIELDS = Object.freeze(['callback', 'callbackUrl', 'callbackURL', 'redirectUri', 'redirect_uri']);
/** Exact registered callback aliases only. A mobile browser client may have been
 * provisioned using either the original -app route or the newer -mobile route.
 * Neither channel mapping nor the authorization redirect may infer an unrecorded URL.
 */
function allowedCallbacks(brand, channel, callbackOrigin) {
  const routes = channel === 'web' ? [`${brand}-web`] : [`${brand}-app`, `${brand}-mobile`];
  return routes.map(route => new URL(`/auth/${route}/callback`, callbackOrigin).href);
}
function matchingChannelCallback(entry, brand, channel, origin) {
  const value = pickString(entry, CALLBACK_FIELDS, `${brand}_${channel}_CALLBACK`);
  return typeof value === 'string' && allowedCallbacks(brand, channel, origin).includes(value) ? value : null;
}

const allowedKeys = new Set(CLIENT_KEYS.flatMap(k => [k, keyAlias(k)]));
function required(v, kind) {
  if (typeof v !== 'string' || !v.trim() || v.trim() !== v || v.length > 2048)
    throw new Error(`WSO2_PRIVATE_${kind}_INVALID`);
  return v;
}
function inside(root, file) {
  const r = relative(root, file);
  return r === '' || (r !== '..' && !r.startsWith('..' + (process.platform === 'win32' ? '\\' : '/')) && !isAbsolute(r));
}
function secureRead(file, baseDir) {
  // Compare LIKE-FOR-LIKE lexical paths first. On macOS /var is a symlink to
  // /private/var; comparing realpath(baseDir) with resolve(file) falsely rejects
  // honest temporary directories before lstat can return ENOENT.
  const absolute = resolve(file);
  if (!inside(resolve(baseDir), absolute)) throw new Error('WSO2_PRIVATE_OUTSIDE_LOCAL_STATE');
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 128 * 1024)
    throw new Error('WSO2_PRIVATE_FILE_UNSAFE');
  if ((stat.mode & 0o077) !== 0) throw new Error('WSO2_PRIVATE_PERMISSIONS_REQUIRE_0600');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    throw new Error('WSO2_PRIVATE_OWNER_MISMATCH');
  // Re-check canonical paths. A symlink at var/wso2 must not relocate
  // private material into the Git worktree root or anywhere else.
  const canonicalRoot = realpathSync(resolve(baseDir, '../..'));
  const canonicalBase = realpathSync(baseDir);
  if (canonicalBase !== join(canonicalRoot, 'var/wso2') || !inside(canonicalBase, realpathSync(absolute)))
    throw new Error('WSO2_PRIVATE_PATH_ESCAPE');
  let data;
  try { data = JSON.parse(readFileSync(absolute, 'utf8')); }
  catch { throw new Error('WSO2_PRIVATE_MALFORMED_JSON'); }
  if (!shape(data)) throw new Error('WSO2_PRIVATE_EXPECTED_OBJECT');
  return data;
}
function listKey(row) {
  if (!shape(row)) return null;
  const direct = [row.key, row.clientKey, row.registrationKey, row.idKey, row.name]
    .filter(v => typeof v === 'string' && allowedKeys.has(v));
  if (new Set(direct).size > 1) throw new Error('WSO2_PRIVATE_AMBIGUOUS_CLIENT_KEY');
  if (direct.length) return direct[0];
  return ['aurora', 'brisa'].includes(row.brand) && ['web', 'app', 'mobile'].includes(row.channel)
    ? `${row.brand}-${row.channel}` : null;
}
function asMap(collection, callbackOrigin) {
  if (Array.isArray(collection)) {
    if (!collection.length) return null;
    const mapped = {};
    for (const row of collection) {
      const key = listKey(row);
      if (!key) return null; // Not an explicit four-client OIDC collection.
      if (Object.hasOwn(mapped, key)) throw new Error('WSO2_PRIVATE_DUPLICATE_CLIENT');
      mapped[key] = row;
    }
    return mapped;
  }
  if (!shape(collection)) return null;
  if (Object.keys(collection).some(k => allowedKeys.has(k))) return collection;
  // A brand can name its two registrations using local bootstrap identifiers.
  // Only an exact, explicit callback URI may identify unknown channel keys:
  // neither insertion order nor client ID / secret text may establish identity.
  // Common bootstrap representation: {aurora:{clients:{opaqueLabel:{callback,...}}}, brisa:{...}}
  // Tenant/brand metadata may be inherited, but secrets cannot be inherited.
  const mapped = {};
  for (const brand of ['aurora', 'brisa']) {
    const container = collection[brand];
    if (!shape(container)) return null;
    const scoped = shape(container.clients) ? container.clients :
      shape(container.oidcClients) ? container.oidcClients :
      shape(container.applications) ? container.applications : container;
    const entries = Object.entries(scoped).filter(([, record]) => shape(record));
    // Client-only collections must contain exactly two structured registrations;
    // top-level brand containers may also contain scalar issuer/domain metadata.
    if (scoped !== container && Object.keys(scoped).length !== entries.length)
      throw new Error(`WSO2_PRIVATE_BRAND_CLIENT_SHAPE_INVALID_${brand}`);
    if (entries.length !== 2)
      throw new Error(`WSO2_PRIVATE_BRAND_CLIENT_SHAPE_INVALID_${brand}`);
    const taken = new Set();
    for (const channel of ['web', 'mobile']) {
      // Both callback spellings are permitted ONLY when explicitly recorded.
      // The original WSO2 provisioning plan uses /auth/<brand>-app/callback.
      // Modern private manifests may instead use /auth/<brand>-mobile/callback.
      const explicitKeys = channel === 'mobile'
        ? ['mobile', 'app', `${brand}-mobile`, `${brand}-app`]
        : ['web', `${brand}-web`];
      const explicit = explicitKeys.filter(key => Object.hasOwn(scoped, key));
      if (explicit.length > 1) throw new Error(`WSO2_PRIVATE_AMBIGUOUS_CHANNEL_${brand}_${channel}`);
      let label = explicit[0];
      if (label === undefined) {
        const matches = entries.filter(([, record]) => {
          return matchingChannelCallback(record, brand, channel, callbackOrigin) !== null;
        });
        if (matches.length !== 1)
          throw new Error(`WSO2_PRIVATE_UNRECOGNIZED_CHANNEL_CALLBACK_${brand}_${channel}`);
        label = matches[0][0];
      }
      if (taken.has(label)) throw new Error(`WSO2_PRIVATE_DUPLICATE_CHANNEL_${brand}`);
      taken.add(label);
      const entry = scoped[label];
      mapped[`${brand}-${channel}`] = {
        ...entry,
        issuer: entry.issuer ?? entry.issuerUrl ?? container.issuer ?? container.issuerUrl,
        tenantDomain: entry.tenantDomain ?? (typeof entry.tenant === 'string' ? entry.tenant : undefined) ??
          container.tenantDomain ?? (typeof container.domain === 'string' ? container.domain : undefined),
      };
    }
    if (taken.size !== entries.length) throw new Error(`WSO2_PRIVATE_UNMAPPED_BRAND_CLIENT_${brand}`);
  }
  return mapped;
}
const COLLECTION_PATHS = Object.freeze([
  [], ['clients'], ['oidcClients'], ['applications'], ['registrations'],
  ['oidcApplications'], ['clientConfigurations'], ['bffClients'], ['clientRegistry'],
  ['tenantClients'], ['providers'], ['brands'], ['tenants'],
  ['bff', 'clients'], ['bff', 'applications'], ['bff', 'providers'],
  ['identityBff', 'clients'], ['identityBff', 'applications'],
  ['oidc', 'clients'], ['oidc', 'applications'],
  ['integration', 'clients'], ['wso2', 'clients'], ['wso2', 'oidcClients'],
]);
function atPath(obj, path) { return path.reduce((value, part) => value?.[part], obj); }
function normalizeCollection(manifest, callbackOrigin) {
  const candidates = [];
  for (const path of COLLECTION_PATHS) {
    const map = asMap(atPath(manifest, path), callbackOrigin);
    if (map) candidates.push({ path: path.join('.') || '$', map });
  }
  if (candidates.length === 0) throw new Error('WSO2_PRIVATE_CLIENT_COLLECTION_MISSING');
  if (candidates.length !== 1) throw new Error('WSO2_PRIVATE_AMBIGUOUS_CLIENT_COLLECTION');
  return candidates[0].map;
}
function valueFor(collection, key) {
  const alias = keyAlias(key);
  if (Object.hasOwn(collection, key) && alias !== key && Object.hasOwn(collection, alias))
    throw new Error(`WSO2_PRIVATE_AMBIGUOUS_${key}`);
  return collection[key] ?? collection[alias];
}
function pickString(entry, fields, name, fallback) {
  const sources = [entry, ...(shape(entry.oidc) ? [entry.oidc] : []),
    ...(shape(entry.oauth) ? [entry.oauth] : []),
    ...(shape(entry.credentials) ? [entry.credentials] : []),
    ...(shape(entry.registration) ? [entry.registration] : [])];
  const found = [];
  for (const obj of sources) for (const field of fields) {
    if (obj[field] !== undefined && obj[field] !== null) found.push(obj[field]);
  }
  if (found.length > 1 && new Set(found).size > 1)
    throw new Error(`WSO2_PRIVATE_CONFLICTING_${name}`);
  return found.length ? found[0] : fallback;
}
function trustedHttps(value, field) {
  const v = required(value, field);
  let url; try { url = new URL(v); } catch { throw new Error(`WSO2_PRIVATE_${field}_URL_INVALID`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || url.href !== v)
    throw new Error(`WSO2_PRIVATE_${field}_MUST_BE_HTTPS`);
  return v;
}
export function validatePrivateClients(manifest, { origin = 'http://127.0.0.1:4000' } = {}) {
  const callbackOrigin = new URL(origin);
  if (!['http:', 'https:'].includes(callbackOrigin.protocol) || callbackOrigin.username || callbackOrigin.password || callbackOrigin.pathname !== '/' || callbackOrigin.search || callbackOrigin.hash)
    throw new Error('WSO2_PRIVATE_CALLBACK_ORIGIN_INVALID');
  if (callbackOrigin.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(callbackOrigin.hostname))
    throw new Error('WSO2_PRIVATE_HTTP_CALLBACK_NOT_LOOPBACK');
  const collection = normalizeCollection(manifest, callbackOrigin);
  const result = {}, ids = new Set(), issuers = {};
  for (const key of CLIENT_KEYS) {
    const entry = valueFor(collection, key);
    if (!shape(entry)) throw new Error(`WSO2_PRIVATE_CLIENT_MISSING_${key}`);
    const [brand, channel] = key.split('-');
    const clientId = required(pickString(entry,
      ['clientId', 'client_id', 'oauthClientId', 'oauth2ClientId', 'clientID'], `${key}_ID`), `${key}_ID`);
    const clientSecret = required(pickString(entry,
      ['clientSecret', 'client_secret', 'oauthClientSecret', 'oauth2ClientSecret'], `${key}_SECRET`), `${key}_SECRET`);
    const issuer = trustedHttps(pickString(entry,
      ['issuer', 'issuerUrl', 'oidcIssuer', 'issuerURL'], `${key}_ISSUER`, manifest.issuers?.[brand]), `${key}_ISSUER`);
    const tenantDomain = entry.tenantDomain ?? (typeof entry.tenant === 'string' ? entry.tenant : entry.tenant?.domain) ?? DOMAINS[brand];
    if (tenantDomain !== DOMAINS[brand] || !issuer.includes(`/t/${DOMAINS[brand]}/`))
      throw new Error(`WSO2_PRIVATE_TENANT_MISMATCH_${key}`);
    // Never derive the redirect URI independently of the registered client.
    // Without an explicit canonical callback, live client loading must fail.
    const recorded = pickString(entry, CALLBACK_FIELDS, `${key}_CALLBACK`);
    const allowed = allowedCallbacks(brand, channel === 'app' ? 'mobile' : channel, callbackOrigin);
    if (typeof recorded !== 'string' || !allowed.includes(recorded))
      throw new Error(`WSO2_PRIVATE_CALLBACK_MISMATCH_${key}`);
    const redirectUri = recorded;
    if (ids.has(clientId)) throw new Error('WSO2_PRIVATE_CLIENT_IDS_NOT_UNIQUE');
    ids.add(clientId);
    if (issuers[brand] && issuers[brand] !== issuer)
      throw new Error(`WSO2_PRIVATE_BRAND_ISSUERS_DIFFER_${brand}`);
    issuers[brand] = issuer;
    result[key] = Object.freeze({ name: key, brand, channel, clientId, clientSecret, issuer, scope: 'openid', redirectUri });
  }
  if (issuers.aurora === issuers.brisa) throw new Error('WSO2_PRIVATE_TENANT_ISSUERS_IDENTICAL');
  return Object.freeze(result);
}
/** Live mode NEVER falls back to environment-defined OAuth clients. */
export function loadPrivateWso2Clients({ env = process.env, fallback = {}, projectRoot = fileURLToPath(new URL('../../../', import.meta.url)) } = {}) {
  const enabled = env.IDENTITY_MODE === 'live-wso2' || Boolean(env.WSO2_BFF_PRIVATE_MANIFEST);
  if (!enabled) return fallback;
  const baseDir = join(projectRoot, 'var/wso2');
  const requested = env.WSO2_BFF_PRIVATE_MANIFEST || join(baseDir, 'identity-bff-wso2.private.json');
  const file = isAbsolute(requested) ? requested : resolve(projectRoot, requested);
  return validatePrivateClients(secureRead(file, baseDir), { origin: env.PUBLIC_ORIGIN || 'http://127.0.0.1:4000' });
}
