/** Read ONLY structural hints, NEVER values, from the local private BFF manifest.
 * No network, no child processes and no mutation.
 */
import { readFileSync, lstatSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const path = join(root, 'var/wso2/identity-bff-wso2.private.json');
const shape = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const stat = lstatSync(path);
if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size > 128 * 1024)
  throw new Error('BFF_MANIFEST_SHAPE_REFUSED_UNSAFE_FILE');
if (typeof process.getuid === 'function' && stat.uid !== process.getuid())
  throw new Error('BFF_MANIFEST_SHAPE_REFUSED_OWNER_MISMATCH');
let data;
try { data = JSON.parse(readFileSync(path, 'utf8')); }
catch { throw new Error('BFF_MANIFEST_SHAPE_MALFORMED_JSON'); }
if (!shape(data)) throw new Error('BFF_MANIFEST_SHAPE_EXPECTED_OBJECT');
// Exact static allowlist: never print data-derived key names except those below.
const KNOWN = new Set([
  'schema','version','issuer','issuerUrl','issuers','origin','clients','oidcClients','applications',
  'registrations','oidcApplications','clientConfigurations','bffClients','clientRegistry',
  'tenantClients','providers','brands','tenants','bff','identityBff','oidc','integration','wso2',
  'aurora','brisa','aurora-web','aurora-app','aurora-mobile','brisa-web','brisa-app','brisa-mobile',
  'web','app','mobile','oauth','credentials','registration','tenant','domain','tenantDomain',
  'clientId','client_id','oauthClientId','oauth2ClientId','clientID','clientSecret','client_secret',
  'oauthClientSecret','oauth2ClientSecret','callback','callbackUrl','callbackURL','redirectUri',
  'redirect_uri','name','key','clientKey','channel','brand','state','id','oidcIssuer','issuerURL',
  'privateManifest','configuration','clientConfig','oidcConfiguration','mappings','channels',
]);
const hints = [];
function walk(value, path, depth) {
  if (hints.length >= 85) return;
  const type = Array.isArray(value) ? 'array' : shape(value) ? 'object' : typeof value;
  if (type !== 'object' && type !== 'array') return;
  if (type === 'array') {
    hints.push({ path, kind: 'array', count: value.length });
    if (value.length && depth < 4) walk(value[0], path + '[first-object]', depth + 1);
    return;
  }
  const keys = Object.keys(value);
  const seen = keys.filter(k => KNOWN.has(k)).sort();
  hints.push({ path, kind: 'object', knownFieldNames: seen, unreportedFieldCount: keys.length - seen.length });
  // For this exact two-brand manifest layout, expose only the SHAPE of unknown
  // client entries. Never print the original entry labels or any JSON values.
  if (path === '$.brands.aurora.clients' || path === '$.brands.brisa.clients') {
    const unknown = keys.filter(k => !KNOWN.has(k));
    for (let i = 0; i < unknown.length && i < 4; i++) {
      const entry = value[unknown[i]];
      const kind = Array.isArray(entry) ? 'array' : shape(entry) ? 'object' : typeof entry;
      if (kind === 'object') {
        const entryKeys = Object.keys(entry);
        const entryKnown = entryKeys.filter(k => KNOWN.has(k)).sort();
        // Only emit an enum derived from exact known loopback callback URIs,
        // not the raw URL, label, client ID or credential.
        const brand = path === '$.brands.aurora.clients' ? 'aurora' : 'brisa';
        const cb = entry.callback;
        const possible = ['web', 'app', 'mobile'].map(channel =>
          [`http://127.0.0.1:4000/auth/${brand}-${channel}/callback`, channel]);
        const matched = possible.find(([url]) => cb === url);
        hints.push({ path: `${path}[anonymous-entry-${i + 1}]`, kind,
          knownFieldNames: entryKnown, unreportedFieldCount: entryKeys.length - entryKnown.length,
          callbackCategory: matched ? `REGISTERED_${matched[1].toUpperCase()}_ROUTE` : 'UNKNOWN_OR_UNREGISTERED' });
      } else {
        hints.push({ path: `${path}[anonymous-entry-${i + 1}]`, kind });
      }
    }
  }
  if (depth >= 4) return;
  for (const key of seen) {
    if (shape(value[key]) || Array.isArray(value[key])) walk(value[key], `${path}.${key}`, depth + 1);
  }
}
walk(data, '$', 0);
console.log(JSON.stringify({ gate: 'BFF_PRIVATE_STRUCTURE_ONLY',
  noValuesOrCredentialsEmitted: true, diagnostic: hints }, null, 2));
