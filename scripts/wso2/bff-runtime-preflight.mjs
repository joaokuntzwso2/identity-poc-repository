/** Read-only discovery/identity BFF config gate. Never logs secrets. */
import { clients, appConfig } from '../../services/identity-bff/src/config.js';
import { discover, getJson, assertTrustedEndpoint } from '../../services/identity-bff/src/oidc.js';
import { CLIENT_KEYS } from '../../services/identity-bff/src/wso2-private.js';

if (process.env.IDENTITY_MODE !== 'live-wso2' || process.env.WSO2_INTEGRATION_ACK !== 'yes') {
  console.error('BFF_PREFLIGHT_REFUSED: explicit live integration acknowledgement required');
  process.exit(2);
}
if (appConfig.origin !== 'http://127.0.0.1:4000' && appConfig.origin !== 'https://127.0.0.1:4000') {
  console.error('BFF_PREFLIGHT_REFUSED: callback origin must match the four registered 127.0.0.1:4000 redirect URLs');
  process.exit(2);
}
try {
  const statuses = [];
  for (const key of CLIENT_KEYS) {
    const client = clients[key];
    const doc = await discover(client.issuer); // GET, no changes
    if (doc.issuer !== client.issuer) throw new Error(`issuer mismatch: ${key}`);
    if (Array.isArray(doc.code_challenge_methods_supported) && !doc.code_challenge_methods_supported.includes('S256')) throw new Error(`PKCE S256 unsupported: ${key}`);
    if (Array.isArray(doc.id_token_signing_alg_values_supported) && !doc.id_token_signing_alg_values_supported.some(v => ['RS256', 'RS384', 'RS512'].includes(v))) throw new Error(`No supported JWT signature algorithm: ${key}`);
    const jwks = await getJson(assertTrustedEndpoint(doc.jwks_uri, client.issuer));
    if (!Array.isArray(jwks.keys) || !jwks.keys.some(k => k.kty === 'RSA' && typeof k.kid === 'string' && k.kid.length > 0)) throw new Error(`No usable RSA JWKS: ${key}`);
    statuses.push({ client: key, issuer: doc.issuer, discovery: 'READ_ONLY_VERIFIED', jwks: 'READ_ONLY_REACHABLE',
      pairwiseAdvertised: doc.subject_types_supported?.includes('pairwise') === true,
      idTokenSignature: 'NOT_BROWSER_VERIFIED' });
  }
  console.log(JSON.stringify({ gate: 'BFF_READ_ONLY_PREFLIGHT_OK', statuses,
    interactiveLogin: 'NOT_VERIFIED', crossTenantSso: 'NOT_VERIFIED', signedPairwiseTokens: 'NOT_VERIFIED' }, null, 2));
} catch (e) {
  console.error('BFF_READ_ONLY_PREFLIGHT_FAILED: '+e.message);
  process.exitCode = 2;
}
