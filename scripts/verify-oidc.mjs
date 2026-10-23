/** Runtime read-only verification, requires actual trusted WSO2 issuer and clients. */
import { discover, getJson } from '../services/identity-bff/src/oidc.js';
import { clients } from '../services/identity-bff/src/config.js';
const status = [];
for (const client of Object.values(clients)) {
  const result = { client: client.name, configured: Boolean(client.clientId && client.issuer), discovery: false, pairwiseAdvertised: false };
  if (result.configured) {
    try {
      const disc = await discover(client.issuer);
      result.discovery = true;
      result.pairwiseAdvertised = (disc.subject_types_supported || []).includes('pairwise');
      result.jwksReachable = Array.isArray((await getJson(disc.jwks_uri)).keys);
      result.issuer = disc.issuer;
    } catch (e) { result.error = e.message; }
  }
  status.push(result);
}
console.log(JSON.stringify({ status, completedAt: new Date().toISOString(), note: 'OIDC metadata preflight; does not validate subject equality or authentication' }, null, 2));
if (status.some(s => !s.configured || !s.discovery || !s.pairwiseAdvertised || !s.jwksReachable)) process.exitCode = 1;
