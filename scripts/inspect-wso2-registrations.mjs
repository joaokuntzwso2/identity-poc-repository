/** Read-only WSO2 IS 7.3 Management API inventory. Requires an authorized Management API token. */
import { clients } from '../services/identity-bff/src/config.js';
const base = process.env.WSO2_MGMT_BASE;
const bearer = process.env.WSO2_MGMT_BEARER;
if (!base || !bearer || !base.startsWith('https://')) throw new Error('Set HTTPS WSO2_MGMT_BASE and authorized WSO2_MGMT_BEARER');
const appIds = Object.fromEntries(Object.keys(clients).map(x => [x, process.env[`WSO2_${x.toUpperCase().replace(/-/g, '_')}_APP_ID`]]));
if (Object.values(appIds).some(x => !x)) throw new Error('Set WSO2_<BRAND>_<CHANNEL>_APP_ID for all four real application records');
const output = [];
async function fetchApi(path) {
    const res = await fetch(`${base.replace(/\/$/, '')}/api/server/v1${path}`, { headers: { authorization: `Bearer ${bearer}`, accept: 'application/json' }, signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (!res.ok) throw new Error(`WSO2 GET ${path} returned ${res.status}`);
    return res.json();
}
for (const [key, applicationId] of Object.entries(appIds)) {
    if (!/^[0-9a-fA-F-]{36}$/.test(applicationId)) throw new Error(`Invalid WSO2 application UUID for ${key}`);
    const app = await fetchApi(`/applications/${applicationId}`);
    const oidc = await fetchApi(`/applications/${applicationId}/inbound-protocols/oidc`);
    const actualId = oidc.clientId || oidc.clientID || oidc.client_id || null;
    const expected = clients[key].clientId;
    const result = { key, applicationId, appName: app.name, clientIdMatch: Boolean(expected && actualId === expected), protocolReturned: true };
    // Never expose WSO2 client secrets, raw IDs, or full profile dumps.
    output.push(result);
}
console.log(JSON.stringify({ checkedAt: new Date().toISOString(), apps: output, notes: ['Read-only Management API check; subjectType/sectorIdentifier must be verified separately in Console or version-specific documented fields.', 'No pairwise token equality test performed.'] }, null, 2));
if (output.some(x => !x.clientIdMatch)) process.exitCode = 1;
