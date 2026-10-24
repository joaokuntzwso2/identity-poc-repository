#!/usr/bin/env node
// Read-only diagnostic for a POST-completed but owner-unverified root tenant.
// All output is explicitly allowlisted; no credentials, tokens, tenant IDs, or response bodies.
import {readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const statePath = resolve(root, 'var/wso2/tenant-brand.private.json');
const output = {purpose:'TENANT_OWNER_READ_ONLY_CHECK',method:'GET',writes:0};
try {
  const base = new URL(process.env.WSO2_BASE_URL || 'https://localhost:9443');
  if (base.origin !== 'https://localhost:9443' && base.origin !== 'https://127.0.0.1:9443')
    throw Error('UNTRUSTED_LOCAL_ORIGIN');
  if (base.username || base.password || base.pathname !== '/' || base.search || base.hash)
    throw Error('UNTRUSTED_LOCAL_ORIGIN');
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw Error('TLS_VERIFICATION_DISABLED');
  const state = JSON.parse(readFileSync(statePath,'utf8'));
  const item = state.tenants?.aurora;
  if (!item || item.domain !== 'aurora.identity.test' || item.owned !== true ||
      !['create-started','created'].includes(item.state) ||
      !item.owner?.username || !item.owner?.password)
    throw Error('JOURNAL_OWNERSHIP_NOT_ESTABLISHED');
  output.brand = 'aurora';
  output.journalState = item.state;
  const tenant = encodeURIComponent(item.domain);
  const auth = 'Basic ' + Buffer.from(`${item.owner.username}@${item.domain}:${item.owner.password}`,'utf8').toString('base64');
  for (const [name, path] of [
    ['applicationList',`/t/${tenant}/api/server/v1/applications?limit=1`],
    ['scimSelf',`/t/${tenant}/scim2/Me`]
  ]) {
    try {
      const response = await fetch(new URL(path, base), {
        method:'GET', redirect:'error',
        headers: {Accept:'application/json',Authorization:auth},
        signal:AbortSignal.timeout(12000)
      });
      output[name] = {httpStatus:response.status};
      // Avoid consuming/printing the response body: it can contain sensitive PII.
      await response.body?.cancel();
    } catch (e) {
      output[name] = {errorCode: /^[-A-Z0-9_]{2,80}$/.test(e.cause?.code || '') ? e.cause.code : 'FETCH_FAILED'};
    }
  }
} catch (e) {
  output.preflightError = /^[A-Z0-9_]{2,80}$/.test(e.message) ? e.message : 'PREFLIGHT_FAILED';
}
console.log(JSON.stringify(output,null,2));
if (output.preflightError || !output.applicationList || output.applicationList.httpStatus !== 200)
  process.exitCode=2;
