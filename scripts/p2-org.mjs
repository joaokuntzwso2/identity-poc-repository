#!/usr/bin/env node
/** P2.24 operator CLI: no token printed; no automatic writes; no insecure TLS. */
import { lstatSync, readFileSync } from 'node:fs';
import { planPartner, applyPartner, planPartnerDeactivation, deactivatePartner, rootTenant } from './p2-org-core.mjs';
const required = (n) => { const x=process.env[n]; if(!x) throw new Error(`${n}_required`); return x; };
function tokenFromPrivateFile() {
  const path=required('CIAM_P2_ORG_TOKEN_FILE');
  const st=lstatSync(path);
  if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) !== 0 ||
      (process.getuid && st.uid !== process.getuid()) || st.size > 32768)
    throw new Error('management_token_file_must_be_owner_only_0600');
  const token=readFileSync(path,'utf8').trim();
  if (!/^[\w~.+/-]+(?:[=]*)$/.test(token) || token.length < 16) throw new Error('invalid_token_file');
  return token;
}
export function secureBase() {
  const value=process.env.CIAM_P2_WSO2_BASE || 'https://localhost:9444';
  const u = new URL(value);
  if (u.protocol !== 'https:' || !['localhost','127.0.0.1'].includes(u.hostname) ||
      u.port !== '9444' || u.pathname !== '/' || u.search || u.hash || u.username || u.password)
    throw new Error('only_existing_https_local_wso2_9444_is_permitted');
  return value;
}
export function clientFor(token) {
  return async (method, url, body) => {
    const u=new URL(url);
    if (u.origin !== new URL(secureBase()).origin ||
        !/^\/t\/(aurora|brisa)\.identity\.test\/o\/api\/server\/v1\/organizations(?:\/.*)?$/.test(u.pathname))
      throw new Error('management_request_outside_tenant_allowlist');
    const response = await fetch(u, {
      method, redirect:'manual', signal:AbortSignal.timeout(8000),
      headers:{'accept':'application/json','authorization':`Bearer ${token}`,
        ...(body ? {'content-type':'application/json'} : {})},
      ...(body ? {body:JSON.stringify(body)} : {})
    });
    if (!response.ok || response.status >= 300) throw new Error(`wso2_management_http_${response.status}_do_not_retry_blindly`);
    const text=await response.text();
    if (text.length > 256 * 1024) throw new Error('wso2_response_oversize');
    try {return text ? JSON.parse(text) : null;} catch {throw new Error('wso2_invalid_json');}
  };
}
async function main() {
  const [action,tenant,name,handle,approval] = process.argv.slice(2);
  if (!['plan','create','plan-disable','disable'].includes(action) || !tenant || !name || !handle)
    throw new Error('usage: node scripts/p2-org.mjs plan|create|plan-disable|disable <aurora.identity.test|brisa.identity.test> <partner-name> <partner-handle> [approval_sha256]');
  rootTenant(tenant); const base=secureBase(), client=clientFor(tokenFromPrivateFile());
  let result;
  if(action==='plan') result=await planPartner({client,base,tenant,name,handle});
  if(action==='create') result=await applyPartner({client,base,tenant,name,handle,approval});
  if(action==='plan-disable') result=await planPartnerDeactivation({client,base,tenant,name,handle});
  if(action==='disable') result=await deactivatePartner({client,base,tenant,name,handle,approval});
  process.stdout.write(JSON.stringify({evidence:'WSO2_ORGANIZATION_API_DIRECT_READBACK',...result},null,2)+'\n');
}
if (import.meta.url === `file://${process.argv[1]}`) main().catch(e=>{
  // Do not print raw fetch exceptions that might include private hostnames or body.
  const message=String(e.message || 'operation_failed');
  console.error(JSON.stringify({ok:false,error:message.replace(/[\r\n]/g,' ').slice(0,180)}));
  process.exitCode=1;
});
