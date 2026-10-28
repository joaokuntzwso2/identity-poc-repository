#!/usr/bin/env node
/** Public-safe, GET-only: inspect real BFF runtime and verified WSO2 application readback.
 * Do not import config.js in an untrusted shell; that loses the private runtime manifest.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve, dirname, join } from 'node:path';
import { assessReadbacks } from './ciam-p010-preflight-core.mjs';
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BFF = 'http://127.0.0.1:4400';
async function get(path) {
  const res = await fetch(BFF + path, {headers:{accept:'application/json'},redirect:'error',
    signal:AbortSignal.timeout(12000)});
  if (!res.ok) throw Error('BFF_HTTP_'+res.status);
  const body=await res.text();if(body.length>100000)throw Error('BFF_OVERSIZED_RESPONSE');
  return JSON.parse(body);
}
try {
  const [me, runtime]=await Promise.all([get('/api/identity/me'),get('/api/wso2-status')]);
  // Uses the already-proven 0600 private tenant and OIDC journals; no client secrets in stdout.
  const policy = spawnSync('python3',[join(REPO,'scripts/ciam-p010-wso2-auth-policy-readback.py')],{
    cwd:REPO,encoding:'utf8',timeout:65000,maxBuffer:250000,env:process.env
  });
  if(policy.error || policy.status!==0)throw Error('WSO2_MANAGEMENT_READBACK_UNAVAILABLE');
  const report=assessReadbacks(me,runtime,JSON.parse(policy.stdout));
  report.at=new Date().toISOString();
  console.log(JSON.stringify(report,null,2));
  if (!report.fourClientsReadyForInteractiveLogin)process.exitCode=2;
}catch(error){
  // No private URLs, credentials or raw remote response in error output.
  const code=String(error?.message||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,'_').slice(0,80);
  console.log(JSON.stringify({stage:'P008_P010_RUNTIME_AND_MANAGEMENT_PREFLIGHT_V2',
    status:'BLOCKED_PREFLIGHT',remoteWrites:0,browserLoginsPerformed:0,reason:code},null,2));
  process.exitCode=2;
}
