import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const read=p=>readFile(resolve(p),'utf8');
test('premium assets are same-origin BFF resources, not synthetic identity',async()=>{
  const s=await read('services/identity-bff/src/server.js');
  const h=await read('services/identity-bff/src/live-experience-v5.html');
  const ui=await read('services/identity-bff/src/live-premium-p120.js');
  assert.match(s,/\/live-premium-p120\.js/);
  assert.match(s,/\/live-premium-p120\.css/);
  assert.match(h,/live-premium-p120\.js/);
  assert.match(ui,/\/api\/identity\/me/);
  assert.match(ui,/\/api\/wso2-status/);
  assert.match(ui,/\/api\/brands\//);
  assert.doesNotMatch(ui,/localStorage|document\.cookie|access_token|sessionStorage/);
});
test('startup provenance includes same-source asset digest and current Git commit',async()=>{
  const s=await read('services/identity-bff/src/server.js');
  const provenance=await read('services/identity-bff/src/demo-provenance-p123.js');
  assert.match(s,/demoProvenance/);
  assert.match(provenance,/createHash\('sha256'\)/);
  assert.match(provenance,/rev-parse/);
});
test('preflight cannot turn old demo evidence into positive TOTP proof',async()=>{
  const s=await read('scripts/demo-preflight.mjs');
  assert.match(s,/mfa\.positive_approval','BLOCKED'/);
  assert.match(s,/business\.persistence','BLOCKED'/);
  assert.match(s,/database\.consistency','BLOCKED'/);
  assert.match(s,/NOT_READY/);
  assert.match(s,/BLOCKED/);
});

test('Existing WSO2 approval HTTP 202 handoff and persisted readback are preserved', async()=>{
  const v5=await read('services/identity-bff/src/live-experience-v5.js');
  assert.match(v5,/async function approveCase\(id,button\)/);
  assert.match(v5,/response\.status===202&&data\.status==='WSO2_TOTP_STEP_UP_REQUIRED'/);
  assert.match(v5,/location\.assign\(data\.authorizationUrl\)/);
  assert.match(v5,/record\.history\?\.some\(e=>e\.action==='approved'/);
});
