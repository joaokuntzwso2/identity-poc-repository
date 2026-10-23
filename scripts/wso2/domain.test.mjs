import test from 'node:test';import assert from 'node:assert/strict';import{mkdtempSync,writeFileSync}from'node:fs';import{tmpdir}from'node:os';import{join}from'node:path';
import{config,validate,deploymentPlan,assertUpdatedBuild}from'./domain.mjs';import{documents,writeSectorDocuments,assertSectorDocuments}from'./sector.mjs';
const c=config();const env={DEMO_PUBLIC_BASE_URL:'https://demo.example.invalid',DEMO_AURORA_SECTOR_BASE_URL:'https://aurora-sectors.example.invalid',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa-sectors.example.invalid'};
test('four independent OIDC clients: same-brand sector, separate brands',()=>{const p=deploymentPlan(c,env);assert.equal(p.apps.filter(x=>x.brand!=='workload').length,4);assert.equal(new Set(p.apps.map(x=>x.key)).size,6);assert.equal(new Set(p.apps.filter(x=>x.brand!=='workload').map(x=>x.sector)).size,2);assert.notEqual(p.apps[0].sector,p.apps[2].sector)});
test('reject duplicate sector across brands',()=>{const copy=structuredClone(c);copy.brands[1].sector=copy.brands[0].sector;assert.throws(()=>validate(copy),/SECTOR_MUST_DIFFER/)});
test('reject missing mobile and invalid organization parent',()=>{const copy=structuredClone(c);copy.brands[0].clients.pop();assert.throws(()=>validate(copy),/FOUR_CLIENTS_REQUIRED/);const more=structuredClone(c);more.b2bOrganizations[0].parent='missing';assert.throws(()=>validate(more),/INVALID_PARENT/)});
test('plan rejects insecure nonlocal deployment',()=>assert.throws(()=>deploymentPlan(c,{DEMO_PUBLIC_BASE_URL:'http://demo.example.com'}),/PUBLIC_BASE/));
test('plan never claims live verification',()=>{const p=deploymentPlan(c,env);assert.equal(p.mode,'PLAN_ONLY');assert.equal(p.acceptance,'NOT_VERIFIED');assert.ok(p.manualGates.length>4)});
test('sector document matches all same-brand callback URIs',()=>{const p=deploymentPlan(c,env);const d=documents(p);assert.equal(d.aurora.length,2);assert.equal(d.brisa.length,2);assert.ok(d.aurora.every(s=>s.includes('aurora')));assert.ok(d.brisa.every(s=>s.includes('brisa')))});
test('sector retrieval fails on mismatch and allows exact source',async()=>{const p=deploymentPlan(c,env);const d=documents(p);const f=async url=>({ok:true,status:200,text:async()=>JSON.stringify(d[url.includes('aurora')?'aurora':'brisa'])});assert.equal(await assertSectorDocuments(p,env,f),true);await assert.rejects(()=>assertSectorDocuments(p,env,async()=>({ok:true,text:async()=>JSON.stringify(['https://attacker.example/'])})),/SECTOR_REDIRECT_MISMATCH/)});
test('build below level 18 is rejected; update attestation required',()=>{const dir=mkdtempSync(join(tmpdir(),'wso2-attest-'));const f=join(dir,'level.json');writeFileSync(f,JSON.stringify({release:'7.3.0',update:17,imageDigest:'sha256:'+'a'.repeat(64)}));assert.throws(()=>assertUpdatedBuild({WSO2_BUILD_ATTESTATION_FILE:f}),/MINIMUM/);writeFileSync(f,JSON.stringify({release:'7.3.0',update:18,imageDigest:'sha256:'+'a'.repeat(64)}));assert.equal(assertUpdatedBuild({WSO2_BUILD_ATTESTATION_FILE:f}).update,18)});
test('live registration callbacks match the exact existing identity BFF routes, not synthetic API paths',()=>{
 const p=deploymentPlan(c,{...env,DEMO_BFF_BASE_URL:'https://login.example.invalid'});
 assert.deepEqual(p.apps.filter(a=>a.brand!=='workload').map(a=>a.callback).sort(),[
  'https://login.example.invalid/auth/aurora-app/callback',
  'https://login.example.invalid/auth/aurora-web/callback',
  'https://login.example.invalid/auth/brisa-app/callback',
  'https://login.example.invalid/auth/brisa-web/callback']);
 assert.ok(p.apps.filter(a=>a.brand!=='workload').every(a=>a.accessUrl.startsWith('https://demo.example.invalid/')));
});
