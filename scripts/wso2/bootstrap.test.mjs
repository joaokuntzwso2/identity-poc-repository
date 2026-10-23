import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync} from 'node:fs';import{tmpdir}from'node:os';import{join}from'node:path';
import {execute} from './cli.mjs';import {deploymentPlan,config} from './domain.mjs';import{documents}from'./sector.mjs';
test('fake-Wso2 bootstrap/verified inventory/reset roundtrip, no unowned objects',async()=>{
 const tmp=mkdtempSync(join(tmpdir(),'is-bootstrap-'));const attest=join(tmp,'attest.json'),inventoryPath=join(tmp,'inventory.json'),credentialsPath=join(tmp,'credentials.json');
 writeFileSync(attest,JSON.stringify({release:'7.3.0',update:18,imageDigest:'sha256:'+'a'.repeat(64)}));
 const env={WSO2_BASE_URL:'https://localhost:9443',WSO2_ADMIN_USER:'admin',WSO2_ADMIN_PASSWORD:'test-only',WSO2_ORG_API_TOKEN:'test-only-org',WSO2_BUILD_ATTESTATION_FILE:attest,
 DEMO_PUBLIC_BASE_URL:'https://demo.example.invalid',DEMO_AURORA_SECTOR_BASE_URL:'https://aurora-sectors.example.invalid',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa-sectors.example.invalid',WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES'};
 const p=deploymentPlan(config(),env),doc=documents(p);const sectorFetchImpl=async url=>({ok:true,text:async()=>JSON.stringify(doc[url.includes('aurora')?'aurora':'brisa'])});
 const deleted=[],created=[];let id=0;
 const fake={hashOrigin:()=> 'mock-origin',createApp:async x=>{created.push(['application',x.name]);return {data:{id:`app-${++id}aaaa`}}},
 getApp:async x=>({data:{id:x}}),getUser:async x=>({data:{id:x}}),getOrg:async x=>({data:{id:x}}),
 getOidc:async id=>({data:{clientId:`oauth-${id}`,clientSecret:`fixture-secret-${id}`}}),
 createUser:async x=>{created.push(['user',x.userName]);return {data:{id:`usr-${++id}aaaa`}}},
 createOrg:async x=>{created.push(['org',x.name]);return {data:{id:`org-${++id}aaaa`}}},
 deleteApp:async x=>{deleted.push(['application',x])},deleteUser:async x=>{deleted.push(['user',x])},deleteOrg:async x=>{deleted.push(['org',x])}};
 const opts={env,client:fake,emit:()=>{},inventoryPath,credentialsPath,sectorFetchImpl};
 await execute('apply',opts);const inv=JSON.parse(readFileSync(inventoryPath));assert.equal(inv.resources.length,13);assert.equal(inv.completion,'PARTIAL_INTEGRATION_REQUIRED');
 const secrets=JSON.parse(readFileSync(credentialsPath));assert.equal(Object.keys(secrets.clients).length,6);assert.equal(Object.keys(secrets.users).length,4);
 await execute('apply',opts);assert.equal(created.length,13,'second apply is no-op for inventoried resources');
 assert.deepEqual(JSON.parse(readFileSync(credentialsPath)).users,secrets.users,'repeat bootstrap preserves real user passwords');
 env.WSO2_LAB_CONFIRM='DELETE_LAB_OWNED_RESOURCES';await execute('reset',opts);assert.equal(deleted.length,13);assert.equal(JSON.parse(readFileSync(inventoryPath)).resources.length,0);
 assert.equal(Object.keys(JSON.parse(readFileSync(credentialsPath)).clients).length,0);assert.equal(Object.keys(JSON.parse(readFileSync(credentialsPath)).users).length,0);
 assert.ok(deleted.slice(0,3).every(v=>v[0]==='org'),'reset children before app/users');
});
