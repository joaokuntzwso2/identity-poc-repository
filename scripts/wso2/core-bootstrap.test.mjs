import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execute} from './cli.mjs';
import {config,deploymentPlan} from './domain.mjs';
import {documents} from './sector.mjs';
import {REQUIRED_ORG_SCOPES} from './management-token.mjs';

function harness(){
 const dir=mkdtempSync(join(tmpdir(),'identity-core-v084-'));
 const attest=join(dir,'update.json'),inventoryPath=join(dir,'inventory.json'),credentialsPath=join(dir,'credentials.json');
 writeFileSync(attest,JSON.stringify({release:'7.3.0',update:18,imageDigest:'sha256:'+'a'.repeat(64)}));
 const env={WSO2_BASE_URL:'https://localhost:9443',WSO2_ADMIN_USER:'admin',WSO2_ADMIN_PASSWORD:'fixture-only',
  WSO2_BUILD_ATTESTATION_FILE:attest,WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES'};
 const actions=[],messages=[];let next=0,authorized=[];
 const id=(prefix)=>`${prefix}-${String(++next).padStart(6,'0')}`;
 const orgResource={id:'organization-resource-001',identifier:'/api/server/v1/organizations',scopes:REQUIRED_ORG_SCOPES.map(name=>({name}))};
 const client={hashOrigin:()=> 'fixture-origin',
  createApp:async x=>{const newId=id('app');actions.push({kind:'app',object:x,id:newId});return {data:{id:newId}};},
  getApp:async id=>({data:{id}}),getOidc:async id=>({data:{clientId:`oauth-${id}`,clientSecret:`secret-${id}`}}),
  createUser:async x=>{const newId=id('usr');actions.push({kind:'user',object:x,id:newId});return {data:{id:newId}};},
  getUser:async id=>({data:{id}}),deleteUser:async id=>{actions.push({kind:'deleteUser',id});},
  createOrg:async x=>{const newId=id('org');actions.push({kind:'org',object:x,id:newId});return {data:{id:newId}};},
  getOrg:async id=>({data:{id}}),deleteOrg:async id=>{actions.push({kind:'deleteOrg',id});},
  deleteApp:async id=>{actions.push({kind:'deleteApp',id});},
  listApiResources:async()=>({data:{apiResources:[orgResource]}}),
  getAuthorizedApis:async()=>({data:{authorizedAPIs:authorized}}),
  authorizeApi:async(_,body)=>{authorized.push(body);return {status:201,data:{}}},
 };
 const opts={env,client,inventoryPath,credentialsPath,emit:s=>messages.push(s),
  sectorFetchImpl:async()=>{throw Error('SECTOR_FETCH_MUST_NOT_BE_CALLED_DURING_CORE')},
  managementFetchImpl:async()=>({ok:true,status:200,text:async()=>JSON.stringify({access_token:'secret-fixture-bearer',scope:REQUIRED_ORG_SCOPES.join(' '),token_type:'Bearer'})}),
 };
 return {env,actions,messages,opts,inventoryPath,credentialsPath};
}

test('core bootstrap needs no sector URLs and never creates customer-facing OIDC applications',async()=>{
 const h=harness();
 await execute('core',h.opts);
 const created=h.actions.filter(a=>['app','user','org'].includes(a.kind));
 assert.equal(created.length,10,'one management client + two workload clients + four users + three orgs');
 assert.equal(created.filter(x=>x.kind==='app').length,3);
 for(const item of created.filter(x=>x.kind==='app')){
  assert.deepEqual(item.object.inboundProtocolConfiguration.oidc.grantTypes,['client_credentials']);
  assert.notEqual(item.object.inboundProtocolConfiguration.oidc.subject?.subjectType,'public');
 }
 assert.equal(created.filter(x=>x.kind==='user').length,4);
 assert.equal(created.filter(x=>x.kind==='org').length,3);
 const inventory=JSON.parse(readFileSync(h.inventoryPath));
 assert.equal(inventory.completion,'CORE_PROVISIONED_PAIRWISE_PENDING');
 assert.ok(inventory.resources.every(x=>!['AURORA_WEB','AURORA_MOBILE','BRISA_WEB','BRISA_MOBILE'].includes(x.key)));
 assert.ok(h.messages.some(x=>x.includes('Four brand OIDC applications NOT CREATED')));
 assert.doesNotMatch(JSON.stringify(inventory),/secret-fixture-bearer|secret-app/);
 const count=h.actions.length;
 await execute('core',h.opts);
 assert.equal(h.actions.length,count,'core re-run must not create duplicate resources');
});

test('pairwise activation after core adds exactly four distinct brand clients and reset removes only owned resources',async()=>{
 const h=harness();
 await execute('core',h.opts);
 Object.assign(h.env,{DEMO_AURORA_SECTOR_BASE_URL:'https://aurora.example.invalid',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa.example.invalid'});
 const docs=documents(deploymentPlan(config(),h.env));
 h.opts.sectorFetchImpl=async url=>({ok:true,text:async()=>JSON.stringify(docs[url.includes('aurora')?'aurora':'brisa'])});
 await execute('apply',h.opts);
 const clientApps=h.actions.filter(a=>a.kind==='app'&&a.object.inboundProtocolConfiguration.oidc.grantTypes.includes('authorization_code'));
 assert.equal(clientApps.length,4);
 assert.deepEqual(new Set(clientApps.map(x=>x.object.inboundProtocolConfiguration.oidc.subject.sectorIdentifierUri)).size,2);
 assert.ok(clientApps.every(a=>a.object.inboundProtocolConfiguration.oidc.subject.subjectType==='pairwise'));
 assert.equal(JSON.parse(readFileSync(h.inventoryPath)).resources.length,14);
 h.env.WSO2_LAB_CONFIRM='DELETE_LAB_OWNED_RESOURCES';
 await execute('reset',h.opts);
 assert.equal(JSON.parse(readFileSync(h.inventoryPath)).resources.length,0);
 assert.equal(h.actions.filter(x=>x.kind.startsWith('delete')).length,14);
});

test('pairwise activation without sector URL fails before creating any resource',async()=>{
 const h=harness();
 await assert.rejects(()=>execute('apply',h.opts),/SECTOR_BASE_URL_REQUIRED/);
 assert.equal(h.actions.length,0);
});

test('core bootstrap still demands explicit operator confirmation and admin credentials',async()=>{
 const h=harness();
 delete h.env.WSO2_LAB_CONFIRM;
 await assert.rejects(()=>execute('core',h.opts),/EXPLICIT_APPLY_ACK_REQUIRED/);
 h.env.WSO2_LAB_CONFIRM='CREATE_SYNTHETIC_RESOURCES';
 delete h.env.WSO2_ADMIN_PASSWORD;
 await assert.rejects(()=>execute('core',h.opts),/ADMIN_CREDENTIALS_REQUIRED/);
});
