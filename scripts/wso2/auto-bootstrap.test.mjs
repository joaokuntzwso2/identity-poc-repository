import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execute} from './cli.mjs';
import {deploymentPlan,config} from './domain.mjs';
import {documents} from './sector.mjs';
import {REQUIRED_ORG_SCOPES,requestOrgManagementToken,findOrgResource} from './management-token.mjs';

const ORG_RESOURCE={id:'root-org-resource-98765',identifier:'/api/server/v1/organizations',scopes:REQUIRED_ORG_SCOPES.map(name=>({name}))};
test('API identifier match is exact, not arbitrary management resource',()=>{
 assert.equal(findOrgResource({APIResources:[ORG_RESOURCE]}).id,ORG_RESOURCE.id);
 assert.throws(()=>findOrgResource({apiResources:[{id:'wrong',identifier:'/o/api/server/v1/organizations'}]}),/NOT_UNIQUELY_FOUND/);
});
test('real Client Credentials token request uses documented form and never discloses secrets',async()=>{
 let observed;
 const token=await requestOrgManagementToken({base:'https://localhost:9443',clientId:'lab-id',clientSecret:'secret',fetchImpl:async(url,opt)=>{
  observed={url,opt};return {ok:true,status:200,text:async()=>JSON.stringify({access_token:'sensitive-token',token_type:'Bearer',scope:REQUIRED_ORG_SCOPES.join(' ')})};
 }});
 assert.equal(token,'sensitive-token');
 assert.equal(new URL(observed.url).pathname,'/oauth2/token');
 assert.match(observed.opt.headers.Authorization,/^Basic /);
 assert.equal(new URLSearchParams(observed.opt.body).get('grant_type'),'client_credentials');
 assert.equal(observed.opt.redirect,'error');
});
test('invalid_client and scope shortage fail closed',async()=>{
 for(const [status,body,pattern] of [
  [401,{error:'invalid_client'},/ORG_TOKEN_REQUEST_401_invalid_client/],
  [200,{access_token:'opaque',scope:'internal_organization_view'},/SCOPES_NOT_GRANTED/]
 ]){
  await assert.rejects(()=>requestOrgManagementToken({base:'https://localhost:9443',clientId:'id',clientSecret:'secret',fetchImpl:async()=>({ok:status===200,status,text:async()=>JSON.stringify(body)})}),pattern);
 }
});
test('fully automatic bootstrap is idempotent, uses real scoped bearer and reset owns client',async()=>{
 const tmp=mkdtempSync(join(tmpdir(),'wso2-auto-bootstrap-'));
 const attest=join(tmp,'attest.json'),inventoryPath=join(tmp,'inventory.json'),credentialsPath=join(tmp,'credentials.json');
 writeFileSync(attest,JSON.stringify({release:'7.3.0',update:18,imageDigest:'sha256:'+'a'.repeat(64)}));
 const env={WSO2_BASE_URL:'https://localhost:9443',WSO2_ADMIN_USER:'admin',WSO2_ADMIN_PASSWORD:'fixture-password',WSO2_BUILD_ATTESTATION_FILE:attest,
  DEMO_PUBLIC_BASE_URL:'https://demo.example.invalid',DEMO_AURORA_SECTOR_BASE_URL:'https://aurora-sectors.example.invalid',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa-sectors.example.invalid',WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES'};
 const plan=deploymentPlan(config(),env),sectorDocs=documents(plan),deleted=[],created=[];
 let next=0,auth=[];
 const f={hashOrigin:()=> 'fixture-origin',
  createApp:async x=>{let id=`app-${++next}abc123`;created.push(['application',x.name]);return {data:{id}}},
  getApp:async id=>({data:{id}}),
  getOidc:async id=>({data:{clientId:`client-${id}`,clientSecret:`private-${id}`}}),
  getUser:async id=>({data:{id}}),getOrg:async id=>({data:{id}}),
  createUser:async x=>{let id=`usr-${++next}abc123`;created.push(['user',x.userName]);return {data:{id}}},
  createOrg:async x=>{let id=`org-${++next}abc123`;created.push(['org',x.name]);return {data:{id}}},
  deleteApp:async id=>deleted.push(['application',id]),deleteUser:async id=>deleted.push(['user',id]),deleteOrg:async id=>deleted.push(['org',id]),
  listApiResources:async()=>({data:{APIResources:[ORG_RESOURCE]}}),
  getAuthorizedApis:async()=>({data:{authorizedAPIs:auth}}),
  authorizeApi:async(id,body)=>{auth.push(body);return {status:201,data:{}}}
 };
 let tokenCalls=0;
 const opts={env,client:f,inventoryPath,credentialsPath,emit:()=>{},
  sectorFetchImpl:async url=>({ok:true,text:async()=>JSON.stringify(sectorDocs[url.includes('aurora')?'aurora':'brisa'])}),
  managementFetchImpl:async(url,opt)=>{tokenCalls++;assert.equal(new URL(url).pathname,'/oauth2/token');return {ok:true,status:200,text:async()=>JSON.stringify({access_token:'fixture-scoped-token',scope:REQUIRED_ORG_SCOPES.join(' '),token_type:'Bearer'})};}
 };
 await execute('apply',opts);
 assert.equal(created.length,14,'six clients, four users, three organizations, one management app');
 assert.equal(auth.length,1);assert.deepEqual(auth[0].scopes,REQUIRED_ORG_SCOPES);
 const inventory=JSON.parse(readFileSync(inventoryPath));assert.equal(inventory.resources[0].key,'bootstrap-org-management');
 const credentials=JSON.parse(readFileSync(credentialsPath));assert.ok(credentials.management.clientSecret);
 assert.doesNotMatch(JSON.stringify(inventory),/fixture-scoped-token|private-app/);
 await execute('apply',opts);assert.equal(created.length,14,'repeat must never recreate owned objects');assert.equal(auth.length,1);
 env.WSO2_LAB_CONFIRM='DELETE_LAB_OWNED_RESOURCES';await execute('reset',opts);
 assert.equal(deleted.length,14);assert.equal(deleted.at(-1)[0],'application','management app removed last');
 assert.equal(JSON.parse(readFileSync(inventoryPath)).resources.length,0);
 assert.equal(JSON.parse(readFileSync(credentialsPath)).management,undefined);
 assert.equal(tokenCalls,3,'each command uses a new short lived token');
});
