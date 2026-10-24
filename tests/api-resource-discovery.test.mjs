import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {discoverApplicationResource,seedManagement} from '../scripts/wso2/tenant-control-plane.mjs';
const base='https://localhost:9443';
const domains={aurora:'aurora.identity.test',brisa:'brisa.identity.test'};
const required=['internal_application_mgt_view','internal_application_mgt_create','internal_application_mgt_client_secret_view'];
const resource={id:'resource-999',identifier:'/api/server/v1/applications'};
const response=(data,status=200)=>({ok:status>=200&&status<300,status,headers:{get:()=>null},text:async()=>JSON.stringify(data)});
const cred={username:'labtenantadmin@aurora.identity.test',password:'redacted-fixture'};
function capture(fn){const calls=[];return {calls,fetchImpl:async(url,options)=>{calls.push({url,method:options.method});return fn(url,options)}}}
test('falls back to exact identifier filter and fetches scope details without writes',async()=>{
  const f=capture((url)=>{
    if(url.endsWith('?limit=100'))return response({totalResults:204,APIResources:[{id:'other-abc',identifier:'other'}]});
    if(url.includes('filter=identifier+eq+%2Fapi%2Fserver%2Fv1%2Fapplications'))return response({APIResources:[resource]});
    if(url.endsWith('/api-resources/resource-999'))return response({...resource,scopes:required.map(name=>({name}))});
    throw Error('UNEXPECTED_URL_'+url);
  });
  const found=await discoverApplicationResource({fetchImpl:f.fetchImpl,base,domain:domains.aurora,basic:cred});
  assert.equal(found.id,'resource-999');
  assert(f.calls.every(c=>c.method==='GET'));
  assert.equal(f.calls.length,3);
});
test('paginates with a cursor when first page and filter both omit the resource',async()=>{
  const f=capture((url)=>{
    if(url.endsWith('?limit=100'))return response({APIResources:[],links:[{rel:'next',href:'/api/server/v1/api-resources?after=opaque-123'}]});
    if(url.includes('filter=identifier+eq+%2Fapi%2Fserver%2Fv1%2Fapplications'))return response({APIResources:[]});
    if(url.includes('after=opaque-123'))return response({APIResources:[{...resource,scopes:required.map(name=>({name}))}]});
    throw Error('UNEXPECTED_URL_'+url);
  });
  const found=await discoverApplicationResource({fetchImpl:f.fetchImpl,base,domain:domains.aurora,basic:cred});
  assert.equal(found.id,resource.id);
  assert.equal(f.calls.length,3);
  assert(f.calls.every(c=>c.method==='GET'));
});
test('falls back to documented /scopes when list and detail lack scope collection',async()=>{
  const f=capture(url=>{
    if(url.endsWith('?limit=100'))return response({APIResources:[resource]});
    if(url.endsWith('/api-resources/resource-999'))return response(resource);
    if(url.endsWith('/api-resources/resource-999/scopes'))return response(required.map(name=>({name})));
    throw Error('UNEXPECTED_URL_'+url);
  });
  assert.equal((await discoverApplicationResource({fetchImpl:f.fetchImpl,base,domain:domains.aurora,basic:cred})).id,resource.id);
  assert(f.calls.every(c=>c.method==='GET'));
});
test('missing resource in Brisa prevents first M2M application create and journal writes',async()=>{
  const root={tenantProvisioning:'TWO_ROOT_TENANTS_CREATED_OR_VERIFIED',tenants:Object.fromEntries(Object.entries(domains).map(([brand,domain])=>[brand,{
    owned:true,state:'created',domain,tenantId:'tenant-'+brand,ownerId:'owner-'+brand,
    owner:{username:'labtenantadmin',password:'testpass'}
  }]))};
  const f=capture(url=>{
    if(url.includes('/applications?limit=1'))return response({applications:[]});
    if(url.includes('/api-resources?'))return response({APIResources:url.includes('aurora')?[{...resource,scopes:required.map(name=>({name}))}]:[]});
    throw Error('UNEXPECTED_URL_'+url);
  });
  const file=join(mkdtempSync(join(tmpdir(),'resource-no-write-')),'management.json');
  await assert.rejects(seedManagement({fetchImpl:f.fetchImpl,base,domains,rootJournal:root,stateFile:file}),/APPLICATION_API_RESOURCE_NOT_FOUND/);
  assert(f.calls.every(c=>c.method==='GET'));
  assert(!existsSync(file));
});
test('missing required scope refuses resource without application POST',async()=>{
  const f=capture(url=>{
    if(url.endsWith('?limit=100'))return response({APIResources:[resource]});
    if(url.endsWith('/api-resources/resource-999'))return response({...resource,scopes:required.slice(0,2).map(name=>({name}))});
    if(url.endsWith('/api-resources/resource-999/scopes'))return response(required.slice(0,2).map(name=>({name})));
    throw Error('UNEXPECTED_URL_'+url);
  });
  await assert.rejects(discoverApplicationResource({fetchImpl:f.fetchImpl,base,domain:domains.aurora,basic:cred}),/APPLICATION_API_SCOPES_UNAVAILABLE/);
  assert(f.calls.every(c=>c.method==='GET'));
});
test('verified empty response without APIResources is handled without inventing a match',async()=>{
  const f=capture(url=>{
    if(url.includes('/api-resources?'))return response({totalResults:0,links:[]});
    throw Error('UNEXPECTED_URL_'+url);
  });
  await assert.rejects(discoverApplicationResource({fetchImpl:f.fetchImpl,base,domain:domains.aurora,basic:cred}),/APPLICATION_API_RESOURCE_NOT_FOUND/);
  assert.equal(f.calls.length,2);
  assert(f.calls.every(c=>c.method==='GET'));
});
test('duplicate matching resource IDs fail closed',async()=>{
  const f=capture(url=>{
    if(url.endsWith('?limit=100'))return response({APIResources:[resource,{...resource,id:'resource-abc'}]});
    throw Error('UNEXPECTED_URL_'+url);
  });
  await assert.rejects(discoverApplicationResource({fetchImpl:f.fetchImpl,base,domain:domains.aurora,basic:cred}),/APPLICATION_API_RESOURCE_AMBIGUOUS/);
  assert.equal(f.calls.length,1);
});
