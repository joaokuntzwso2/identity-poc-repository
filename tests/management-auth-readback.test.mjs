import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {seedManagement,privateWrite,readPrivate} from '../scripts/wso2/tenant-control-plane.mjs';

const base='https://localhost:9443';
const domains={aurora:'aurora.identity.test',brisa:'brisa.identity.test'};
const scopes=['internal_application_mgt_view','internal_application_mgt_create','internal_application_mgt_client_secret_view'];
const tenantJournal=()=>({tenantProvisioning:'TWO_ROOT_TENANTS_CREATED_OR_VERIFIED',tenants:Object.fromEntries(
  Object.keys(domains).map(brand=>[brand,{owned:true,state:'created',domain:domains[brand],tenantId:'tenant-'+brand,
    ownerId:'owner-'+brand,owner:{username:'labtenantadmin',password:'synthetic-pass-'+brand}}]))});
const apiResource={id:'apiresource-12345',identifier:'/api/server/v1/applications',scopes:scopes.map(name=>({name}))};
const reply=(status,data={})=>({ok:status>=200&&status<300,status,headers:{get:()=>null},
  text:async()=>status===204?'':JSON.stringify(data)});
function fake({authorizationStatus=201, applyAuthorization=true, auroraInitiallyAuthorized=false,
    partiallyAuthorized=false}={}){
  const requests=[];
  const state=Object.fromEntries(Object.keys(domains).map(b=>[b,{
    exists:b==='aurora' && auroraInitiallyAuthorized,authorized:b==='aurora'&&auroraInitiallyAuthorized,
  }]));
  return {requests,state,fetchImpl:async(url,opts)=>{
    const method=opts.method??'GET';
    const brand=url.includes('aurora.identity.test')?'aurora':'brisa';
    const s=state[brand];
    requests.push({method,brand,url});
    const local=url.split(`/t/${domains[brand]}`)[1];
    if(local==='/api/server/v1/applications?limit=1')return reply(200,{applications:[]});
    if(local==='/api/server/v1/api-resources?limit=100')return reply(200,{APIResources:[apiResource]});
    if(local==='/api/server/v1/applications'&&method==='POST'){
      s.exists=true;
      return reply(201,{id:'mgmt-'+brand+'-01'});
    }
    if(local===`/api/server/v1/applications/mgmt-${brand}-01` && method==='GET'){
      if(!s.exists)throw Error('FIXTURE_APP_MISSING_'+brand);
      return reply(200,{name:`Identity Lab ${brand.toUpperCase()} Management Bootstrap`,isManagementApp:true});
    }
    if(local===`/api/server/v1/applications/mgmt-${brand}-01/authorized-apis`){
      if(method==='POST'){
        if(applyAuthorization)s.authorized=true;
        return reply(authorizationStatus);
      }
      if(!s.authorized)return reply(200,[]);
      return reply(200,[{id:apiResource.id,authorizedScopes:(partiallyAuthorized?scopes.slice(0,2):scopes).map(name=>({name}))}]);
    }
    if(local===`/api/server/v1/applications/mgmt-${brand}-01/inbound-protocols/oidc`){
      return reply(200,{clientId:'client-'+brand,clientSecret:'synthetic-secret-'+brand});
    }
    if(local==='/oauth2/token'&&method==='POST')return reply(200,{
      access_token:'fake-bearer-'+brand,token_type:'Bearer',scope:scopes.join(' ')});
    throw Error('UNEXPECTED_FIXTURE_ROUTE_'+method+'_'+url);
  }};
}
const journalPath=()=>join(mkdtempSync(join(tmpdir(),'wso2-v33-auth-')),'management.private.json');
const run=(f,path)=>seedManagement({fetchImpl:f.fetchImpl,base,domains,rootJournal:tenantJournal(),stateFile:path});

for(const code of [200,201,204]){
  test(`HTTP ${code} API authorization accepted only after full tenant scopes GET, repeat has no writes`,async()=>{
    const f=fake({authorizationStatus:code});const path=journalPath();
    await run(f,path);
    const s=readPrivate(path,null);
    assert.equal(s.management.aurora.state,'verified');
    assert.equal(s.management.brisa.state,'verified');
    assert.equal(s.management.aurora.authorizationHttpStatus,code);
    assert.equal(s.management.brisa.authorizationHttpStatus,code);
    const before=f.requests.filter(r=>r.method==='POST'&&r.url.endsWith('/authorized-apis')).length;
    assert.equal(before,2);
    await run(f,path);
    assert.equal(f.requests.filter(r=>r.method==='POST'&&r.url.endsWith('/authorized-apis')).length,before);
  });
}

test('pending authorization-started reconciles from GET without repeating POST',async()=>{
  const f=fake({auroraInitiallyAuthorized:true});const path=journalPath();
  privateWrite(path,{schemaVersion:1,base,management:{aurora:{
    domain:domains.aurora,name:'Identity Lab AURORA Management Bootstrap',
    state:'authorization-started',id:'mgmt-aurora-01',apiResourceId:apiResource.id}}});
  await run(f,path);
  assert.equal(readPrivate(path,null).management.aurora.state,'verified');
  assert.equal(f.requests.filter(r=>r.method==='POST'&&r.brand==='aurora'&&r.url.endsWith('/authorized-apis')).length,0);
  assert.equal(f.requests.filter(r=>r.method==='POST'&&r.brand==='brisa'&&r.url.endsWith('/authorized-apis')).length,1);
});

test('2xx without authorization readback leaves pending journal; rerun makes zero extra POST',async()=>{
  const f=fake({authorizationStatus:200,applyAuthorization:false});const path=journalPath();
  await assert.rejects(run(f,path),/MANAGEMENT_AUTH_NOT_CONFIRMED_aurora_HTTP_200_MANUAL_REVIEW/);
  const current=readPrivate(path,null).management.aurora;
  assert.equal(current.state,'authorization-started');
  assert.equal(current.authorizationHttpStatus,200);
  assert.equal(f.requests.filter(r=>r.method==='POST'&&r.url.endsWith('/authorized-apis')).length,1);
  await assert.rejects(run(f,path),/MANAGEMENT_AUTH_OUTCOME_UNCERTAIN_aurora_READBACK_MISSING/);
  assert.equal(f.requests.filter(r=>r.method==='POST'&&r.url.endsWith('/authorized-apis')).length,1);
});

test('partial authorization readback never qualifies as management authority',async()=>{
  const f=fake({authorizationStatus:204,partiallyAuthorized:true});const path=journalPath();
  await assert.rejects(run(f,path),/MANAGEMENT_AUTH_NOT_CONFIRMED_aurora_HTTP_204_MANUAL_REVIEW/);
  assert.equal(readPrivate(path,null).management.aurora.state,'authorization-started');
  assert.equal(f.requests.filter(r=>r.method==='POST'&&r.url.endsWith('/authorized-apis')).length,1);
});
