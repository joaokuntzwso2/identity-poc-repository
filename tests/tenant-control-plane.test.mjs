import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  assertLab,ownerCredential,adminPreflight,requestTenantToken,
  seedManagement,readPrivate,publicControlPlane
} from '../scripts/wso2/tenant-control-plane.mjs';
import {assertPlan,provisionBrandClients,exportBffContracts} from '../scripts/wso2/tenant-brand-clients.mjs';
const base='https://localhost:9443';
const domains={aurora:'aurora.identity.test',brisa:'brisa.identity.test'};
const needed=['internal_application_mgt_view','internal_application_mgt_create','internal_application_mgt_client_secret_view'];
const root=()=>({tenantProvisioning:'TWO_ROOT_TENANTS_CREATED_OR_VERIFIED',
  tenants:Object.fromEntries(['aurora','brisa'].map(b=>[b,{state:'created',owned:true,domain:domains[b],
    tenantId:'tenant-'+b,ownerId:'owner-'+b,owner:{username:'labtenantadmin',password:'private-'+b}}])),clients:{}});
const response=(status,data={},location=null)=>({ok:status>=200&&status<300,status,headers:{get:n=>n==='location'?location:null},text:async()=>JSON.stringify(data)});
const decodeAuth=options=>Buffer.from((options.headers.Authorization||'').split(' ')[1]||'','base64').toString();
function fakeServer({failAurora=false, uncertain=false}={}){
  const requests=[], db={aurora:{},brisa:{}};
  const fetchImpl=async(url,opt)=>{
    const method=opt.method||'GET';requests.push({url,method,authType:opt.headers.Authorization.split(' ')[0]});
    const brand=url.includes('aurora.identity.test')?'aurora':'brisa';
    const state=db[brand], suffix=url.split('/api/server/v1/')[1]||'';
    if(suffix==='applications?limit=1'){
      if(failAurora&&brand==='aurora'&&opt.headers.Authorization.startsWith('Basic'))return response(401,{message:'denied'});
      return response(200,{applications:[]});
    }
    if(suffix==='applications'&&method==='POST'){
      if(uncertain)throw Error('simulated disconnect');
      state.name=JSON.parse(opt.body).name;
      return response(201,{id:'app-'+brand+'-001'});
    }
    if(suffix===`applications/app-${brand}-001`)return response(200,{name:state.name,isManagementApp:true});
    if(suffix==='api-resources?limit=100')return response(200,{APIResources:[{id:'resource-123',identifier:'/api/server/v1/applications',
      scopes:needed.map(name=>({name}))}]});
    if(suffix===`applications/app-${brand}-001/authorized-apis`){
      if(method==='POST'){state.authorized=true;return response(201,{});}
      return response(200,state.authorized?[{id:'resource-123',authorizedScopes:needed.map(name=>({name}))}]:[]);
    }
    if(suffix===`applications/app-${brand}-001/inbound-protocols/oidc`)
      return response(200,{clientId:'m2m-'+brand,clientSecret:'private-secret-'+brand});
    if(url.endsWith('/oauth2/token')&&method==='POST')return response(200,{access_token:'jwt-'+brand,scope:needed.join(' '),token_type:'Bearer'});
    throw Error('UNEXPECTED_FIXTURE_ROUTE_'+method+'_'+url);
  };
  return {fetchImpl,requests,db};
}

test('local-only consent and strict URL',()=>{
  assert.throws(()=>assertLab({WSO2_BASE_URL:'https://evil.example:9443',WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES'}),/LOCALHOST/);
  assert.throws(()=>assertLab({WSO2_BASE_URL:base}),/CONSENT/);
  assert.equal(assertLab({WSO2_BASE_URL:base,WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES'}).domains.brisa,domains.brisa);
});
test('pending Aurora recovery candidate is used, original not substituted',()=>{
  const r=root();r.tenants.aurora.ownerRecovery={state:'update-started',tenantId:'tenant-aurora',ownerId:'owner-aurora',candidatePassword:'candidate'};
  assert.equal(ownerCredential(r.tenants.aurora,'aurora',domains.aurora).password,'candidate');
  r.tenants.aurora.ownerRecovery.ownerId='another-owner';
  assert.throws(()=>ownerCredential(r.tenants.aurora,'aurora',domains.aurora),/RECOVERY_STATE/);
});
test('unauthorized Aurora preflight means no writes to either tenant',async()=>{
  const f=fakeServer({failAurora:true});
  const path=join(mkdtempSync(join(tmpdir(),'lab-auth-test-')),'management.json');
  await assert.rejects(seedManagement({fetchImpl:f.fetchImpl,base,domains,rootJournal:root(),stateFile:path}),/UNAVAILABLE_aurora/);
  assert(f.requests.every(x=>x.method==='GET'));
});
test('one-time management app creation, authorization, Bearer proof and idempotent rerun',async()=>{
  const f=fakeServer();
  const path=join(mkdtempSync(join(tmpdir(),'lab-m2m-test-')),'management.json');
  await seedManagement({fetchImpl:f.fetchImpl,base,domains,rootJournal:root(),stateFile:path});
  assert.equal(f.requests.filter(x=>x.url.endsWith('/applications')&&x.method==='POST').length,2);
  assert.equal(f.requests.filter(x=>x.url.endsWith('/authorized-apis')&&x.method==='POST').length,2);
  assert.equal(readPrivate(path,null).management.brisa.state,'verified');
  await seedManagement({fetchImpl:f.fetchImpl,base,domains,rootJournal:root(),stateFile:path});
  assert.equal(f.requests.filter(x=>x.url.endsWith('/applications')&&x.method==='POST').length,2);
});
test('unknown create outcome is recorded before POST, never retried',async()=>{
  const f=fakeServer({uncertain:true});
  const path=join(mkdtempSync(join(tmpdir(),'lab-uncertain-test-')),'management.json');
  await assert.rejects(seedManagement({fetchImpl:f.fetchImpl,base,domains,rootJournal:root(),stateFile:path}),/disconnect/);
  assert.equal(readPrivate(path,null).management.aurora.state,'create-started');
  await assert.rejects(seedManagement({fetchImpl:f.fetchImpl,base,domains,rootJournal:root(),stateFile:path}),/UNCERTAIN/);
  assert.equal(f.requests.filter(x=>x.url.endsWith('/applications')&&x.method==='POST').length,1);
});
test('token lacking requested scope never verifies tenant API access',async()=>{
  const fetchImpl=async()=>response(200,{access_token:'secret',scope:needed.slice(0,2).join(' '),token_type:'Bearer'});
  await assert.rejects(requestTenantToken({fetchImpl,base,domain:domains.brisa,clientId:'client',clientSecret:'secret'}),/NOT_GRANTED/);
});
test('manifests exclude all private secrets and never claim interactive SSO',()=>{
  const r=root();r.clients['aurora-web']={tenant:domains.aurora,state:'verified',id:'app-11111',clientId:'public-client',clientSecret:'do-not-expose'};
  const state={management:{aurora:{state:'verified'},brisa:{state:'verified',clientSecret:'private'}}};
  const manifest=publicControlPlane({base,domains,rootJournal:r,managementJournal:state,clients:r.clients});
  assert.equal(manifest.brands.aurora.ssoVerified,false);
  assert.equal(manifest.brands.aurora.pairwiseTokenVerified,false);
  assert(!JSON.stringify(manifest).includes('do-not-expose'));
});
test('four OIDC clients, two per brand, are required before any writes',()=>{
  assert.throws(()=>assertPlan({apps:[]},domains,{aurora:'https://a.test/s',brisa:'https://b.test/s'}),/FOUR_DISTINCT/);
});
test('UI exporter refuses to claim live linkage for unverified clients',()=>{
  const d=mkdtempSync(join(tmpdir(),'lab-export-test-'));
  assert.throws(()=>exportBffContracts({base,domains,rootJournal:root(),managementJournal:{management:{brisa:{state:'verified'},aurora:{state:'verified'}}},
    privateOutput:join(d,'var/wso2/private.json'),publicOutput:join(d,'var/wso2/public.json')}),/UI_BFF_BRAND_NOT_READY/);
});

test('brand client stage creates four OIDC applications and never duplicates on rerun',async()=>{
  const temp=mkdtempSync(join(tmpdir(),'lab-four-clients-'));
  const path=join(temp,'tenant-brand.private.json');
  const {privateWrite}=await import('../scripts/wso2/tenant-control-plane.mjs');
  const initial=root();privateWrite(path,initial);
  const apps=['aurora-web','aurora-mobile','brisa-web','brisa-mobile'].map(key=>({
    key,brand:key.split('-')[0],name:'Identity Lab '+key,
    callback:'https://'+key+'.example.test/callback',accessUrl:'https://'+key+'.example.test/'
  }));
  const sectors={aurora:'https://aurora.example.test/sector.json',brisa:'https://brisa.example.test/sector.json'};
  const seen={}, writes=[];
  const fetchImpl=async(url,opt)=>{
    const method=opt.method||'GET',brand=url.includes('aurora.identity.test')?'aurora':'brisa';
    if(url.endsWith('/applications?limit=1'))return response(200,{});
    if(url.endsWith('/applications')&&method==='POST'){
      const p=JSON.parse(opt.body);
      writes.push(p.name);const id='oidc-'+String(writes.length).padStart(5,'0');
      seen[id]={payload:p,brand};return response(201,{id});
    }
    const m=url.match(/\/applications\/(oidc-\d{5})(\/inbound-protocols\/oidc)?$/);
    if(m){const p=seen[m[1]]?.payload;if(!p)throw Error('unexpected read');
      if(m[2])return response(200,{clientId:'cid-'+m[1],clientSecret:'private-'+m[1],
        ...p.inboundProtocolConfiguration.oidc});
      return response(200,{name:p.name,isManagementApp:false});
    }
    throw Error('unexpected '+method+' '+url);
  };
  await provisionBrandClients({fetchImpl,base,domains,bearerTokens:{aurora:'tok-a',brisa:'tok-b'},
    rootStateFile:path,plan:{apps},sectorUrls:sectors});
  assert.equal(writes.length,4);
  const final=readPrivate(path,null);
  assert.equal(Object.values(final.clients).filter(v=>v.state==='verified').length,4);
  await provisionBrandClients({fetchImpl,base,domains,bearerTokens:{aurora:'tok-a',brisa:'tok-b'},
    rootStateFile:path,plan:{apps},sectorUrls:sectors});
  assert.equal(writes.length,4);
  const m={management:{aurora:{state:'verified'},brisa:{state:'verified'}}};
  const publicPath=join(temp,'var/wso2/public.private.json');
  const privatePath=join(temp,'var/wso2/bff.private.json');
  const status=exportBffContracts({base,domains,rootJournal:readPrivate(path,null),managementJournal:m,
    privateOutput:privatePath,publicOutput:publicPath});
  assert.equal(status.brands.aurora.oidcClients.length,2);
  assert(!readFileSync(publicPath,'utf8').includes('private-oidc-'));
  assert(readFileSync(privatePath,'utf8').includes('private-oidc-'));
  assert.equal(status.brands.aurora.ssoVerified,false);
});
