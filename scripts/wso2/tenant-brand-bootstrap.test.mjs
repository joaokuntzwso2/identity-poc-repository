import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {bootstrapTenants,tenantStatus,tenantApiPreflight} from './tenant-brand-bootstrap.mjs';
import {config,deploymentPlan} from './domain.mjs';
import {documents} from './sector.mjs';

const env={WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES',WSO2_BASE_URL:'https://localhost:9443',
 WSO2_ADMIN_USER:'admin',WSO2_ADMIN_PASSWORD:'fixture-secret',WSO2_BUILD_ATTESTATION_FILE:join(tmpdir(),'nonexistent-attestation'),
 WSO2_AURORA_ROOT_TENANT:'aurora.identity.test',WSO2_BRISA_ROOT_TENANT:'brisa.identity.test',
 DEMO_AURORA_SECTOR_BASE_URL:'https://aurora-sector.identity.test',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa-sector.identity.test'};
// Reuse the repository's test build attestation from the existing fixture suite.
import {writeFileSync} from 'node:fs';
const dir=mkdtempSync(join(tmpdir(),'tenant-fixture-'));
const build=join(dir,'updated-image.json');
writeFileSync(build,JSON.stringify({release:'7.3.0',update:18,imageDigest:'sha256:'+'a'.repeat(64)}));
env.WSO2_BUILD_ATTESTATION_FILE=build;
function reply(body,status=200,location=null){return {ok:status>=200&&status<300,status,headers:{get:n=>n.toLowerCase()==='location'?location:null},text:async()=>JSON.stringify(body)};}
function fixture(){
 const domains=new Set(),apps=new Map(),calls=[];
 const fetchImpl=async(uri,options={})=>{
  const u=new URL(uri),method=options.method||'GET',path=u.pathname;
  calls.push({method,path,body:options.body?JSON.parse(options.body):undefined,auth:options.headers?.Authorization});
  if(path==='/api/server/v1/tenants'&&method==='GET')return reply({tenants:[...domains].map(domain=>({domain})),totalResults:domains.size});
  if(path==='/api/server/v1/tenants'&&method==='POST'){
   assert.deepEqual(Object.keys(options.body?JSON.parse(options.body):{}).sort(),['domain','name','owners']);
   const body=JSON.parse(options.body);assert.equal(body.owners[0].provisioningMethod,'inline-password');domains.add(body.domain);return reply({},201);
  }
  const match=path.match(/^\/t\/([^/]+)\/api\/server\/v1\/applications(?:\/([^/]+)(?:\/inbound-protocols\/oidc)?)?$/);
  if(match){const domain=decodeURIComponent(match[1]),id=match[2];if(!domains.has(domain))return reply({code:'UNKNOWN_TENANT'},404);
   if(method==='POST'){
    const input=JSON.parse(options.body),appId='lab-app-'+(apps.size+1).toString().padStart(8,'0');
    assert.equal(input.inboundProtocolConfiguration.oidc.subject.subjectType,'pairwise');
    apps.set(appId,{domain,payload:input});return reply({id:appId},201);
   }
   if(method==='GET'&&id){const entry=apps.get(id);if(!entry||entry.domain!==domain)return reply({code:'NOT_FOUND'},404);
    if(path.endsWith('/inbound-protocols/oidc'))return reply({clientId:'client-'+id,clientSecret:'secret-'+id,subject:entry.payload.inboundProtocolConfiguration.oidc.subject});
    return reply({id});}
  }
  throw Error('UNEXPECTED_FETCH_'+method+'_'+path);
 };
 const docs=documents(deploymentPlan(config(),env));
 const sectorFetchImpl=async(uri)=>{const brand=uri.includes('aurora')?'aurora':'brisa';return {ok:true,text:async()=>JSON.stringify(docs[brand])}};
 return {fetchImpl,sectorFetchImpl,calls,apps,domains};
}
function opts(f,overrides={}){return {env:{...env,...overrides},fetchImpl:f.fetchImpl,sectorFetchImpl:f.sectorFetchImpl,
 stateFile:join(mkdtempSync(join(tmpdir(),'tenant-state-')),'state.json'),emit:()=>{}};}
test('creates two actual root tenants and exactly four tenant-scoped pairwise OIDC apps',async()=>{
 const f=fixture(),o=opts(f);const result=await bootstrapTenants(o);
 assert.equal(f.domains.size,2);assert.equal(f.apps.size,4);
 assert.equal(f.calls.filter(x=>x.method==='POST'&&x.path==='/api/server/v1/tenants').length,2);
 assert.equal(f.calls.filter(x=>x.path.startsWith('/t/carbon.super/api/server/v1/tenants')).length,0);
 const createApps=f.calls.filter(x=>x.method==='POST'&&x.path.includes('/api/server/v1/applications'));
 assert.equal(createApps.length,4);
 assert.equal(createApps.filter(x=>x.path.startsWith('/t/aurora.identity.test/')).length,2);
 assert.equal(createApps.filter(x=>x.path.startsWith('/t/brisa.identity.test/')).length,2);
 assert.equal(result.pairwise,'FOUR_BRAND_CLIENTS_CONFIGURED_NOT_TOKEN_VERIFIED');
 assert.equal(result.acceptance,'NOT_VERIFIED');
 const data=JSON.parse(readFileSync(o.stateFile,'utf8'));
 assert.equal(data.tenants.aurora.state,'created');assert.equal(data.tenants.brisa.state,'created');
 assert.equal(tenantStatus({env:o.env,stateFile:o.stateFile}).identityBff,'NOT_INTEGRATED');
 // Retries only read, never duplicate resource writes.
 const before=f.calls.filter(x=>x.method==='POST').length;
 await bootstrapTenants(o);
 assert.equal(f.calls.filter(x=>x.method==='POST').length,before);
});
test('creates real tenant roots even without any HTTPS sector host but cannot claim pairwise clients',async()=>{
 const f=fixture(),o=opts(f,{DEMO_AURORA_SECTOR_BASE_URL:undefined,DEMO_BRISA_SECTOR_BASE_URL:undefined});
 const s=await bootstrapTenants(o);assert.equal(f.domains.size,2);assert.equal(f.apps.size,0);
 assert.equal(s.pairwise,'PENDING_STABLE_HTTPS_SECTOR_HOSTS');
});
test('refuses existing unowned tenant domains before any POST',async()=>{
 const f=fixture();f.domains.add('aurora.identity.test');const o=opts(f);
 await assert.rejects(bootstrapTenants(o),/TENANT_ALREADY_EXISTS_UNOWNED_aurora/);
 assert.equal(f.calls.filter(x=>x.method==='POST').length,0);
});
test('refuses domain changes, even with existing state',async()=>{
 const f=fixture(),o=opts(f);await bootstrapTenants({...o,onlyTenants:true});
 await assert.rejects(bootstrapTenants({...o,env:{...o.env,WSO2_AURORA_ROOT_TENANT:'another.identity.test'}}),/TENANT_STATE_ORIGIN_OR_DOMAIN_CHANGE_REFUSED/);
});
test('explicit operator consent is mandatory for tenant creation',async()=>{
 const f=fixture(),o=opts(f,{WSO2_LAB_CONFIRM:''});
 await assert.rejects(bootstrapTenants(o),/EXPLICIT_APPLY_ACK_REQUIRED/);assert.equal(f.calls.length,0);
});
test('disallows provisioning against nonlocal WSO2',async()=>{
 const f=fixture(),o=opts(f,{WSO2_BASE_URL:'https://identity.example.com'});
 await assert.rejects(bootstrapTenants(o),/TENANT_AUTOCREATE_LOCAL_ONLY/);
});
test('sector URLs must be HTTPS and distinct HOSTS; no public tunnel fallback',async()=>{
 const f=fixture(),o=opts(f,{DEMO_BRISA_SECTOR_BASE_URL:'https://aurora-sector.identity.test'});
 await assert.rejects(bootstrapTenants(o),/SECTOR_HOSTS_MUST_DIFFER/);
 assert.equal(f.apps.size,0);
});
test('tenant-qualified apps reject unexpected application readback',async()=>{
 const f=fixture(),o=opts(f);await bootstrapTenants(o);
 const s=JSON.parse(readFileSync(o.stateFile,'utf8'));
 s.clients.AURORA_WEB.tenant='brisa.identity.test';
 writeFileSync(o.stateFile,JSON.stringify(s));
 await assert.rejects(bootstrapTenants(o),/APP_TENANT_MISMATCH/);
});
test('prepared tenant journal retries only its own tenant, never adopts unrelated domain',async()=>{
 const f=fixture(),o=opts(f);await bootstrapTenants({...o,onlyTenants:true});
 // Existing owned, verified tenants are safe to reconcile.
 assert.equal((await bootstrapTenants({...o,onlyTenants:true})).tenantProvisioning,'TWO_ROOT_TENANTS_CREATED_OR_VERIFIED');
 assert.equal(f.calls.filter(x=>x.method==='POST').length,2);
});

test('tenant API preflight uses canonical URL and GET only (no consent or writes)',async()=>{
 const f=fixture(),o=opts(f);
 const result=await tenantApiPreflight({env:{...o.env,WSO2_LAB_CONFIRM:''},fetchImpl:f.fetchImpl});
 assert.equal(result.tenantApiRoute,'/api/server/v1/tenants');
 assert.equal(result.authentication,'VERIFIED_READ_ONLY');
 assert.equal(result.tenantCount,0);assert.equal(result.tenantWrites,0);
 assert.deepEqual(f.calls.map(c=>c.method),['GET']);
 assert.equal(existsSync(o.stateFile),false);
});
test('tenant API 401 stops preflight before writes and discloses no credentials',async()=>{
 const calls=[];
 const denied=async(uri,o)=>{calls.push({path:new URL(uri).pathname,method:o?.method||'GET'});return reply({code:'UNAUTHORIZED'},401)};
 await assert.rejects(tenantApiPreflight({env,fetchImpl:denied}),e=>{
  assert.equal(e.status,401);assert.ok(!e.message.includes(env.WSO2_ADMIN_PASSWORD));return true;
 });
 assert.deepEqual(calls,[{path:'/api/server/v1/tenants',method:'GET'}]);
});
