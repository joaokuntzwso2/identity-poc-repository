import test from 'node:test';
import assert from 'node:assert/strict';
import {sectorUris,assertSectorDocuments,documents} from './sector.mjs';
import {extractTunnelHost,makeSectorHandler,describeNetworkError,waitForSectorPublication} from './local-sector-tunnels.mjs';
import {deploymentPlan,config} from './domain.mjs';
const env={DEMO_PUBLIC_BASE_URL:'http://127.0.0.1:5173',DEMO_BFF_BASE_URL:'http://127.0.0.1:4000',DEMO_AURORA_SECTOR_BASE_URL:'https://aurora-sectors.example.invalid',DEMO_BRISA_SECTOR_BASE_URL:'https://brisa-sectors.example.invalid'};
test('two distinct, stable pairwise HOSTS for two brands; web and mobile share within one brand',()=>{
 const urls=sectorUris(env);
 assert.equal(new URL(urls.aurora).hostname,'aurora-sectors.example.invalid');
 assert.equal(new URL(urls.brisa).hostname,'brisa-sectors.example.invalid');
 assert.notEqual(new URL(urls.aurora).hostname,new URL(urls.brisa).hostname);
 const docs=documents(deploymentPlan(config(),env));assert.equal(docs.aurora.length,2);assert.equal(docs.brisa.length,2);
});
test('rejects single HTTPS hostname even with different paths: OIDC Core §8.1',()=>{
 assert.throws(()=>sectorUris({...env,DEMO_BRISA_SECTOR_BASE_URL:'https://aurora-sectors.example.invalid'}),/HOSTS_MUST_DIFFER/);
 assert.throws(()=>sectorUris({...env,DEMO_BRISA_SECTOR_BASE_URL:'https://aurora-sectors.example.invalid/other/'}),/INVALID_HTTPS_BASE/);
});
test('rejects HTTP, loopback and missing sector hostnames',()=>{
 assert.throws(()=>sectorUris({...env,DEMO_AURORA_SECTOR_BASE_URL:'http://aurora.example.invalid'}),/INVALID_HTTPS_BASE/);
 assert.throws(()=>sectorUris({...env,DEMO_AURORA_SECTOR_BASE_URL:'https://localhost'}),/PUBLICLY_REACHABLE/);
 assert.throws(()=>sectorUris({DEMO_SECTOR_BASE_URL:'https://one.example.invalid'}),/DEMO_AURORA_SECTOR_BASE_URL_REQUIRED/);
});
test('actual sector retrieval rejects mismatched redirect callback lists',async()=>{
 const p=deploymentPlan(config(),env),docs=documents(p);
 const good=async url=>({ok:true,text:async()=>JSON.stringify(docs[url.includes('aurora')?'aurora':'brisa'])});
 assert.equal(await assertSectorDocuments(p,env,good),true);
 await assert.rejects(()=>assertSectorDocuments(p,env,async()=>({ok:true,text:async()=>JSON.stringify(['https://malicious.example/callback'])})),/REDIRECT_MISMATCH/);
});
test('quick tunnel parser never accepts arbitrary URL',()=>{
 assert.equal(extractTunnelHost('2026 INFO https://quiet-marble-otter.trycloudflare.com ready'),'https://quiet-marble-otter.trycloudflare.com');
 assert.equal(extractTunnelHost('https://malicious.example https://localhost:8787'),null);
});
test('temporary HTTP origin exposes only the requested sector JSON route',async()=>{
 const handler=makeSectorHandler('aurora',['http://127.0.0.1:4000/auth/aurora-web/callback']);
 const makeRes=()=>({status:0,headers:{},data:'',writeHead(s,h){this.status=s;this.headers=h},end(d=''){this.data=d||''}});
 const ok=makeRes();handler({method:'GET',url:'/sectors/aurora.json'},ok);
 assert.equal(ok.status,200);assert.deepEqual(JSON.parse(ok.data),['http://127.0.0.1:4000/auth/aurora-web/callback']);
 const denied=makeRes();handler({method:'GET',url:'/var/wso2/lab.env'},denied);assert.equal(denied.status,404);
});

test('does not mistake Cloudflare registration API for a public Quick Tunnel host',()=>{
 const api='Post "https://api.trycloudflare.com/tunnel": dial tcp: connection refused';
 assert.equal(extractTunnelHost(api),null);
 assert.equal(extractTunnelHost(api+'\n2026 INFO https://quiet-marble-otter.trycloudflare.com ready'), 'https://quiet-marble-otter.trycloudflare.com');
});
test('readiness retries transient publication failures, without claiming a live resource',async()=>{
 let tries=0,retries=[];
 const fakeChecker=async()=>{tries++;if(tries<3)throw Object.assign(new Error('fetch failed'),{cause:Object.assign(new Error('lookup failed'),{code:'ENOTFOUND'})});return true;};
 assert.equal(await waitForSectorPublication({},env,{checker:fakeChecker,attempts:4,sleep:async()=>{},onRetry:(...a)=>retries.push(a)}),true);
 assert.equal(tries,3);assert.equal(retries.length,2);assert.match(retries[0][2],/ENOTFOUND/);
});
test('exhausted public HTTPS validation fails closed with underlying error reason',async()=>{
 const cause=Object.assign(new Error('dns resolution failed'),{code:'ENOTFOUND'});
 await assert.rejects(()=>waitForSectorPublication({},env,{checker:async()=>{throw Object.assign(new Error('fetch failed'),{cause})},attempts:2,sleep:async()=>{}}),/SECTOR_PUBLICATION_NOT_READY.*ENOTFOUND/);
 assert.match(describeNetworkError(Object.assign(new Error('fetch failed'),{cause})),/ENOTFOUND/);
});
test('refuses a dead tunnel before treating DNS check as success',async()=>{
 await assert.rejects(()=>waitForSectorPublication({},env,{checker:async()=>true,tunnels:[{brand:'aurora',child:{exitCode:1,signalCode:null},diagnostics:()=> 'edge connection failed'}]}),/TUNNEL_EXITED_aurora/);
});
