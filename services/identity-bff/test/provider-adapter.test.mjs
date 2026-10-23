import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
 MODES,getMode,assertSafeUrl,resolveConfig,safeStatus,createProvider,
 PreviewProviderAdapter,OfflineContractAdapter,Wso2ProviderAdapter
} from '../src/provider/core.mjs';
import {createProviderHttpRoute} from '../src/provider/http-route.mjs';
const env=(extra={})=>({
 IDENTITY_MODE:'live-wso2',WSO2_INTEGRATION_ACK:'yes',
 WSO2_OIDC_ISSUER:'https://identity.example',
 WSO2_OIDC_DISCOVERY_URL:'https://identity.example/.well-known/openid-configuration',
 WSO2_CLIENT_AURORA_WEB_ID:'aw',WSO2_CLIENT_AURORA_MOBILE_ID:'am',
 WSO2_CLIENT_BRISA_WEB_ID:'bw',WSO2_CLIENT_BRISA_MOBILE_ID:'bm',...extra
});
async function withAttestation(callback,update=18){
 const dir=mkdtempSync(join(tmpdir(),'provider-contract-'));
 const file=join(dir,'release.json');writeFileSync(file,JSON.stringify({release:'7.3.0',update}));
 try{return await callback(file)}finally{rmSync(dir,{recursive:true,force:true})}
}
const discovery={issuer:'https://identity.example',authorization_endpoint:'https://identity.example/oauth2/authorize',token_endpoint:'https://identity.example/oauth2/token',jwks_uri:'https://identity.example/oauth2/jwks',response_types_supported:['code'],subject_types_supported:['public','pairwise']};
test('missing mode defaults to story preview; invalid modes are refused',()=>{
 assert.equal(getMode({}),MODES.PREVIEW);
 assert.throws(()=>getMode({IDENTITY_MODE:'anything'}),/INVALID_IDENTITY_MODE/);
});
test('no configured provider is never shown as live verified',()=>{
 const s=safeStatus({});assert.equal(s.mode,MODES.PREVIEW);
 assert.equal(s.identityVerified,false);assert.equal(s.liveAcceptance,'NOT_VERIFIED');
 assert.equal(s.providerConfigured,false);assert.equal(s.oidcClientsConfigured,0);
});
test('only the explicit live adapter can fetch remote discovery',()=>{
 assert.ok(createProvider({}) instanceof PreviewProviderAdapter);
 assert.ok(createProvider({IDENTITY_MODE:MODES.CONTRACT}) instanceof OfflineContractAdapter);
 assert.ok(createProvider(env()) instanceof Wso2ProviderAdapter);
});
test('preview and offline adapter cannot authenticate, mint tokens, exchange or provision',async()=>{
 for(const p of [createProvider({}),createProvider({IDENTITY_MODE:MODES.CONTRACT})]){
  await assert.rejects(()=>p.authenticate(),/REAL_AUTHENTICATION_REQUIRES_IDENTITY_BFF/);
  await assert.rejects(()=>p.exchangeToken(),/REAL_TOKEN_EXCHANGE_REQUIRES_IDENTITY_BFF/);
  await assert.rejects(()=>p.provisionTenant(),/TENANT_PROVISIONING_NOT_IMPLEMENTED/);
  await assert.rejects(()=>p.discover(),/PROVIDER_NOT_CONNECTED/);
 }
});
test('URL security rejects non-TLS remote, credentials, fragments, and arbitrary schemes',()=>{
 for(const target of ['http://login.example','file:///etc/passwd','https://u:p@login.example/','https://login.example/#fragment','https://login.example/?token=x']){
  assert.throws(()=>assertSafeUrl(target));
 }
 assert.equal(assertSafeUrl('https://identity.example').hostname,'identity.example');
 assert.throws(()=>assertSafeUrl('http://127.0.0.1:9443/'));
 assert.doesNotThrow(()=>assertSafeUrl('http://127.0.0.1:9443/',{allowLoopback:true}));
 assert.throws(()=>assertSafeUrl('http://192.168.1.3:9443/',{allowLoopback:true}));
});
test('requires four unique clients, provenance, controlled live opt-in',()=>withAttestation(file=>{
 let cfg=resolveConfig(env({WSO2_BUILD_ATTESTATION_FILE:file}));assert.equal(cfg.configured,true);
 cfg=resolveConfig(env({WSO2_BUILD_ATTESTATION_FILE:file,WSO2_CLIENT_BRISA_MOBILE_ID:'am'}));
 assert.ok(cfg.missing.includes('DUPLICATED_OIDC_CLIENT_IDS'));
 cfg=resolveConfig(env({WSO2_BUILD_ATTESTATION_FILE:file,WSO2_INTEGRATION_ACK:'no'}));
 assert.ok(cfg.missing.includes('WSO2_INTEGRATION_ACK=yes'));
}));
test('attested update levels show prerequisites without live capability proof',()=>withAttestation(file=>{
 const s=safeStatus(env({WSO2_BUILD_ATTESTATION_FILE:file}));
 assert.equal(s.providerConfigured,true);assert.equal(s.liveConnectivity,'NOT_TESTED');
 assert.equal(s.capabilities.find(c=>c.id==='Actor-aware delegation update level').state,'CONFIGURED');
 assert.equal(s.capabilities.find(c=>c.id==='Real OIDC login').state,'PENDING');
 assert.equal(s.identityVerified,false);
},18));
test('read-only discovery validates issuer and endpoints but not login',()=>withAttestation(async file=>{
 const provider=new Wso2ProviderAdapter(resolveConfig(env({WSO2_BUILD_ATTESTATION_FILE:file})));
 const result=await provider.discover({fetchImpl:async (url,opts)=>{
  assert.equal(url,'https://identity.example/.well-known/openid-configuration');
  assert.equal(opts.redirect,'error');return {ok:true,text:async()=>JSON.stringify(discovery)};
 }});
 assert.equal(result.pairwiseAdvertised,true);assert.equal(result.identityVerified,false);
 assert.equal(result.liveAcceptance,'NOT_VERIFIED');
}));
test('discovery rejects issuer substitution and cross-host token endpoints',()=>withAttestation(async file=>{
 const provider=new Wso2ProviderAdapter(resolveConfig(env({WSO2_BUILD_ATTESTATION_FILE:file})));
 for(const altered of [{...discovery,issuer:'https://other.example'},
  {...discovery,token_endpoint:'https://evil.example/oauth2/token'},
  {...discovery,response_types_supported:['implicit']}]){
  await assert.rejects(()=>provider.discover({fetchImpl:async()=>({ok:true,text:async()=>JSON.stringify(altered)})}));
 }
}));
test('discovery fails closed if configured to wrong endpoint origin',()=>withAttestation(async file=>{
 const provider=new Wso2ProviderAdapter(resolveConfig(env({WSO2_BUILD_ATTESTATION_FILE:file,WSO2_OIDC_DISCOVERY_URL:'https://other.example/.well-known/openid-configuration'})));
 await assert.rejects(()=>provider.discover({fetchImpl:async()=>{throw Error('must never fetch')}}),/LIVE_CONFIG_INCOMPLETE/);
}));
test('provider endpoints are GET only, never reveal client IDs or secrets',async()=>{
 const route=createProviderHttpRoute(env({WSO2_BUILD_ATTESTATION_FILE:'/not/a/real/file'}));
 const records=[];const send=(res,status,data)=>records.push({status,data});
 let hit=await route({req:{method:'POST'},res:{},path:'/api/provider/status',send});
 assert.equal(hit,true);assert.equal(records[0].status,405);
 hit=await route({req:{method:'GET'},res:{},path:'/api/provider/status',send});
 assert.equal(hit,true);assert.equal(records[1].status,200);
 assert.equal(JSON.stringify(records[1]).includes('\"aw\"'),false);
 assert.equal(records[1].data.identityVerified,false);
 assert.equal(await route({req:{method:'GET'},res:{},path:'/api/experience/meta',send}),false);
});
