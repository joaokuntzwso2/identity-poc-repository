/**
 * Identity provider boundary. Never treats preview fixtures as authenticated users.
 * No local JWT issuance, no fake login, and no browser-provided provider URLs.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

export const MODES=Object.freeze({PREVIEW:'story-preview',CONTRACT:'offline-contract',LIVE:'live-wso2'});
export const ACCEPTANCE='NOT_VERIFIED';
const CLIENTS=['AURORA_WEB','AURORA_MOBILE','BRISA_WEB','BRISA_MOBILE'];
const clean=s=>typeof s==='string'?s.trim():'';
const bool=s=>s==='yes'||s==='true';
function failure(message){const error=new Error(message);error.code=message;error.status=503;return error;}
export function assertSafeUrl(raw,{allowLoopback=false}={}){
  if(!raw||typeof raw!=='string')throw failure('PROVIDER_URL_MISSING');
  let url;try{url=new URL(raw)}catch{throw failure('PROVIDER_URL_INVALID')}
  if(url.username||url.password||url.hash||url.search)throw failure('PROVIDER_URL_REJECTED');
  const loopback=(url.hostname==='localhost'||url.hostname==='127.0.0.1'||url.hostname==='[::1]');
  if(url.protocol!=='https:'&&!(allowLoopback&&loopback&&url.protocol==='http:'))throw failure('PROVIDER_HTTPS_REQUIRED');
  if(!['https:','http:'].includes(url.protocol))throw failure('PROVIDER_SCHEME_REJECTED');
  return url;
}
export function getMode(env=process.env){
 const value=clean(env.IDENTITY_MODE)||MODES.PREVIEW;
 if(!Object.values(MODES).includes(value))throw failure('INVALID_IDENTITY_MODE');
 return value;
}
function buildAttestation(env){
 const file=clean(env.WSO2_BUILD_ATTESTATION_FILE);
 if(!file)return {supplied:false,checked:false,release:null,update:null};
 try{
  const stat=JSON.parse(readFileSync(file,'utf8'));
  const release=clean(stat.release),update=Number(stat.update);
  const valid=release==='7.3.0'&&Number.isSafeInteger(update)&&update>=0;
  return {supplied:true,checked:valid,release:valid?release:null,update:valid?update:null};
 }catch{return {supplied:true,checked:false,release:null,update:null}}
}
export function resolveConfig(env=process.env){
 const mode=getMode(env);
 const issuer=clean(env.WSO2_OIDC_ISSUER),discoveryUrl=clean(env.WSO2_OIDC_DISCOVERY_URL);
 const allowLoopback=bool(env.WSO2_DEV_ALLOW_LOCAL_HTTP);
 const clients=Object.fromEntries(CLIENTS.map(id=>[id,clean(env[`WSO2_CLIENT_${id}_ID`])]));
 const missing=[];
 if(!issuer)missing.push('WSO2_OIDC_ISSUER');
 if(!discoveryUrl)missing.push('WSO2_OIDC_DISCOVERY_URL');
 for(const id of CLIENTS)if(!clients[id])missing.push(`WSO2_CLIENT_${id}_ID`);
 if(!clean(env.WSO2_BUILD_ATTESTATION_FILE))missing.push('WSO2_BUILD_ATTESTATION_FILE');
 if(mode===MODES.LIVE&&!bool(env.WSO2_INTEGRATION_ACK))missing.push('WSO2_INTEGRATION_ACK=yes');
 let urlsValid=false,originMatched=false;
 try{
  const a=assertSafeUrl(issuer,{allowLoopback});
  const b=assertSafeUrl(discoveryUrl,{allowLoopback});
  urlsValid=true;originMatched=a.origin===b.origin;
  if(!originMatched)missing.push('ISSUER_DISCOVERY_ORIGIN_MISMATCH');
 }catch{if(issuer&&discoveryUrl)missing.push('PROVIDER_URL_POLICY_FAILED')}
 const attestation=buildAttestation(env);
 if(attestation.supplied&&!attestation.checked)missing.push('BUILD_ATTESTATION_INVALID');
 if(!attestation.supplied){} // listed above
 const vals=Object.values(clients).filter(Boolean);
 if(new Set(vals).size!==vals.length)missing.push('DUPLICATED_OIDC_CLIENT_IDS');
 return {mode,issuer,discoveryUrl,allowLoopback,clients,attestation,missing,urlsValid,originMatched,
   configured:missing.length===0,acknowledged:bool(env.WSO2_INTEGRATION_ACK)};
}
export function safeStatus(env=process.env){
 const c=resolveConfig(env);
 const configuredClientCount=Object.values(c.clients).filter(Boolean).length;
 const next=(key,ready,detail)=>({id:key,state:ready?'CONFIGURED':'PENDING',detail});
 return {
  schema:'identity.provider.status.v1',mode:c.mode,modeLabel:({[MODES.PREVIEW]:'Story Preview',[MODES.CONTRACT]:'Offline Contract Tests',[MODES.LIVE]:'Live WSO2 (integration pending)'})[c.mode],
  identityProvider:'WSO2 Identity Server 7.3',providerConfigured:c.configured,
  liveConnectivity:'NOT_TESTED',identityVerified:false,liveAcceptance:ACCEPTANCE,
  evidenceStatus:'NO_LIVE_EVIDENCE',oidcClientsConfigured:configuredClientCount,oidcClientsExpected:4,
  configuredBuild:c.attestation.checked?`7.3.0 update ${c.attestation.update}`:'NOT_ATTESTED',
  capabilities:[
   next('OIDC configuration',Boolean(c.issuer&&c.discoveryUrl&&c.urlsValid&&c.originMatched),'Discovery and issuer pinning required'),
   next('Independent OIDC clients',configuredClientCount===4&&new Set(Object.values(c.clients)).size===4,'Four distinct applications; sector grouping not verified'),
   next('WSO2 build provenance',c.attestation.checked,'Independent release/update attestation, not runtime proof'),
   next('Consent v2 update level',c.attestation.checked&&c.attestation.update>=12,'Requires a compatible installed update and real integration'),
   next('Actor-aware delegation update level',c.attestation.checked&&c.attestation.update>=18,'Requires compatible update and live RFC 8693 proof'),
   next('Real OIDC login',false,'Must use established identity BFF authorization-code/PKCE flow'),
   next('Live pairwise/SSO/claims',false,'Cannot be proved without signed tokens'),
  ],
  missingConfiguration:c.missing,
  message:c.mode===MODES.PREVIEW?'Synthetic preview only. No WSO2 user authentication is performed.':
   c.mode===MODES.CONTRACT?'Offline fixtures are not real issuer evidence.':
    'Configuration alone does not verify WSO2 or authorize real identity operations.'
 };
}
export class IdentityProviderPort{
 constructor(config=resolveConfig()){this.config=config}
 async discover(){throw failure('PROVIDER_NOT_CONNECTED')}
 async authenticate(){throw failure('REAL_AUTHENTICATION_REQUIRES_IDENTITY_BFF')}
 async exchangeToken(){throw failure('REAL_TOKEN_EXCHANGE_REQUIRES_IDENTITY_BFF')}
 async provisionTenant(){throw failure('TENANT_PROVISIONING_NOT_IMPLEMENTED')}
}
export class PreviewProviderAdapter extends IdentityProviderPort{}
export class OfflineContractAdapter extends IdentityProviderPort{}
export class Wso2ProviderAdapter extends IdentityProviderPort{
 async discover({fetchImpl=fetch,timeoutMs=4500}={}){
  const c=this.config;
  if(!c.configured||c.mode!==MODES.LIVE)throw failure('LIVE_CONFIG_INCOMPLETE');
  assertSafeUrl(c.issuer,{allowLoopback:c.allowLoopback});
  const discovery=assertSafeUrl(c.discoveryUrl,{allowLoopback:c.allowLoopback});
  if(discovery.origin!==new URL(c.issuer).origin)throw failure('DISCOVERY_ORIGIN_MISMATCH');
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),Math.min(Math.max(100,timeoutMs),8000));
  try{
   const response=await fetchImpl(discovery.href,{signal:controller.signal,redirect:'error',headers:{Accept:'application/json'},credentials:'omit'});
   if(!response.ok)throw failure('DISCOVERY_HTTP_ERROR');
   const text=await response.text();if(text.length>262144)throw failure('DISCOVERY_TOO_LARGE');
   let d;try{d=JSON.parse(text)}catch{throw failure('DISCOVERY_INVALID_JSON')}
   if(d.issuer!==c.issuer)throw failure('DISCOVERY_ISSUER_MISMATCH');
   for(const name of ['authorization_endpoint','token_endpoint','jwks_uri']){
    const uri=assertSafeUrl(d[name],{allowLoopback:c.allowLoopback});
    if(uri.origin!==discovery.origin)throw failure('DISCOVERY_ENDPOINT_UNTRUSTED');
   }
   if(!Array.isArray(d.response_types_supported)||!d.response_types_supported.includes('code'))throw failure('AUTHORIZATION_CODE_NOT_ADVERTISED');
   return {issuerVerified:true,configurationFetched:true,authorizeEndpointVerified:true,
    tokenEndpointVerified:true,jwksEndpointVerified:true,
    advertisedSubjectTypes:Array.isArray(d.subject_types_supported)?d.subject_types_supported:[],
    pairwiseAdvertised:Array.isArray(d.subject_types_supported)&&d.subject_types_supported.includes('pairwise'),
    // A discovery response is NOT a signed-token, MFA, token-exchange, or SLA acceptance test.
    liveAcceptance:ACCEPTANCE,identityVerified:false,checkedAt:new Date().toISOString()};
  }finally{clearTimeout(timeout)}
 }
}
export function createProvider(env=process.env){
 const config=resolveConfig(env);
 return config.mode===MODES.LIVE?new Wso2ProviderAdapter(config):
   config.mode===MODES.CONTRACT?new OfflineContractAdapter(config):new PreviewProviderAdapter(config);
}
export function issuerFingerprint(issuer){return createHash('sha256').update(issuer).digest('hex').slice(0,16)}
