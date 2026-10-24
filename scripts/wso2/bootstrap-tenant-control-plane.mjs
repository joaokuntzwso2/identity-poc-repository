/** Usage:
 * NODE_EXTRA_CA_CERTS=... WSO2_LAB_CONFIRM=CREATE_SYNTHETIC_RESOURCES \
 * node --env-file=var/wso2/lab.env scripts/wso2/bootstrap-tenant-control-plane.mjs preflight|all|verify|status
 */
import {resolve} from 'node:path';
import {request as httpsRequest} from 'node:https';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {assertLab,readPrivate,adminPreflight,seedManagement,verifyManagement} from './tenant-control-plane.mjs';
import {provisionBrandClients,exportBffContracts} from './tenant-brand-clients.mjs';
const ROOT=resolve('var/wso2/tenant-brand.private.json');
const MGMT=resolve('var/wso2/tenant-management.private.json');
const UI=resolve('var/wso2/lab-wso2-linked-status.private.json');
const BFF=resolve('var/wso2/identity-bff-wso2.private.json');

/** The Mac does not resolve Docker network aliases. Fetch only pinned sector
 * documents via a loopback-only published port, retaining TLS SNI and hostname
 * verification. All other URLs use the original fetch implementation.
 */
export function sectorSidecarFetch(fetchImpl,env){
  if(env.WSO2_LAB_SECTOR_BRIDGE!=='docker-sidecar-v1')return fetchImpl;
  const names=new Set(['aurora-sector.identity.test','brisa-sector.identity.test']);
  const ca=readFileSync(resolve('var/wso2/sector-host/tls/sector.pem'));
  return async(input,init={})=>{
    const u=new URL(String(input));
    if(!names.has(u.hostname))return fetchImpl(input,init);
    if(u.protocol!=='https:'||u.port||u.pathname!=='/sector.json'||u.search||u.hash||
       (init.method&&init.method.toUpperCase()!=='GET'))throw Error('SECTOR_BRIDGE_URL_REJECTED');
    return await new Promise((done,fail)=>{
      const req=httpsRequest({hostname:'127.0.0.1',port:18443,path:'/sector.json',
        method:'GET',servername:u.hostname,ca,rejectUnauthorized:true,
        headers:{Host:u.hostname,Accept:'application/json'},timeout:8000},res=>{
        const chunks=[];let length=0;
        res.on('data',c=>{length+=c.length;if(length>32768){req.destroy(Error('SECTOR_DOCUMENT_TOO_LARGE'));return;}chunks.push(c);});
        res.on('end',()=>done(new Response(Buffer.concat(chunks),{status:res.statusCode,
          headers:{'content-type':res.headers['content-type']||'application/octet-stream'}})));
      });
      req.on('error',fail);req.on('timeout',()=>req.destroy(Error('SECTOR_HTTPS_TIMEOUT')));req.end();
    });
  };
}

/** Read-only, tenant-independent gate for durable HTTPS sector documents.
 * Must pass BEFORE management-app and OIDC-client writes in all mode.
 */
export async function sectorPreflight({env=process.env,fetchImpl=fetch,domains}={}){
  const [{config,deploymentPlan},{sectorUris,assertSectorDocuments},{assertPlan}]=await Promise.all([
    import('./domain.mjs'),import('./sector.mjs'),import('./tenant-brand-clients.mjs')
  ]);
  const plan=deploymentPlan(config(),env);
  const urls=sectorUris(env);
  assertPlan(plan,domains,urls);
  await assertSectorDocuments(plan,env,sectorSidecarFetch(fetchImpl,env));
  return {plan,urls};
}

export async function execute(mode,{env=process.env,fetchImpl=fetch,emit=console.log}={}){
  if(mode==='status'){
    const root=readPrivate(ROOT,{tenants:{},clients:{}});
    const management=readPrivate(MGMT,{management:{}});
    return {tenants:Object.fromEntries(['aurora','brisa'].map(b=>[b,{
      state:root.tenants?.[b]?.state||'MISSING',
      adminLogin:root.tenants?.[b]?.ownerAuthentication||'NOT_VERIFIED',
      ownerRecovery:root.tenants?.[b]?.ownerRecovery?.state||'NOT_STARTED',
      managementBearer:management.management?.[b]?.state||'NOT_STARTED'}])),
      fourOidcClientConfigurationsVerified:Object.values(root.clients||{}).filter(x=>x?.state==='verified').length===4,
      bffRuntime:'NOT_ATTESTED',browserSso:'NOT_ATTESTED',signedPairwiseIdTokens:'NOT_ATTESTED'};
  }
  const {base,domains}=assertLab(env);
  // Validate the external HTTPS documents and distinct sector hosts BEFORE
  // creating even one WSO2 resource. This GET-only phase does not need Basic.
  const sector= ['all','clients','sector-preflight'].includes(mode)
    ? await sectorPreflight({env,fetchImpl,domains}) : null;
  if(mode==='sector-preflight')return {sectorDocuments:'VERIFIED_READ_ONLY',distinctHosts:true,writes:0};
  let root=readPrivate(ROOT,null);
  if(mode==='all'){
    const {bootstrapTenants}=await import('./tenant-brand-bootstrap.mjs');
    await bootstrapTenants({env,fetchImpl,onlyTenants:true,emit});
    root=readPrivate(ROOT,null);
  }
  if(!root)throw Error('ROOT_JOURNAL_MISSING_RUN_TENANTS_ONLY_FIRST');
  if(mode==='preflight'){
    await adminPreflight({fetchImpl,base,domains,rootJournal:root});
    return {rootTenants:'JOURNALED',adminBasicForBoth:'VERIFIED_READ_ONLY',writes:0};
  }
  if(mode==='verify'){
    await verifyManagement({fetchImpl,base,domains,stateFile:MGMT});
    return {tenantManagementBearer:'VERIFIED_READ_ONLY',writes:0};
  }
  if(!['all','seed','clients','ui-map'].includes(mode))throw Error('INVALID_MODE');
  let bearerTokens={};
  if(['all','seed'].includes(mode)){
    const result=await seedManagement({fetchImpl,base,domains,rootJournal:root,stateFile:MGMT,emit});
    bearerTokens=result.bearerTokens;
  }else if(mode==='clients'){
    bearerTokens=await verifyManagement({fetchImpl,base,domains,stateFile:MGMT});
  }
  if(mode==='seed')return {managementApps:'TWO_VERIFIED',oidcClients:'NOT_REQUESTED'};
  if(['all','clients'].includes(mode)){
    root=await provisionBrandClients({fetchImpl,base,domains,bearerTokens,
      rootStateFile:ROOT,plan:sector.plan,sectorUrls:sector.urls,emit});
  }
  const management=readPrivate(MGMT,null);
  const manifest=exportBffContracts({base,domains,rootJournal:root,managementJournal:management,
    privateOutput:BFF,publicOutput:UI});
  return {managementApps:'TWO_VERIFIED',oidcConfiguration:'FOUR_READBACK_VERIFIED',
    wso2ToBffContractFile:BFF,wso2ToLaboratoryStatusFile:UI,
    actualBffConnected:false,interactiveSsoVerified:false,signedPairwiseIdTokensVerified:false};
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  execute(process.argv[2]||'status').then(v=>console.log(JSON.stringify(v,null,2)))
    .catch(e=>{console.error('WSO2_CONTROL_PLANE_ERROR:',e.message);process.exitCode=1});
}
