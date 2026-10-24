/** Register four brand OIDC clients only with verified tenant-scoped Bearer tokens.
 * Never infers SSO or signed pairwise-token acceptance from configuration.
 */
import {readPrivate,privateWrite,call,publicControlPlane} from './tenant-control-plane.mjs';
import {writeFileSync,mkdirSync,chmodSync} from 'node:fs';
import {dirname} from 'node:path';

const BRANDS=['aurora','brisa'];
const ID=/^[a-zA-Z0-9-]{5,128}$/;
const tp=(d,s)=>`/t/${encodeURIComponent(d)}${s}`;
const appId=r=>{
  const value=r.data?.id||r.location?.split('?')[0].split('/').pop();
  if(!ID.test(value||''))throw Error('OIDC_CREATE_ID_MISSING_MANUAL_REVIEW');
  return value;
};
const payload=(app,sector)=>({
  name:app.name,description:'Lab-owned WSO2 OIDC client — real browser identity via BFF',
  isManagementApp:false,accessUrl:app.accessUrl,
  inboundProtocolConfiguration:{oidc:{
    grantTypes:['authorization_code','refresh_token'],publicClient:false,
    callbackURLs:[app.callback],pkce:{mandatory:true,supportPlainTransformAlgorithm:false},
    subject:{subjectType:'pairwise',sectorIdentifierUri:sector}
  }}
});

export function assertPlan(plan,domains,sectorUrls){
  const expected=plan.apps.filter(x=>BRANDS.includes(x.brand));
  if(expected.length!==4||new Set(expected.map(a=>a.key)).size!==4||
     BRANDS.some(b=>expected.filter(x=>x.brand===b).length!==2))
    throw Error('FOUR_DISTINCT_BRAND_APPS_REQUIRED');
  for(const b of BRANDS){
    if(typeof domains[b]!=='string')throw Error('TENANT_DOMAIN_MISSING');
    const url=new URL(sectorUrls[b]);
    if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)
      throw Error('INVALID_PAIRWISE_HTTPS_SECTOR_URI');
  }
  for(const app of expected){
    const callback=new URL(app.callback);
    if(!app.name||!(callback.protocol==='https:' || (process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS==='allow-loopback-v1' && callback.protocol==='http:' && callback.hostname==='127.0.0.1' && !callback.username && !callback.password))||callback.username||callback.password||callback.hash)
      throw Error('INVALID_BRAND_HTTPS_CALLBACK');
  }
  return expected;
}

export async function provisionBrandClients({fetchImpl=fetch,base,domains,bearerTokens,
  rootStateFile,plan,sectorUrls,emit=()=>{}}){
  const expected=assertPlan(plan,domains,sectorUrls);
  const state=readPrivate(rootStateFile,null);
  if(state?.tenantProvisioning!=='TWO_ROOT_TENANTS_CREATED_OR_VERIFIED'||!state.clients||
     BRANDS.some(b=>state.tenants?.[b]?.state!=='created'||state.tenants[b].domain!==domains[b]))
    throw Error('ROOT_TENANT_CONTEXT_NOT_VERIFIED');
  // Fail closed BEFORE first application POST if both management tokens unavailable.
  for(const brand of BRANDS){
    if(!bearerTokens[brand])throw Error(`TENANT_MANAGEMENT_BEARER_MISSING_${brand}`);
    await call(fetchImpl,base,tp(domains[brand],'/api/server/v1/applications?limit=1'),
      {bearer:bearerTokens[brand]});
  }
  for(const app of expected){
    const domain=domains[app.brand],bearer=bearerTokens[app.brand],sector=sectorUrls[app.brand];
    const path=tp(domain,'/api/server/v1/applications');
    let item=state.clients[app.key];
    if(item){
      if(item.tenant!==domain||item.callback!==app.callback||item.sectorUri!==sector)
        throw Error(`OIDC_JOURNAL_CONTEXT_CHANGED_${app.key}`);
      if(!ID.test(item.id||''))throw Error(`OIDC_WRITE_OUTCOME_UNCERTAIN_${app.key}`);
    }else{
      item={tenant:domain,state:'create-started',callback:app.callback,sectorUri:sector};
      state.clients[app.key]=item;privateWrite(rootStateFile,state);
      // Unknown HTTP outcomes and 206 remain create-started; NEVER repeat automatically.
      const created=await call(fetchImpl,base,path,{method:'POST',bearer,payload:payload(app,sector)});
      if(created.status!==201)throw Error(`OIDC_CREATE_NOT_201_${app.key}_MANUAL_REVIEW`);
      item.id=appId(created);item.state='created';privateWrite(rootStateFile,state);
    }
    const read=await call(fetchImpl,base,`${path}/${encodeURIComponent(item.id)}`,{bearer});
    if(read.data?.name!==app.name || read.data?.isManagementApp!==false)
      throw Error(`OIDC_APP_READBACK_MISMATCH_${app.key}`);
    const oidc=await call(fetchImpl,base,`${path}/${encodeURIComponent(item.id)}/inbound-protocols/oidc`,{bearer});
    const d=oidc.data;
    if(!d?.clientId||!d?.clientSecret||d?.subject?.subjectType!=='pairwise'||
       d?.subject?.sectorIdentifierUri!==sector||
       !Array.isArray(d?.callbackURLs)||!d.callbackURLs.includes(app.callback)||
       d?.pkce?.mandatory!==true)
      throw Error(`OIDC_CONFIGURATION_READBACK_FAILED_${app.key}`);
    if(item.clientId&&item.clientId!==d.clientId)throw Error(`OIDC_CLIENT_ID_CHANGED_${app.key}`);
    item.clientId=d.clientId;item.clientSecret=d.clientSecret;item.state='verified';
    privateWrite(rootStateFile,state);
    emit(`OIDC_CONFIG_READBACK_VERIFIED ${app.key} ${domain}`);
  }
  const ids=expected.map(app=>state.clients[app.key].clientId);
  if(new Set(ids).size!==4)throw Error('FOUR_OIDC_CLIENT_IDS_NOT_DISTINCT');
  state.pairwise='FOUR_BRAND_CLIENTS_CONFIGURED_NOT_TOKEN_VERIFIED';
  state.acceptance='NOT_VERIFIED';privateWrite(rootStateFile,state);
  return state;
}

/** Delivers structured BFF input and a scrubbed laboratory UI status contract.
 * Generation alone is NOT equivalent to wiring a BFF or to a live user session.
 */
export function exportBffContracts({base,domains,rootJournal,managementJournal,
  privateOutput,publicOutput}){
  const manifest=publicControlPlane({base,domains,rootJournal,managementJournal,
    clients:rootJournal.clients||{}});
  const confidential={schemaVersion:1,source:'WSO2_SERVER_API_READBACK',
    requiresBffConnection:true,
    brands:Object.fromEntries(BRANDS.map(b=>[b,{issuer:manifest.brands[b].issuer,
      clients:Object.fromEntries(Object.entries(rootJournal.clients||{})
        .filter(([,v])=>v.tenant===domains[b]&&v.state==='verified')
        .map(([key,v])=>[key,{clientId:v.clientId,clientSecret:v.clientSecret,
          callback:v.callback,sectorUri:v.sectorUri}]))}]))};
  for(const b of BRANDS){
    if(!manifest.brands[b].managementBearerVerified||
       Object.keys(confidential.brands[b].clients).length!==2)
      throw Error(`UI_BFF_BRAND_NOT_READY_${b}`);
  }
  // Both files stay under var/wso2/ (private, gitignored); no secrets in public contract.
  for(const [path,content] of [[privateOutput,confidential],[publicOutput,manifest]]){
    if(!path.includes('/var/wso2/')&&!path.startsWith('var/wso2/'))
      throw Error('UI_CONTRACT_PATH_MUST_BE_PRIVATE');
    privateWrite(path,content);
  }
  return manifest;
}
