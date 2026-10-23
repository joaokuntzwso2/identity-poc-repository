/** Private bridge from owned WSO2 registrations into the existing OIDC BFF config keys. */
import {resolve} from 'node:path';
import {readFileSync,existsSync,writeFileSync,chmodSync,mkdirSync,renameSync} from 'node:fs';
import {config,root} from './domain.mjs';
import {origin} from './api.mjs';
import {sectorUris} from './sector.mjs';
const quote = s => "'"+String(s).replaceAll("'", "'\\''")+"'";
export function renderBffEnvironment(c,credentials,env=process.env){
 const raw=env.DEMO_BFF_BASE_URL||'http://127.0.0.1:4000',bff=new URL(raw);
 if(bff.pathname!=='/'||bff.search||bff.hash||bff.username||bff.password||
   (bff.protocol==='http:'&&!['127.0.0.1','localhost'].includes(bff.hostname))||!['http:','https:'].includes(bff.protocol))throw Error('INVALID_BFF_PUBLIC_ORIGIN');
 if(!env.WSO2_OIDC_ISSUER)throw Error('WSO2_OIDC_ISSUER_DISCOVERY_VALUE_REQUIRED');
 const issuer=new URL(env.WSO2_OIDC_ISSUER);if(issuer.protocol!=='https:'||issuer.username||issuer.password||issuer.hash||issuer.search||issuer.origin!==origin(env.WSO2_BASE_URL))throw Error('OIDC_ISSUER_SECURITY_MISMATCH');
 const sectors=sectorUris(env);
 const vars={PUBLIC_ORIGIN:bff.origin,OIDC_ISSUER:issuer.href,PORT:bff.port||'4000',SECTOR_AURORA_URI:sectors.aurora,SECTOR_BRISA_URI:sectors.brisa};
 if(bff.protocol==='http:')vars.ALLOW_INSECURE_LOCAL='true';
 for(const brand of c.brands)for(const app of brand.clients){
  const entry=credentials.clients?.[app.key];if(!entry?.clientId||!entry?.clientSecret)throw Error(`MISSING_REAL_CLIENT_SECRET_${app.key}`);
  const prefix='OIDC_'+app.bffClientKey.toUpperCase().replaceAll('-','_');
  vars[prefix+'_CLIENT_ID']=entry.clientId;
  vars[prefix+'_CLIENT_SECRET']=entry.clientSecret;
 }
 const m2m=credentials.clients?.['inventory-workload'];if(m2m?.clientId&&m2m?.clientSecret){vars.M2M_CLIENT_ID=m2m.clientId;vars.M2M_CLIENT_SECRET=m2m.clientSecret;vars.M2M_ISSUER=issuer.href;}
 return '# PRIVATE: generated from lab-owned WSO2 app registrations. NEVER COMMIT.\n'+Object.entries(vars).map(([k,v])=>`${k}=${quote(v)}`).join('\n')+'\n';
}
export function generateBffEnvironment(env=process.env,dir=resolve(root,'var/wso2')){
 const inventory=resolve(dir,'inventory.private.json'),secret=resolve(dir,'credentials.private.json');
 if(!existsSync(inventory)||!existsSync(secret))throw Error('APPLY_WSO2_BOOTSTRAP_FIRST');
 const state=JSON.parse(readFileSync(inventory,'utf8'));if(state.completion!=='PARTIAL_INTEGRATION_REQUIRED')throw Error('BOOTSTRAP_NOT_COMPLETE');
 const raw=renderBffEnvironment(config(),JSON.parse(readFileSync(secret,'utf8')),env);
 mkdirSync(dir,{recursive:true,mode:0o700});const dest=resolve(dir,'identity-bff.generated.env'),temp=`${dest}.${process.pid}.tmp`;
 writeFileSync(temp,raw,{mode:0o600,flag:'wx'});chmodSync(temp,0o600);renameSync(temp,dest);
 return dest;
}
