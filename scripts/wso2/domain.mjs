import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
export const root=resolve(import.meta.dirname,'../..');
export function config(path=resolve(root,'config/wso2/lab.json')){
 const c=JSON.parse(readFileSync(path,'utf8'));validate(c);return c;
}
export function validate(c){
 if(c.schema!=='identity.wso2.lab.v1'||c.tenantDomain!=='carbon.super')throw Error('INVALID_LAB_CONFIG');
 if(c.brands?.length!==2||new Set(c.brands.map(b=>b.id)).size!==2)throw Error('BRANDS_INVALID');
 const keys=c.brands.flatMap(b=>b.clients.map(x=>x.key));
 if(keys.length!==4||new Set(keys).size!==4)throw Error('FOUR_CLIENTS_REQUIRED');
 const bffKeys=c.brands.flatMap(b=>b.clients.map(a=>a.bffClientKey));
 if(bffKeys.length!==4||new Set(bffKeys).size!==4||bffKeys.some(x=>!['aurora-web','aurora-app','brisa-web','brisa-app'].includes(x)))throw Error('EXACT_BFF_CLIENT_ROUTES_REQUIRED');
 if(new Set(c.brands.map(b=>b.sector)).size!==2)throw Error('SECTOR_MUST_DIFFER_BETWEEN_BRANDS');
 for(const b of c.brands){if(b.clients.length!==2||b.clients.filter(x=>x.kind==='web').length!==1||b.clients.filter(x=>x.kind==='mobile-browser-preview').length!==1)throw Error('WEB_MOBILE_PER_BRAND_REQUIRED');}
 const o=new Set(c.b2bOrganizations.map(x=>x.key));for(const org of c.b2bOrganizations){if(org.parent&&!o.has(org.parent))throw Error('INVALID_PARENT')}
 return c;
}
export function assertUpdatedBuild(env=process.env){
 if(!env.WSO2_BUILD_ATTESTATION_FILE)throw Error('WSO2_BUILD_ATTESTATION_FILE_REQUIRED');
 const p=JSON.parse(readFileSync(env.WSO2_BUILD_ATTESTATION_FILE,'utf8'));
 if(p.release!=='7.3.0'||!Number.isInteger(p.update)||p.update<18)throw Error('WSO2_MINIMUM_7_3_0_UPDATE_18_REQUIRED');
 if(!p.imageDigest||!/^sha256:[a-f0-9]{64}$/.test(p.imageDigest))throw Error('IMAGE_DIGEST_EVIDENCE_REQUIRED');
 return {release:p.release,update:p.update,imageDigest:p.imageDigest,claim:'OPERATOR_ATTESTED_NOT_RUNTIME_VERIFIED'};
}
export function deploymentPlan(c,env=process.env){
 const base=env.DEMO_PUBLIC_BASE_URL||'http://127.0.0.1:5173';const uri=new URL(base);
 if(uri.username||uri.password||uri.hash||uri.search||!['http:','https:'].includes(uri.protocol)||
  (uri.protocol==='http:'&&!['localhost','127.0.0.1'].includes(uri.hostname)))throw Error('PUBLIC_BASE_MUST_BE_HTTPS_OR_LOOPBACK');
 const bff=new URL(env.DEMO_BFF_BASE_URL||'http://127.0.0.1:4000');
 if(bff.username||bff.password||bff.search||bff.hash||bff.pathname!=='/'||!['http:','https:'].includes(bff.protocol)||
  (bff.protocol==='http:'&&!['localhost','127.0.0.1'].includes(bff.hostname)))throw Error('BFF_BASE_MUST_BE_TLS_OR_LOOPBACK');
 const apps=c.brands.flatMap(b=>b.clients.map(a=>({key:a.key,bffClientKey:a.bffClientKey,brand:b.id,sector:b.sector,name:`Identity Lab ${a.label}`,kind:a.kind,accessUrl:new URL(a.path,uri).href,
   callback:new URL(`/auth/${a.bffClientKey}/callback`,bff).href})))
   .concat(c.m2m.map(x=>({key:x.key,brand:'workload',name:`Identity Lab ${x.name}`,kind:'m2m'})));
 return {schema:'identity.wso2.plan.v1',createdAt:new Date().toISOString(),mode:'PLAN_ONLY',tenantDomain:c.tenantDomain,apps,
  orgs:c.b2bOrganizations,users:c.users.map(({key,username})=>({key,username})),
  manualGates:['verify update from running server','pairwise sector identifier registration and token assertions','issuer/discovery/callback URL congruence','organization bearer and delegated assignments','agent identity enrollment and MCP server resource authorization','MFA/consent and verified acceptance'],
  acceptance:'NOT_VERIFIED'};
}
