import {safeStatus,MODES,getMode} from './core.mjs';
const architecture={schema:'identity.provider.architecture.v1',layers:[
 {name:'Experience Center',owns:['Brands','B2B','Consent UX','Assurance UX','M2M UX','Operations UX'],mayIssueTokens:false},
 {name:'Identity Backend / BFF',owns:['Real OAuth/OIDC callback','Session security','Provider adapters','Token verification','Evidence correlation'],mayIssueTokens:false},
 {name:'Local extensions',owns:['Synthetic consent ledger','Assurance records','Controlled fixtures','Append-only evidence'],mayIssueTokens:false},
 {name:'WSO2 Identity Server 7.3 (future)',owns:['OIDC issuer','MFA','Federation','Organizations','Token issuance'],mayIssueTokens:true,connected:false}
],boundaries:['Browsers never hold OAuth client secrets','Local preview does not mint signed identity tokens','Canonical customer IDs never leave privileged backend','Only independently tested flows may be labeled Live Verified']};
export function createProviderHttpRoute(env=process.env){
 // Strictly read-only public endpoints. No untrusted target URLs and no login emulation.
 return async function providerHttpRoute({req,res,path,send}){
  if(!path.startsWith('/api/provider/'))return false;
  if(req.method!=='GET'){send(res,405,{error:'METHOD_NOT_ALLOWED'});return true}
  if(path==='/api/provider/status'){send(res,200,safeStatus(env));return true}
  if(path==='/api/provider/architecture'){send(res,200,architecture);return true}
  if(path==='/api/provider/modes'){send(res,200,{activeMode:getMode(env),modes:[
   {id:MODES.PREVIEW,allowed:'Synthetic journeys and illustrative decisions',never:'Real authentication or verified WSO2 behavior'},
   {id:MODES.CONTRACT,allowed:'Fixture-driven service and security contract tests',never:'End-to-end customer compliance'},
   {id:MODES.LIVE,allowed:'Real operations only through separately wired and proven BFF integrations',never:'PASS without captured, independently reviewed evidence'}],acceptance:'NOT_VERIFIED'});return true}
  send(res,404,{error:'NOT_FOUND'});return true;
 }
}
