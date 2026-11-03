/**
 * P1.23 strict GET-only interpretation for the existing four-client and
 * Carbon Super inventory scripts. No remote actions, no trusted free text.
 * Inconclusive/malformed evidence is BLOCKED; demonstrated drift is FAIL.
 * Raw management output must never be added to public demo evidence.
 */
const CLIENTS=['aurora-web','aurora-app','brisa-web','brisa-app'];
const COLLECTIONS=['rootTenants','superApplications','superApiResources','superScimUsers','superScimRolesV2'];
const DOMAINS=['aurora.identity.test','brisa.identity.test'];
const object=x=>x!==null && typeof x==='object' && !Array.isArray(x);
const integer=x=>Number.isSafeInteger(x) && x>=0;
const reason=(status,code)=>({status,reason:code,summary:`Read-only management evidence ${status==='FAIL'?'drift':'incomplete'}: ${code}`});
const pass=(summary)=>({status:'PASS',reason:'VERIFIED',summary});
const json=raw=>{
  if(typeof raw!=='string' || raw.length>1048576)return null;
  try{const d=JSON.parse(raw);return object(d)?d:null;}catch{return null;}
};

/** The producer reports field flags; its exit code checks only 3 of 5 flags.
 * All five must pass for each channel, regardless of a 0 process exit. */
export function evaluateFourClientReadback(raw){
  const d=json(raw);
  if(!d || d.stage!=='CIAM_V5_FOUR_CLIENT_REMOTE_READBACK' || d.remoteWrites!==0 ||
     d.positiveBrowserAuthentication!=='NOT_TESTED' || !object(d.clients))
    return reason('BLOCKED','CLIENT_READBACK_SCHEMA');
  if(Object.keys(d.clients).length!==4 || !CLIENTS.every(key=>Object.hasOwn(d.clients,key)))
    return reason('BLOCKED','CLIENT_READBACK_FOUR_CHANNELS_REQUIRED');
  const requiredFlags=['oidcJwtConfigured','businessApiAuthorizedRBAC','businessScopesExact',
    'profileAudienceConfigured','businessAudienceConfigured'];
  for(const key of CLIENTS){
    const row=d.clients[key];
    if(!object(row) || row.requestedClientReadback!=='VERIFIED' || row.positiveRuntime!=='NOT_TESTED')
      return reason('BLOCKED',`CLIENT_READBACK_INCOMPLETE_${key}`);
    if(requiredFlags.some(f=>typeof row[f]!=='boolean'))
      return reason('BLOCKED',`CLIENT_READBACK_FLAG_MISSING_${key}`);
    if(requiredFlags.some(f=>row[f]!==true))
      return reason('FAIL',`CLIENT_READBACK_CONFIGURATION_DRIFT_${key}`);
  }
  return pass('Four tenant/channel OIDC registrations: JWT access tokens, RBAC authorization, exact cases scopes, and both API audiences verified by remote GET; authenticated browser proof remains independent');
}

const strings=(v,n)=>Array.isArray(v) && v.length===n &&
  v.every(s=>typeof s==='string' && s.length>0 && s.length<=512);
/**
 * The Carbon script has no nonzero exit for partial HTTP failures. Full page,
 * cardinality and tenant/admin proof are required before claiming PASS.
 * We don't print names, resource identifiers or user information.
 */
export function evaluateCarbonSuperReadback(raw){
  const d=json(raw);
  if(!d || d.stage!=='CARBON_SUPER_READ_ONLY' || d.remoteWrites!==0 ||
    d.identityAuthority!=='carbon.super' || !object(d.inventory))
    return reason('BLOCKED','CARBON_READBACK_SCHEMA');
  if(Object.keys(d.inventory).length!==COLLECTIONS.length ||
     !COLLECTIONS.every(k=>Object.hasOwn(d.inventory,k)))
    return reason('BLOCKED','CARBON_COLLECTIONS_INCOMPLETE');
  for(const name of COLLECTIONS){
    const row=d.inventory[name];
    if(!object(row) || row.status!=='FULL_FIRST_PAGE' ||
       !integer(row.pageCount) || row.pageCount>100 ||
       !integer(row.reportedTotal) || row.pageCount!==row.reportedTotal)
      return reason('BLOCKED',`CARBON_COLLECTION_NOT_FULL_${name}`);
  }
  const inv=d.inventory;
  if(!strings(inv.rootTenants.domains,inv.rootTenants.pageCount))
    return reason('BLOCKED','CARBON_TENANT_DOMAINS_UNVERIFIED');
  if(!DOMAINS.every(domain=>inv.rootTenants.domains.includes(domain)) ||
     new Set(inv.rootTenants.domains).size!==inv.rootTenants.domains.length)
    return reason('FAIL','CARBON_TENANT_DOMAIN_DRIFT');
  for(const [name,field] of [['superApplications','applicationNames'],
     ['superApiResources','resourceIdentifiers'],['superScimRolesV2','roleNames']]){
    if(!strings(inv[name][field],inv[name].pageCount))
      return reason('BLOCKED',`CARBON_COLLECTION_FIELDS_UNVERIFIED_${name}`);
  }
  const users=inv.superScimUsers;
  if(typeof users.adminAccountSeen!=='boolean' || !integer(users.otherUserCountOnPage) ||
     users.otherUserCountOnPage>users.pageCount)
    return reason('BLOCKED','CARBON_SCIM_USERS_UNVERIFIED');
  if(!users.adminAccountSeen || users.pageCount===0 ||
     users.otherUserCountOnPage>=users.pageCount)
    return reason('FAIL','CARBON_SUPER_ADMIN_NOT_OBSERVED');
  return pass('Carbon Super: five complete GET-only inventory collections, both tenant domains and administrative SCIM account verified; no business/browser/MFA activity asserted');
}
