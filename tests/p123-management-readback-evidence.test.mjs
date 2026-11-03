import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateFourClientReadback as clients, evaluateCarbonSuperReadback as carbon } from '../scripts/ciam-management-readback-evidence.mjs';
const names=['aurora-web','aurora-app','brisa-web','brisa-app'];
const mkClients=()=>({stage:'CIAM_V5_FOUR_CLIENT_REMOTE_READBACK',remoteWrites:0,
  positiveBrowserAuthentication:'NOT_TESTED',clients:Object.fromEntries(names.map(k=>[k,{
    oidcJwtConfigured:true,businessApiAuthorizedRBAC:true,businessScopesExact:true,
    profileAudienceConfigured:true,businessAudienceConfigured:true,
    requestedClientReadback:'VERIFIED',positiveRuntime:'NOT_TESTED'}]))});
const coll=(extra={})=>({status:'FULL_FIRST_PAGE',pageCount:0,reportedTotal:0,...extra});
const mkCarbon=()=>({stage:'CARBON_SUPER_READ_ONLY',remoteWrites:0,identityAuthority:'carbon.super',inventory:{
  rootTenants:coll({pageCount:2,reportedTotal:2,domains:['aurora.identity.test','brisa.identity.test']}),
  superApplications:coll({pageCount:1,reportedTotal:1,applicationNames:['Carbon application']}),
  superApiResources:coll({resourceIdentifiers:[]}),
  superScimUsers:coll({pageCount:1,reportedTotal:1,adminAccountSeen:true,otherUserCountOnPage:0}),
  superScimRolesV2:coll({pageCount:1,reportedTotal:1,roleNames:['System role']})
}});
const run=(fn,obj)=>fn(JSON.stringify(obj));
test('four exact OIDC clients plus all five security flags constitute GET-only management proof',()=>{
  const out=run(clients,mkClients());assert.equal(out.status,'PASS');
  assert.match(out.summary,/browser proof remains independent/);
});
test('the Python source exits 0 for a false audience flag: parser must still FAIL',()=>{
  for(const field of ['oidcJwtConfigured','businessApiAuthorizedRBAC','businessScopesExact','profileAudienceConfigured','businessAudienceConfigured']){
    const d=mkClients();d.clients['brisa-app'][field]=false;
    assert.equal(run(clients,d).status,'FAIL',field);
  }
});
test('missing, extra or duplicated-via-key client and incomplete flag schema block proof',()=>{
  const a=mkClients();delete a.clients['aurora-app'];assert.equal(run(clients,a).status,'BLOCKED');
  const b=mkClients();b.clients.extra=b.clients['brisa-app'];assert.equal(run(clients,b).status,'BLOCKED');
  const c=mkClients();delete c.clients['brisa-web'].businessAudienceConfigured;
  assert.equal(run(clients,c).status,'BLOCKED');
  const d=mkClients();d.positiveBrowserAuthentication='VERIFIED';assert.equal(run(clients,d).status,'BLOCKED');
});
test('all five complete Carbon Super inventories plus both tenant domains/admin constitute GET-only proof',()=>{
  const out=run(carbon,mkCarbon());assert.equal(out.status,'PASS');
  assert.match(out.summary,/no business\/browser\/MFA activity asserted/);
});
test('Carbon command HTTP failures and partial pages must BLOCK, even with exit code 0',()=>{
  const a=mkCarbon();a.inventory.superApiResources={status:'UNVERIFIED_HTTP_403'};
  assert.equal(run(carbon,a).status,'BLOCKED');
  const b=mkCarbon();b.inventory.superScimRolesV2.status='PARTIAL_OR_UNVERIFIED';
  assert.equal(run(carbon,b).status,'BLOCKED');
  const c=mkCarbon();c.inventory.rootTenants.reportedTotal=12;
  assert.equal(run(carbon,c).status,'BLOCKED');
});
test('missing tenant domains and missing verified Carbon Super admin must FAIL',()=>{
  const a=mkCarbon();a.inventory.rootTenants.domains=['aurora.identity.test','other.identity.test'];
  assert.equal(run(carbon,a).status,'FAIL');
  const b=mkCarbon();b.inventory.superScimUsers.adminAccountSeen=false;
  assert.equal(run(carbon,b).status,'FAIL');
});
test('invalid Carbon collection schema and omitted fields stay BLOCKED',()=>{
  const a=mkCarbon();a.inventory.superApplications.applicationNames=[];
  assert.equal(run(carbon,a).status,'BLOCKED');
  const b=mkCarbon();delete b.inventory.superScimRolesV2;
  assert.equal(run(carbon,b).status,'BLOCKED');
  const c=mkCarbon();c.inventory.superScimUsers.otherUserCountOnPage=-1;
  assert.equal(run(carbon,c).status,'BLOCKED');
});
test('injected remote text, identities and tokens are never echoed to executive evidence',()=>{
  const danger='VERY_PRIVATE_BEARER_SECRET_123456';
  const a=mkClients();a.clients['brisa-app'].requestedClientReadback=danger;
  assert.doesNotMatch(JSON.stringify(run(clients,a)),/VERY_PRIVATE|BEARER_SECRET/);
  const b=mkCarbon();b.inventory.superApplications.applicationNames=[danger];
  assert.doesNotMatch(JSON.stringify(run(carbon,b)),/VERY_PRIVATE|BEARER_SECRET/);
});
test('write-like outputs, malformed JSON, oversized evidence and wrong producer stages fail closed',()=>{
  const a=mkClients();a.remoteWrites=1;assert.equal(run(clients,a).status,'BLOCKED');
  const b=mkCarbon();b.remoteWrites=1;assert.equal(run(carbon,b).status,'BLOCKED');
  assert.equal(clients('not json').status,'BLOCKED');
  assert.equal(carbon('{"token":"'+ 'X'.repeat(1048576)+'"}').status,'BLOCKED');
  const c=mkCarbon();c.stage='COMPLETELY_DIFFERENT';assert.equal(run(carbon,c).status,'BLOCKED');
});
