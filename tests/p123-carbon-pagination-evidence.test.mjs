import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCarbonSuperReadback as carbon } from '../scripts/ciam-management-readback-evidence.mjs';
const coll=(n,field,value)=>({status:'FULL_FIRST_PAGE',pageCount:n,reportedTotal:n,[field]:value});
const mk=()=>({stage:'CARBON_SUPER_READ_ONLY',remoteWrites:0,identityAuthority:'carbon.super',inventory:{
 rootTenants:coll(2,'domains',['aurora.identity.test','brisa.identity.test']),
 superApplications:coll(1,'applicationNames',['tenant-app']),
 superApiResources:{status:'FULL_PAGINATED',pageCount:184,reportedTotal:184,pagesFetched:2,paginationMode:'WSO2_AFTER_CURSOR',resourceIdentifiers:Array.from({length:184},(_,i)=>`API_${i}`)},
 superScimUsers:{status:'FULL_FIRST_PAGE',pageCount:1,reportedTotal:1,adminAccountSeen:true,otherUserCountOnPage:0},
 superScimRolesV2:coll(1,'roleNames',['role'])
}});
const check=d=>carbon(JSON.stringify(d));
test('complete 100+84 two-page resource readback passes strict management evidence',()=>{
 const p=check(mk());assert.equal(p.status,'PASS');
 assert.doesNotMatch(p.summary,/API_183/);
});
test('partial first page of 100 out of 184 remains BLOCKED',()=>{
 const d=mk();d.inventory.superApiResources={status:'PARTIAL_OR_UNVERIFIED',pageCount:100,reportedTotal:184,verificationCode:'FORWARD_CURSOR_UNVERIFIED'};
 assert.equal(check(d).status,'BLOCKED');
});
test('false pagination evidence missing strategy/pages, wrong totals or excessive pages BLOCKS',()=>{
 for(const f of [
  d=>delete d.inventory.superApiResources.pagesFetched,
  d=>d.inventory.superApiResources.pagesFetched=12,
  d=>d.inventory.superApiResources.paginationMode='OFFSET',
  d=>d.inventory.superApiResources.reportedTotal=185,
  d=>d.inventory.superApiResources.pageCount=1001,
  d=>d.inventory.superApiResources.status='FULL_FIRST_PAGE',
  d=>d.inventory.superApiResources.pagesFetched=1,
 ]){const d=mk();f(d);assert.equal(check(d).status,'BLOCKED');}
});
test('duplicate or missing resource identifiers never count as complete inventory',()=>{
 for(const f of [
  d=>d.inventory.superApiResources.resourceIdentifiers[183]=d.inventory.superApiResources.resourceIdentifiers[0],
  d=>d.inventory.superApiResources.resourceIdentifiers.pop(),
 ]){const d=mk();f(d);assert.equal(check(d).status,'BLOCKED');}
});
test('sensitive resource identifiers are not reflected in summaries',()=>{
 const d=mk();d.inventory.superApiResources.resourceIdentifiers[19]='DO_NOT_PRINT_PRIVATE_ID';
 assert.equal(check(d).status,'PASS');
 assert.doesNotMatch(JSON.stringify(check(d)),/DO_NOT_PRINT_PRIVATE_ID/);
});
