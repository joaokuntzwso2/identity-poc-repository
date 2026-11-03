import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateBusinessVerify,evaluateBusinessRoleAudit} from '../scripts/ciam-phase4-evidence.mjs';
const brands=['aurora','brisa'],channels=['web','app'];
const approve='ciam:cases:approve';
const expected=['ciam:cases:approve','ciam:cases:read','ciam:cases:review'];
const present=['ciam:cases:read','ciam:cases:review'];
const perm=(bad)=>({schema:'SCIM_PERMISSION_OBJECT_ARRAY',count:bad?2:3,exact:!bad,expected,
 presentExpected:bad?present:expected,missingExpected:bad?[approve]:[],otherKnownScopes:[],
 unknownPermissionValueCount:0,entriesWithoutStringValue:0,nonObjectEntries:0,duplicateValueEntries:0});
const build=()=>{
 const rows=[];
 for(const tenant of brands)for(const channel of channels){
   const kinds=tenant==='brisa'?['customer','administrator']:['customer','seller','administrator'];
   for(const roleKind of kinds){
     const bad=roleKind==='administrator';
     rows.push({tenant,channel,roleKind,roleGetHttp:200,roleIdentityMatches:true,audienceMatches:true,membersMatch:true,
       directPermissions:perm(bad),result:bad?'ROLE_PERMISSIONS_MISMATCH_CONFIRMED':'ROLE_PERMISSIONS_MATCH',
       ...(bad?{projectionGetHttp:200,projectedPermissions:perm(true)}:{})});
   }
 }
 return {diagnostic:'CIAM_PHASE4_ROLE_EVIDENCE_V1',method:'GET_ONLY',sourceDigestsVerified:true,
 roleApiVersion:'v2',result:'ROLE_DRIFT_NEEDS_REVIEW',rolesChecked:rows.length,
 rolesNotMatching:4,rows};
};
test('realistic four-administrator missing-approval audit is classified as a FAIL not a PASS',()=>{
 const r=evaluateBusinessRoleAudit(JSON.stringify(build()));
 assert.equal(r.ok,false); assert.equal(r.kind,'CONFIRMED_ADMIN_APPROVAL_DRIFT');
 assert.match(r.summary,/four administrator roles/);assert.match(r.summary,/grants not changed/);
});
test('unrecognized or expanded grants cannot be treated as known safe drift',()=>{
 const d=build();d.rows[2].directPermissions.unknownPermissionValueCount=1;
 const r=evaluateBusinessRoleAudit(JSON.stringify(d));
 assert.equal(r.ok,false);assert.equal(r.kind,'UNVERIFIED');
});
test('missing membership and mismatched count never produce the known drift summary',()=>{
 const d=build();d.rows[2].membersMatch=false;
 assert.equal(evaluateBusinessRoleAudit(JSON.stringify(d)).kind,'UNVERIFIED');
 d.rows[2].membersMatch=true;d.rolesNotMatching=3;
 assert.equal(evaluateBusinessRoleAudit(JSON.stringify(d)).kind,'UNVERIFIED');
});
test('malicious free-form fields cannot leak via the evidence summary',()=>{
 const d=build();d.rows[2].secret='Bearer abcprivate';d.error='password=secret';
 assert.doesNotMatch(evaluateBusinessRoleAudit(JSON.stringify(d)).summary,/abcprivate|password=secret/);
 assert.equal(evaluateBusinessRoleAudit('Bearer abcprivate').kind,'UNVERIFIED');
});
test('successful phase4 verify requires expected schema and explicitly retains runtime NOT_TESTED',()=>{
 assert.equal(evaluateBusinessVerify(JSON.stringify({stage:'CIAM_BUSINESS_V4',mode:'VERIFY',readback:'VERIFIED',businessRuntime:'NOT_TESTED'})).ok,true);
 for(const d of [
   {stage:'CIAM_BUSINESS_V4',mode:'APPLY',readback:'VERIFIED',businessRuntime:'NOT_TESTED'},
   {stage:'CIAM_BUSINESS_V4',mode:'VERIFY',readback:'VERIFIED',businessRuntime:'TESTED'},
   {stage:'CIAM_BUSINESS_V4',mode:'VERIFY',readback:'VERIFIED',businessRuntime:'NOT_TESTED',remoteWrites:1},
 ])assert.equal(evaluateBusinessVerify(JSON.stringify(d)).ok,false);
});
test('a fully matching GET-only role audit is only partial proof, not business runtime proof',()=>{
 const d=build();for(const row of d.rows){row.result='ROLE_PERMISSIONS_MATCH';row.directPermissions.exact=true;}
 d.result='ALL_ROLES_MATCH';d.rolesNotMatching=0;
 const r=evaluateBusinessRoleAudit(JSON.stringify(d));
 assert.equal(r.ok,true);assert.match(r.summary,/independent Phase 4 API readback still required/);
});
