import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyApprovalResponse, StepUpDenied, totpPolicy } from '../src/approval-stepup-p010.js';
const client={brand:'aurora',issuer:'https://localhost/t/aurora.identity.test/oauth2/token',clientId:'aurora-web-private-client'};
const policy=totpPolicy({WSO2_TOTP_STEPUP_ACR:'urn:ciampoc:assurance:totp:v1',WSO2_TOTP_STEPUP_AMR:'totp'});
const start=1800000000100, now=1800000005200;
function fixture(){return {
 session:{id:'opaque-id',logins:{'aurora-web':{verified:true,claims:{iss:client.issuer,sub:'opaque-seller-subject'}}}},
 pending:{kind:'case-approval',at:start,sessionId:'opaque-id',key:'aurora-web',clientId:client.clientId,
 issuer:client.issuer,subject:'opaque-seller-subject',brand:'aurora',caseId:'123e4567-e89b-42d3-a456-426614174000',returnTo:'/portal/aurora/web'},
 claims:{iss:client.issuer,sub:'opaque-seller-subject',aud:client.clientId,acr:policy.acr,
 amr:['BasicAuthenticator','totp'],auth_time:1800000002,iat:1800000002,exp:1800000100}
};}
function verify(f){return verifyApprovalResponse({...f,key:'aurora-web',client,policy,now});}
function expectGate(mut,gate){const f=fixture();mut(f);assert.throws(()=>verify(f),e=>{
 assert.ok(e instanceof StepUpDenied);assert.equal(e.code,'fresh_wso2_totp_not_attested');
 assert.equal(e.status,403);assert.equal(e.attestationGate,gate);
 assert.ok(!JSON.stringify({error:e.code,attestationGate:e.attestationGate}).includes('opaque-seller'));
 return true;});}
test('valid signed assurance still passes only with exact approved claims',()=>{
 const f=fixture();const value=verify(f);
 assert.equal(value.caseId,f.pending.caseId);assert.equal(value.methodAttested,true);
});
test('missing or mismatched ACR gives sanitized gate',()=>{
 expectGate(f=>delete f.claims.acr,'SIGNED_ACR_MISSING');
 expectGate(f=>f.claims.acr='not-authorized','SIGNED_ACR_MISMATCH');
});
test('missing/invalid AMR vs missing TOTP are separated',()=>{
 expectGate(f=>delete f.claims.amr,'SIGNED_AMR_MISSING_OR_INVALID');
 expectGate(f=>f.claims.amr=['BasicAuthenticator'],'SIGNED_AMR_TOTP_NOT_PRESENT');
});
test('missing auth_time is distinct from stale or future values',()=>{
 expectGate(f=>delete f.claims.auth_time,'SIGNED_AUTH_TIME_MISSING');
 expectGate(f=>f.claims.auth_time=1799999999,'SIGNED_AUTH_TIME_BEFORE_TRANSACTION');
 expectGate(f=>f.claims.auth_time=1800001000,'SIGNED_AUTH_TIME_IN_FUTURE');
});
test('non-numeric and fractional signed authentication times are rejected',()=>{
 expectGate(f=>f.claims.auth_time='1800000002','SIGNED_AUTH_TIME_WRONG_TYPE');
 expectGate(f=>f.claims.auth_time=null,'SIGNED_AUTH_TIME_WRONG_TYPE');
 expectGate(f=>f.claims.auth_time=1800000002.5,'SIGNED_AUTH_TIME_NON_INTEGER');
});
test('signed issue time and window are required',()=>{
 expectGate(f=>delete f.claims.iat,'SIGNED_IAT_MISSING_OR_INVALID');
 expectGate(f=>f.claims.iat=1799999999,'SIGNED_IAT_BEFORE_TRANSACTION');
});
test('subject/client failure remains separate and does not reveal diagnostic detail',()=>{
 const f=fixture();f.claims.sub='someone-else';
 assert.throws(()=>verify(f),e=>e.code==='stepup_subject_mismatch'&&!e.attestationGate);
});
