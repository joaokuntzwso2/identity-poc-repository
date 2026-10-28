import test from 'node:test';
import assert from 'node:assert/strict';
import { beginApprovalChallenge, verifyApprovalResponse, totpPolicy, StepUpDenied } from '../src/approval-stepup-p010.js';
const client={brand:'aurora',clientId:'aurora-web-test-oidc-client',issuer:'https://localhost:9444/t/aurora.identity.test/oauth2/token',redirectUri:'http://127.0.0.1:4400/auth/aurora-web/callback',scope:'openid'};
const policy=totpPolicy({WSO2_TOTP_STEPUP_ACR:'urn:ciampoc:assurance:totp:v1',WSO2_TOTP_STEPUP_AMR:'totp'});
const caseId='123e4567-e89b-42d3-a456-426614174000';
const startedAt=1800000000100;
const disc=support=>({authorization_endpoint:'https://localhost:9444/t/aurora.identity.test/oauth2/authorize',claims_parameter_supported:support});
function fixtures(){return {session:{id:'opaque-session',pending:{},logins:{'aurora-web':{verified:true,claims:{iss:client.issuer,sub:'opaque-sub'}}}}, key:'aurora-web',brand:'aurora',caseId,client,policy,now:startedAt};}
function tokenFixtures(){return {session:{id:'opaque-session',logins:{'aurora-web':{verified:true,claims:{iss:client.issuer,sub:'opaque-sub'}}}},pending:{kind:'case-approval',at:startedAt,sessionId:'opaque-session',key:'aurora-web',clientId:client.clientId,issuer:client.issuer,subject:'opaque-sub',brand:'aurora',caseId},key:'aurora-web',client,policy,now:1800000005200,claims:{iss:client.issuer,sub:'opaque-sub',aud:client.clientId,acr:policy.acr,amr:['BasicAuthenticator','totp'],auth_time:1800000002,iat:1800000002}};}
function gate(modify,expected){const f=tokenFixtures();modify(f.claims);assert.throws(()=>verifyApprovalResponse(f),e=>{assert.ok(e instanceof StepUpDenied);assert.equal(e.status,403);assert.equal(e.code,'fresh_wso2_totp_not_attested');assert.equal(e.attestationGate,expected);return true;});}
test('advertised claims support: requests essential signed auth_time with PKCE and max_age=0',()=>{
 const x=fixtures(),out=beginApprovalChallenge({...x,discovery:disc(true)});
 const u=new URL(out.authorizationUrl),c=JSON.parse(u.searchParams.get('claims'));
 assert.deepEqual(c,{id_token:{auth_time:{essential:true}}});
 assert.equal(u.searchParams.get('max_age'),'0');
 assert.equal(u.searchParams.get('prompt'),'login');
 assert.equal(u.searchParams.get('acr_values'),policy.acr);
 assert.equal(u.searchParams.get('code_challenge_method'),'S256');
 assert.ok(u.searchParams.get('nonce'));
 assert.equal(u.searchParams.get('state') in x.session.pending,true);
});
test('unadvertised claims parameter: keep standards-mandated max_age but do not assume support',()=>{
 for(const support of [false,undefined]){
 const out=beginApprovalChallenge({...fixtures(),discovery:disc(support)});
 const u=new URL(out.authorizationUrl);
 assert.equal(u.searchParams.has('claims'),false);
 assert.equal(u.searchParams.get('max_age'),'0');
 }
});
test('missing signed authentication time is explicitly denied',()=>gate(c=>delete c.auth_time,'SIGNED_AUTH_TIME_MISSING'));
test('string timestamps, null and arrays cannot masquerade as signed numeric authentication time',()=>{
 for(const value of ['1800000002',null,[],{value:1800000002}])gate(c=>c.auth_time=value,'SIGNED_AUTH_TIME_WRONG_TYPE');
});
test('fractional numeric authentication time is denied',()=>gate(c=>c.auth_time=1800000002.5,'SIGNED_AUTH_TIME_NON_INTEGER'));
test('iat alone cannot replace absent signed auth_time',()=>gate(c=>{delete c.auth_time;c.iat=1800000003;},'SIGNED_AUTH_TIME_MISSING'));
test('stale and future signed authentication time remain denied',()=>{
 gate(c=>c.auth_time=1799999999,'SIGNED_AUTH_TIME_BEFORE_TRANSACTION');
 gate(c=>c.auth_time=1800000100,'SIGNED_AUTH_TIME_IN_FUTURE');
});
test('valid signed ACR, TOTP AMR, auth_time and iat still pass together',()=>{
 const f=tokenFixtures();const out=verifyApprovalResponse(f);assert.equal(out.caseId,caseId);assert.equal(out.methodAttested,true);
});
test('signed ACR and AMR checks still precede authentication time and fail closed',()=>{
 gate(c=>{delete c.acr;delete c.auth_time;},'SIGNED_ACR_MISSING');
 gate(c=>{c.amr=['BasicAuthenticator'];delete c.auth_time;},'SIGNED_AMR_TOTP_NOT_PRESENT');
});
