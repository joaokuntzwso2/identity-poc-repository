import test from 'node:test';import assert from 'node:assert/strict';
import {assessReadbacks,CLIENTS} from './ciam-p010-preflight-core.mjs';
function fixture(){
 const me={identitySource:'NO_VERIFIED_IDENTITY',authenticated:false,clients:{}};
 const status={identityMode:'live-wso2',statuses:[]};
 const policy={stage:'P010_WSO2_APP_ASSURANCE_READBACK',mode:'GET_ONLY',remoteWrites:0,tenants:{aurora:{},brisa:{}}};
 for(const [key,b,c] of CLIENTS){
   me.clients[key]={configured:true,authenticated:false};status.statuses.push({key,discovery:true});
   policy.tenants[b][c]={registeredApplicationVerified:true,callbackVerified:true,codeAndPkceS256Verified:true,
    roleAudience:'APPLICATION',sequenceType:'DEFAULT'};
 }
 return {me,status,policy};
}
test('real BFF and verified journal readbacks are eligible for interactive login, NOT login proof',()=>{
 const x=fixture(),r=assessReadbacks(x.me,x.status,x.policy);
 assert.equal(r.fourClientsReadyForInteractiveLogin,true);
 assert.equal(r.actualSignedTokenIssuerSubjectAndUserinfoAttested,false);
 assert.equal(r.configuredTotpAssuranceAttested,false);
 assert.equal(Object.keys(r.clients).length,4);
});
test('missing runtime manifest blocks only that client',()=>{const x=fixture();x.me.clients['brisa-app'].configured=false;
 const r=assessReadbacks(x.me,x.status,x.policy);assert.equal(r.fourClientsReadyForInteractiveLogin,false);assert.equal(r.clients['brisa-app'].runtimeConfigured,false);});
test('wrong discovery and wrong runtime mode blocked',()=>{const x=fixture();x.status.statuses[0].discovery=false;assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);
 x.status.statuses[0].discovery=true;x.status.identityMode='preview';assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);});
test('duplicate or unknown runtime key refused',()=>{for(const mutation of [s=>s.status.statuses.push(s.status.statuses[0]),s=>s.status.statuses[0].key='other']){
 const x=fixture();mutation(x);assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);}});
test('journal registration drift fails closed',()=>{const x=fixture();x.policy.tenants.aurora.app.callbackVerified=false;
 assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);});
test('journal cannot contain simulated write success',()=>{const x=fixture();x.policy.remoteWrites=1;
 assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);});
test('anonymous BFF status is not proof of existing user login',()=>{const x=fixture();x.me.authenticated=true;
 assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);});
test('role audience and S256 must both be validated',()=>{const x=fixture();x.policy.tenants.brisa.web.roleAudience='ORGANIZATION';
 assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);
 x.policy.tenants.brisa.web.roleAudience='APPLICATION';x.policy.tenants.brisa.web.codeAndPkceS256Verified=false;
 assert.equal(assessReadbacks(x.me,x.status,x.policy).fourClientsReadyForInteractiveLogin,false);});
