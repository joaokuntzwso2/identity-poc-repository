import test from 'node:test';
import assert from 'node:assert/strict';
import { totpPolicy, beginApprovalChallenge, verifyApprovalResponse, StepUpDenied } from '../src/approval-stepup-p010.js';
const policy=totpPolicy({WSO2_TOTP_STEPUP_ACR:'urn:ciam:totp:loa2',WSO2_TOTP_STEPUP_AMR:'totp'});
const caseId='123e4567-e89b-42d3-a456-426614174000';
const client={brand:'aurora',clientId:'aurora-web-test',redirectUri:'http://127.0.0.1/auth/aurora-web/callback',issuer:'https://idp.example/t/aurora.identity.test/oauth2/token',scope:'openid'};
function setup(now=1800000000000){
 const session={id:'opaque-cookie-hash',pending:{},logins:{'aurora-web':{verified:true,claims:{iss:client.issuer,sub:'seller-1'}}}};
 const doc={authorization_endpoint:'https://idp.example/oauth2/authorize'};
 const started=beginApprovalChallenge({session,key:'aurora-web',brand:'aurora',caseId,client,discovery:doc,policy,now});
 const url=new URL(started.authorizationUrl); const pending=session.pending[url.searchParams.get('state')];
 const claims={iss:client.issuer,sub:'seller-1',aud:client.clientId,acr:policy.acr,amr:['BasicAuthenticator','totp'],auth_time:1800000000,iat:1800000000,exp:1800000300};
 return {session,pending,url,claims};
}
test('approval uses PKCE S256, nonce, new state and explicit WSO2 reauthentication',()=>{
 const {url,pending}=setup();
 assert.equal(url.searchParams.get('code_challenge_method'),'S256');
 assert.equal(url.searchParams.get('max_age'),'0');
 assert.equal(url.searchParams.get('acr_values'),policy.acr);
 assert.equal(url.searchParams.get('prompt'),'login');
 assert.equal(url.searchParams.get('nonce'),pending.nonce);
 assert.equal(url.searchParams.get('redirect_uri'),client.redirectUri);
});
test('accepts fresh signed-claim semantics for same client/subject/target',()=>{
 const x=setup();
 assert.deepEqual(verifyApprovalResponse({session:x.session,pending:x.pending,key:'aurora-web',client,claims:x.claims,policy,now:1800000001100}).caseId,caseId);
});
test('cannot use ordinary login MFA without transaction',()=>{
 const x=setup(); x.pending.kind='normal-login';
 assert.throws(()=>verifyApprovalResponse({session:x.session,pending:x.pending,key:'aurora-web',client,claims:x.claims,policy,now:1800000001000}),StepUpDenied);
});
test('bad subject, client, issuer, session and target fail closed',()=>{
 for(const field of ['sub','iss','aud']){
   const x=setup(); x.claims[field]='other';
   assert.throws(()=>verifyApprovalResponse({session:x.session,pending:x.pending,key:'aurora-web',client,claims:x.claims,policy,now:1800000001100}));
 }
 for(const change of [x=>x.session.id='other',x=>x.pending.caseId='wrong',x=>x.pending.key='brisa-web']){
  const x=setup();change(x);
  assert.throws(()=>verifyApprovalResponse({session:x.session,pending:x.pending,key:'aurora-web',client,claims:x.claims,policy,now:1800000001100}));
 }
});
test('requesting acr does not prove TOTP; exact verified ACR+AMR+auth_time required',()=>{
 for(const change of [x=>delete x.claims.amr,x=>x.claims.amr=['BasicAuthenticator'],
   x=>x.claims.amr=['sms'],x=>x.claims.acr='urn:weak',
   x=>x.claims.auth_time=1799999600,x=>delete x.claims.auth_time,
   x=>x.claims.iat=1799999600]){
  const x=setup();change(x);
  assert.throws(()=>verifyApprovalResponse({session:x.session,pending:x.pending,key:'aurora-web',client,claims:x.claims,policy,now:1800000001100}));
 }
});
test('expired challenge and future auth_time denied',()=>{
 const x=setup();assert.throws(()=>verifyApprovalResponse({session:x.session,pending:x.pending,key:'aurora-web',client,claims:x.claims,policy,now:1800000310000}));
 const y=setup();y.claims.auth_time=1800000400;
 assert.throws(()=>verifyApprovalResponse({session:y.session,pending:y.pending,key:'aurora-web',client,claims:y.claims,policy,now:1800000001000}));
});
test('missing WSO2 assurance mapping refuses to start',()=>{
 assert.throws(()=>totpPolicy({}),/wso2_totp_assurance_mapping_not_configured/);
 assert.throws(()=>totpPolicy({WSO2_TOTP_STEPUP_ACR:'stuff',WSO2_TOTP_STEPUP_AMR:'not safe value'}));
});
test('second concurrent approval challenge refused without changing first transaction',()=>{
 const x=setup();assert.throws(()=>beginApprovalChallenge({session:x.session,key:'aurora-web',brand:'aurora',caseId,client,discovery:{authorization_endpoint:'https://idp.example/oauth2/authorize'},policy,now:1800000000000}),/approval_challenge_already_pending/);
});

test('MFA auth_time from even the same second before step-up start is stale',()=>{
 const x=setup(1800000000500);
 assert.throws(()=>verifyApprovalResponse({session:x.session,pending:x.pending,key:'aurora-web',client,claims:x.claims,policy,now:1800000001600}),/fresh_wso2_totp_not_attested/);
});
