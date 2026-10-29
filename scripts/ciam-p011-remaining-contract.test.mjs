import test from 'node:test';
import assert from 'node:assert/strict';
import {browserScenario,validateUrl,acceptedAuthCallbackError} from './ciam-p011-remaining-contract.mjs';
const base='http://127.0.0.1:4400';
const state='SOME_REAL_STATE';
test('only implemented real browser scenarios are accepted',()=>{
 for(const x of ['canceled-mfa','self-approval','expired-session','expired-stepup-transaction'])assert.equal(browserScenario(x),true);
 for(const x of ['outage','revocation','sso-logout','stale-signed-mfa','../../bad'])assert.equal(browserScenario(x),false);
});
test('BFF and WSO2 destinations pinned',()=>{
 assert.equal(validateUrl(base),true);
 for(const x of ['http://localhost:4400','http://127.0.0.1:4401','https://127.0.0.1:4400',base+'/api'])assert.equal(validateUrl(x),false);
 assert.equal(validateUrl('https://localhost:9444/oauth2/authorize',{wso2:true}),true);
 for(const x of ['https://evil.test:9444/oauth2/authorize','http://localhost:9444/oauth2/authorize','https://localhost:9444@evil.test','https://localhost:9443/'])assert.equal(validateUrl(x,{wso2:true}),false);
});
test('real access_denied callback required; no code/state persisted',()=>{
 assert.equal(acceptedAuthCallbackError(base+'/auth/aurora-web/callback?state=SOME_REAL_STATE&error=access_denied',base,state),true);
 for(const x of [base+'/auth/aurora-web/callback?state=SOME_REAL_STATE&error=server_error',base+'/auth/aurora-web/callback?error=access_denied',base+'/auth/aurora-web/callback?state=SOME_REAL_STATE&code=c&error=access_denied','https://evil.test/auth/aurora-web/callback?state=SOME_REAL_STATE&error=access_denied',base+'/auth/aurora-web/callback?state=WRONG_STATE&error=access_denied'])assert.equal(acceptedAuthCallbackError(x,base,state),false);
});
