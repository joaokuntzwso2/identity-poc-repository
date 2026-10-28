import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { handleCases } from '../services/identity-bff/src/live-cases-v4.js';

const tmp=mkdtempSync(join(tmpdir(),'ciampoc-case-'));
process.env.CIAM_BUSINESS_DATA_DIR=tmp;
const clients={'aurora-web':{brand:'aurora',issuer:'https://issuer/aurora'},'brisa-web':{brand:'brisa',issuer:'https://issuer/brisa'}};
const alice={logins:{'aurora-web':{verified:true,claims:{iss:'https://issuer/aurora',sub:'a'}}},csrf:'csrf'};
const seller={logins:{'aurora-web':{verified:true,claims:{iss:'https://issuer/aurora',sub:'s',amr:['BasicAuthenticator','totp'],auth_time:Math.floor(Date.now()/1000)}}},csrf:'csrf'};
function request(url,method='GET',data){
 const r=Readable.from(data ? [JSON.stringify(data)]: []);
 r.method=method;r.headers={'origin':'http://localhost','x-csrf-token':'csrf','content-type':'application/json'};return [r,new URL(url,'http://localhost')];
}
function response(){let status,body;return {writeHead(c){status=c},end(text){body=JSON.parse(text)},get result(){return {status,body}}};}
async function invoke(url,session,scopes,method='GET',data){
 const [req,u]=request(url,method,data),res=response();
 await handleCases(req,res,u,session,{clients,
  authorize:async(_s,_k,scope)=>scopes.includes(scope)?{http:200}:{http:403,reason:'wso2_scope_denied'},
  sameOrigin:()=>true,safeCsrf:()=>true});
 return res.result;
}
test('cross-brand mismatch denied before authority',async()=>{
 assert.equal((await invoke('/api/brands/brisa/cases?client=aurora-web',alice,[])).status,403);
});
test('no WSO2 scope means denial',async()=>{
 assert.equal((await invoke('/api/brands/aurora/cases?client=aurora-web',alice,[])).status,403);
});
test('real persistent request, owner isolation, and distinct approver',async()=>{
 const u='/api/brands/aurora/cases?client=aurora-web';
 const opened=await invoke(u,alice,['ciam:cases:create'],'POST',{title:'Support request',description:'Please contact me'});
 assert.equal(opened.status,201);
 assert.equal((await invoke(u,seller,['ciam:cases:read'])).body.records.length,0);
 assert.equal((await invoke(u,alice,['ciam:cases:read'])).body.records.length,1);
 const a=`/api/brands/aurora/cases/${opened.body.id}/approve?client=aurora-web`;
 assert.equal((await invoke(a,alice,['ciam:cases:approve'],'POST')).status,403);
 assert.equal((await invoke(a,{...seller,logins:{'aurora-web':{verified:true,claims:{iss:'https://issuer/aurora',sub:'s'}}}},['ciam:cases:approve'],'POST')).body.error,'fresh_wso2_totp_required');
 assert.equal((await invoke(a,seller,['ciam:cases:approve'],'POST')).status,200);
 assert.equal((await invoke(u,seller,['ciam:cases:read','ciam:cases:review'])).body.records[0].status,'APPROVED');
 assert.equal((await invoke(a,seller,['ciam:cases:approve'],'POST')).status,409);
});
test.after(()=>rmSync(tmp,{recursive:true,force:true}));
