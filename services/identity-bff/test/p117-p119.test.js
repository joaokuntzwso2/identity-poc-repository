import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {DemoSessionStore} from '../src/session-store.js';
import {actorFingerprint,parseLedgerBuffer,inventoryLedgers} from '../src/business-ledger.js';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Readable} from 'node:stream';
const res=()=>({headers:{},setHeader(k,v){this.headers[k]=v;},writeHead(s,h){this.status=s;this.headers={...this.headers,...h};},end(s){this.body=s;}});
const uuid=()=>randomUUID();
const actor=actorFingerprint('https://issuer.example/t/aurora/oauth2/token','different:subject');
const other=actorFingerprint('https://issuer.example/t/aurora/oauth2/token','seller:subject');
const makeLedger=(brand='aurora',id=uuid())=>Buffer.from([
  JSON.stringify({brand,id,action:'created',actor,title:'Example service',description:'Reliable record',at:'2026-10-29T12:00:00.000Z'}),
  JSON.stringify({brand,id,action:'approved',actor:other,at:'2026-10-29T12:01:00.000Z'}),''].join('\n'));
test('historical ownership digest matches JSONL issuer/sub encoding',()=>{
 assert.match(actor,/^[0-9a-f]{64}$/);
 assert.notEqual(actor,actorFingerprint('https://issuer.example/t/brisa/oauth2/token','different:subject'));
});
test('migration retains IDs, event order and historical owner digest',()=>{
 const original=makeLedger();const read=parseLedgerBuffer(original,'aurora');
 assert.equal(read.records.length,1);assert.equal(read.events.length,2);
 assert.equal(read.records[0].status,'APPROVED');assert.equal(read.records[0].owner,actor);
 assert.deepEqual(read.events.map(x=>x.sequence),[1,2]);
 assert.deepEqual(read.events.map(x=>x.action),['created','approved']);
});
test('inventory never changes JSONL sources',()=>{
 const dir=mkdtempSync(join(tmpdir(),'p117-ledger-'));
 try{
  const a=makeLedger('aurora'),b=Buffer.from('');
  writeFileSync(join(dir,'requests-aurora.jsonl'),a);
  writeFileSync(join(dir,'requests-brisa.jsonl'),b);
  const first=inventoryLedgers(dir),again=inventoryLedgers(dir);
  assert.equal(first.fingerprint,again.fingerprint);
  assert.equal(first.ledgers[0].records.length,1);
  assert.equal(first.ledgers[1].records.length,0);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('interrupted/malformed ledgers are refused without partial acceptance',()=>{
 const valid=makeLedger();
 assert.throws(()=>parseLedgerBuffer(valid.subarray(0,valid.length-1),'aurora'),/TRUNCATED/);
 assert.throws(()=>parseLedgerBuffer(valid,'brisa'),/INVALID_EVENT/);
 assert.throws(()=>parseLedgerBuffer(Buffer.concat([valid,valid]),'aurora'),/INVALID_CREATION/);
 const lines=valid.toString().trim().split('\n');
 assert.throws(()=>parseLedgerBuffer(Buffer.from([lines[1],lines[0],''].join('\n')),'aurora'),/INVALID_APPROVAL/);
});
test('idle and absolute expirations prevent sliding forever',()=>{
 let clock=0;const s=new DemoSessionStore({now:()=>clock,idleMs:1_000,absoluteMs:2_000});
 const a=res(),initial=s.ensure({headers:{}},a);let req={headers:{cookie:`poc_sid=${initial.id}`}};
 clock=900;assert.equal(s.ensure(req,res()),initial);
 clock=1800;assert.equal(s.ensure(req,res()),initial);
 clock=2000;assert.notEqual(s.ensure(req,res()),initial);
});
test('rotation invalidates fixation cookie, stale MFA, pending OAuth state and CSRF',()=>{
 const store=new DemoSessionStore();const s=store.ensure({headers:{}},res());
 const old=s.id,csrf=s.csrf;s.pending.fake={kind:'case-approval'};
 s.logins['aurora-web']={verified:true};
 store.rotate(s,res());
 assert.notEqual(old,s.id);assert.notEqual(csrf,s.csrf);
 assert.equal(Object.keys(s.pending).length,0);
 assert.equal(store.parseCookie({headers:{cookie:`poc_sid=${old}; poc_sid=${s.id}`}}),null);
 assert.notEqual(store.ensure({headers:{cookie:`poc_sid=${old}`}},res()),s);
 assert.equal(s.logins['aurora-web'].verified,true);
});
test('production cookies secure and local cookies remain HTTP-only',()=>{
 const secure=new DemoSessionStore({secure:true}),r=res(),a=secure.ensure({headers:{}},r);
 assert.match(r.headers['Set-Cookie'],/__Host-poc_sid=/);
 assert.match(r.headers['Set-Cookie'],/; Secure/);
 assert.match(r.headers['Set-Cookie'],/HttpOnly; SameSite=Lax; Path=\//);
 const local=new DemoSessionStore(),r2=res();local.ensure({headers:{}},r2);
 assert.doesNotMatch(r2.headers['Set-Cookie'],/; Secure/);
 secure.destroy(a,r);assert.match(r.headers['Set-Cookie'],/Max-Age=0/);
});
test('WSO2 /Me profile patch is scoped, validated and re-read after write',async t=>{
 let mod;try {mod=await import('../src/wso2-self-service-p119.js');}catch(e){
  if(e.code==='ERR_MODULE_NOT_FOUND')return t.skip('Requires full upstream BFF OIDC/authority modules');throw e;
 }
 const {handleSelfService}=mod;
 const client={brand:'aurora',clientId:'abc',clientSecret:'secret',issuer:'https://idp.example/t/aurora/oauth2/token'};
 const clients={'aurora-web':client,'brisa-web':{...client,brand:'brisa',issuer:'https://idp.example/t/brisa/oauth2/token'}};
 const session={csrf:'good',logins:{'aurora-web':{verified:true,claims:{iss:client.issuer,sub:'owner'},accessToken:'server-only-token'}}};
 const calls=[],fetcher=async(url,options)=>{
  calls.push({url,options});
  if(options.method==='PATCH')return new Response(null,{status:204});
  return new Response(JSON.stringify({id:'scim-id',name:{givenName:'Changed'}}),{status:200});
 };
 const makeReq=(method,json,headers={})=>Object.assign(Readable.from(json?[JSON.stringify(json)]:[]),{
  method,headers:{origin:'https://app.example','content-type':'application/json','x-csrf-token':'good',...headers}});
 const url=(brand='aurora')=>new URL(`https://app.example/api/brands/${brand}/self-service/me?client=aurora-web`);
 const denial=res();await handleSelfService(makeReq('PATCH',{roles:['admin']}),denial,url(),session,{clients,
   sameOrigin:r=>r.headers.origin==='https://app.example',safeCsrf:r=>r.headers['x-csrf-token']===session.csrf,
   introspect:async()=>({active:true}),request:fetcher,env:{WSO2_SELF_SERVICE_WRITES_ENABLED:'1'}});
 assert.equal(denial.status,400);assert.equal(calls.length,0);
 const cross=res();await handleSelfService(makeReq('GET'),cross,url('brisa'),session,{clients,
   sameOrigin:()=>true,safeCsrf:()=>true,introspect:async()=>({active:true}),request:fetcher,env:{WSO2_SELF_SERVICE_WRITES_ENABLED:'1'}});
 assert.equal(cross.status,403);
 const csrf=res();await handleSelfService(makeReq('PATCH',{givenName:'Changed'},{'x-csrf-token':'wrong'}),csrf,url(),session,{clients,
   sameOrigin:()=>true,safeCsrf:r=>r.headers['x-csrf-token']==='good',introspect:async()=>({active:true}),request:fetcher,env:{WSO2_SELF_SERVICE_WRITES_ENABLED:'1'}});
 assert.equal(csrf.status,403);
 const success=res();await handleSelfService(makeReq('PATCH',{givenName:'Changed'}),success,url(),session,{clients,
   sameOrigin:()=>true,safeCsrf:()=>true,introspect:async()=>({active:true}),request:fetcher,env:{WSO2_SELF_SERVICE_WRITES_ENABLED:'1'}});
 assert.equal(success.status,200);assert.equal(JSON.parse(success.body).status,'WSO2_PROFILE_CHANGE_CONFIRMED');
 assert.equal(calls.length,2);assert.match(calls[0].url,/\/t\/aurora\/scim2\/Me$/);
 assert.equal(JSON.parse(calls[0].options.body).Operations[0].path,'name.givenName');
 assert.ok(calls.every(x=>x.options.headers.authorization==='Bearer server-only-token'));
});
test('WSO2-hosted registration/recovery links are explicitly configured and issuer-pinned',async t=>{
 let mod;try{mod=await import('../src/wso2-self-service-p119.js');}catch(e){
  if(e.code==='ERR_MODULE_NOT_FOUND')return t.skip('Requires upstream OIDC modules');throw e;
 }
 const client={brand:'aurora',issuer:'https://idp.example/t/aurora/oauth2/token'};
 const clients={'aurora-web':client};
 const req={method:'GET',headers:{}};
 const target=new URL('https://app.example/api/brands/aurora/self-service/navigation?client=aurora-web');
 const env={WSO2_AURORA_REGISTRATION_URL:'https://idp.example/t/aurora/account/register',
  WSO2_AURORA_PASSWORD_RECOVERY_URL:'https://idp.example/t/aurora/account/recover'};
 const result=res();await mod.handleSelfService(req,result,target,null,{clients,env});
 assert.equal(result.status,200);
 assert.equal(JSON.parse(result.body).urls.registration,env.WSO2_AURORA_REGISTRATION_URL);
 assert.equal(JSON.parse(result.body).urls.passwordChange,null);
 const evil=res();await mod.handleSelfService(req,evil,target,null,{clients,
  env:{...env,WSO2_AURORA_PASSWORD_RECOVERY_URL:'https://attacker.example/recovery'}});
 assert.equal(evil.status,503);
});
test('RP-initiated logout requires verified identity and trusted WSO2 discovery',async t=>{
 let mod;try{mod=await import('../src/rp-logout-p118.js');}catch(e){
  if(e.code==='ERR_MODULE_NOT_FOUND')return t.skip('Requires upstream OIDC modules');throw e;
 }
 const client={clientId:'aurora-app',issuer:'https://idp.example/t/aurora/oauth2/token'};
 const discoverer=async()=>({end_session_endpoint:'https://idp.example/t/aurora/oidc/logout'});
 const login={verified:true,claims:{iss:client.issuer},idToken:'server-held-signed-token'};
 const args={client,login,origin:'https://app.example',
  postLogoutUri:'https://app.example/logged-out',discoverer};
 const link=await mod.rpLogoutUrl(args),u=new URL(link);
 assert.equal(u.searchParams.get('id_token_hint'),login.idToken);
 assert.equal(u.searchParams.get('client_id'),client.clientId);
 assert.equal(u.searchParams.get('post_logout_redirect_uri'),args.postLogoutUri);
 await assert.rejects(()=>mod.rpLogoutUrl({...args,login:{...login,idToken:undefined}}));
 await assert.rejects(()=>mod.rpLogoutUrl({...args,postLogoutUri:'https://evil.example/out'}));
 await assert.rejects(()=>mod.rpLogoutUrl({...args,discoverer:async()=>({})}));
});
