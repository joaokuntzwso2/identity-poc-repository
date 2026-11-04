import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { run } from '../../scripts/p2/partner_io_v13.mjs';

const root='11111111-1111-4111-8111-111111111111';
const child='22222222-2222-4222-8222-222222222222';
const expectedRootFp=createHash('sha256').update(root).digest('hex').slice(0,16);
const viewToken='v'.repeat(30), creatorToken='c'.repeat(30);
const name='Aurora Returns & Fulfillment Partner';
const handle='aurora-returns-fulfillment';
const ORG='/t/aurora.identity.test/o/api/server/v1/organizations';
const approval='P2_V13_AURORA_RETURNS_ONE_CREATE_APPROVED';
const rootDoc={id:root,type:'TENANT',orgHandle:'aurora.identity.test',hasChildren:false};
const childDoc={id:child,name,orgHandle:handle,status:'ACTIVE',parent:{id:root}};
function fake({badParent=false, badBody=false, status=201}={}) {
  const calls=[];
  const fetcher=async (url, opts) => {
    const p=new URL(url).pathname;
    calls.push({path:p,method:opts.method,auth:opts.headers.authorization,body:opts.body});
    let doc={};let s=200;
    if(p===ORG+'/metadata') doc=rootDoc;
    else if(p===ORG && opts.method==='GET') doc={links:[]};
    else if(p===ORG && opts.method==='POST') {
      s=status;
      doc=badBody?{}:{id:child};
    } else if(p===ORG+'/'+child) doc={...childDoc,parent:{id:badParent? '33333333-3333-4333-8333-333333333333': root}};
    else throw new Error('unexpected request');
    return {status:s,text:async()=>JSON.stringify(doc)};
  };
  return {fetcher,calls};
}
const withRoot={rootId:root,viewToken};

test('read-only plan uses view bearer and cannot POST',async()=>{
  const {fetcher,calls}=fake();
  const result=await run({...withRoot,mode:'plan'},{fetcher,expectedRootFp});
  assert.equal(result.action,'CREATE');
  assert.equal(calls.some(c=>c.method==='POST'),false);
  assert.ok(calls.every(c=>c.auth==='Bearer '+viewToken));
});
test('approved creation uses creator bearer only for one org POST',async()=>{
  const {fetcher,calls}=fake();
  let intents=0;
  const result=await run({...withRoot,mode:'create',creatorToken,approval},
     {fetcher,expectedRootFp,checkIntent:async()=>{intents++}});
  assert.equal(result.action,'CREATED_AND_VERIFIED');
  assert.equal(result.id,child);assert.equal(intents,1);
  const writes=calls.filter(c=>c.method==='POST');
  assert.equal(writes.length,1);
  assert.equal(writes[0].auth,'Bearer '+creatorToken);
  assert.equal(JSON.parse(writes[0].body).parentId,root);
  assert.ok(calls.filter(c=>c.method==='GET').every(c=>c.auth==='Bearer '+viewToken));
});
test('missing create approval fails before request',async()=>{
  const {fetcher,calls}=fake();
  await assert.rejects(run({...withRoot,mode:'create',creatorToken,approval:'wrong'},
    {fetcher,expectedRootFp}),/V13_CREATE_REQUIRES_APPROVED_BOOTSTRAP/);
  assert.equal(calls.length,0);
});
test('foreign root fingerprint blocks before request',async()=>{
  const {fetcher,calls}=fake();
  await assert.rejects(run({...withRoot,mode:'plan'},{fetcher}),/V13_ROOT_PIN_MISMATCH/);
  assert.equal(calls.length,0);
});
test('creation with unverified child parent fails and no duplicate POST',async()=>{
  const {fetcher,calls}=fake({badParent:true});
  await assert.rejects(run({...withRoot,mode:'create',creatorToken,approval},
    {fetcher,expectedRootFp,checkIntent:async()=>{}}),/PARTNER_ORGANIZATION_READBACK_MISMATCH/);
  assert.equal(calls.filter(c=>c.method==='POST').length,1);
});
test('201 response without id fails safely; no repeated POST',async()=>{
  const {fetcher,calls}=fake({badBody:true});
  await assert.rejects(run({...withRoot,mode:'create',creatorToken,approval},
    {fetcher,expectedRootFp,checkIntent:async()=>{}}),/ORG_CREATE_ID_MISSING_NO_RETRY/);
  assert.equal(calls.filter(c=>c.method==='POST').length,1);
});
test('unexpected create HTTP status is not accepted',async()=>{
  const {fetcher,calls}=fake({status:200});
  await assert.rejects(run({...withRoot,mode:'create',creatorToken,approval},
    {fetcher,expectedRootFp,checkIntent:async()=>{}}),/ORG_CREATE_OUTCOME_UNCERTAIN_HTTP_200/);
  assert.equal(calls.filter(c=>c.method==='POST').length,1);
});
test('readback checks partner parent; no writes',async()=>{
  const {fetcher,calls}=fake();
  const r=await run({...withRoot,mode:'verify',partnerId:child},{fetcher,expectedRootFp});
  assert.equal(r.action,'EXACT_CHILD_VERIFIED');
  assert.equal(calls.filter(c=>c.method==='POST').length,0);
});
test('wrong parent in readback is rejected',async()=>{
  const {fetcher}=fake({badParent:true});
  await assert.rejects(run({...withRoot,mode:'verify',partnerId:child},
    {fetcher,expectedRootFp}),/V13_CHILD_READBACK_MISMATCH/);
});
test('reconcile performs GET only',async()=>{
  const {fetcher,calls}=fake();
  const r=await run({...withRoot,mode:'reconcile'},{fetcher,expectedRootFp});
  assert.equal(r.action,'CREATE');assert.equal(calls.filter(c=>c.method==='POST').length,0);
});
test('invalid creator token refuses create before request',async()=>{
  const {fetcher,calls}=fake();
  await assert.rejects(run({...withRoot,mode:'create',creatorToken:'x',approval},
    {fetcher,expectedRootFp}),/V13_PRIVATE_TOKEN_INVALID/);
  assert.equal(calls.length,0);
});
