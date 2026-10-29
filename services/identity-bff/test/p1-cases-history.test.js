// Contract tests for authoritative WSO2-gated BFF business record persistence.
// The authorization function here is a unit-test double ONLY. Live WSO2 remains mandatory in deployment.
import test from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { handleCases } from '../src/live-cases-v4.js';

const issuer='https://identity.example/t/aurora.identity.test/oauth2/token';
const clients={
  'aurora-web':{brand:'aurora',issuer},
  'brisa-web':{brand:'brisa',issuer:'https://identity.example/t/brisa.identity.test/oauth2/token'}
};
function user(sub,permissions){return {logins:{'aurora-web':{verified:true,claims:{iss:issuer,sub}}},permissions,csrf:'example'};}
async function call(path,method,session,payload,config={}){
  const u=new URL(`https://demo.test${path}`);
  const req=Readable.from(method==='POST'?[JSON.stringify(payload??{})]:[]);
  req.method=method;
  req.headers={'content-type':'application/json','origin':'https://demo.test','x-csrf-token':'example'};
  let status, result;
  const res={writeHead(value){status=value;},end(value){result=JSON.parse(value);}};
  const handled=await handleCases(req,res,u,session,{
    clients,
    authorize:async(s,_client,scope)=>s.permissions.includes(scope)?{http:200}:{http:403,reason:'scope_denied'},
    sameOrigin:()=>config.allowOrigin!==false,
    safeCsrf:()=>config.allowCsrf!==false,
    beginApproval:async()=>{throw Error('Approval challenge must not be used in these create/read contract tests');}
  });
  assert.equal(handled,true);
  return {status,result};
}

test('durable records: customer ownership, seller review, history and negative gates',async()=>{
  const previous=process.env.CIAM_BUSINESS_DATA_DIR;
  const dir=mkdtempSync(join(tmpdir(),'ciam-p113-'));
  process.env.CIAM_BUSINESS_DATA_DIR=dir;
  const customer=user('customer-one',['ciam:cases:create','ciam:cases:read']);
  const seller=user('seller-one',['ciam:cases:read','ciam:cases:review','ciam:cases:approve']);
  const other=user('customer-two',['ciam:cases:read']);
  const url='/api/brands/aurora/cases?client=aurora-web';
  try {
    const created=await call(url,'POST',customer,{title:'Atendimento de produto',description:'Quero acompanhar a solicitação'});
    assert.equal(created.status,201);assert.equal(created.result.persistent,true);
    const own=await call(url,'GET',customer);
    assert.equal(own.status,200);assert.equal(own.result.visibility,'OWNER_ONLY');
    assert.equal(own.result.records.length,1);
    assert.deepEqual(own.result.records[0].history.map(e=>e.action),['created']);
    assert.equal(own.result.records[0].id,created.result.id);
    assert.equal(Object.hasOwn(own.result.records[0],'owner'),false);
    assert.equal((await call(url,'GET',other)).result.records.length,0);
    const queue=await call(url,'GET',seller);
    assert.equal(queue.status,200);assert.equal(queue.result.visibility,'BRAND_REVIEW');
    assert.equal(queue.result.records.length,1);
    assert.equal((await call(url,'POST',customer,{title:'x',description:''})).status,400);
    assert.equal((await call(url,'POST',customer,{title:'valid',description:''},{allowOrigin:false})).status,403);
    assert.equal((await call(url,'POST',customer,{title:'valid',description:''},{allowCsrf:false})).status,403);
    assert.equal((await call('/api/brands/brisa/cases?client=aurora-web','GET',customer)).status,403);
    assert.equal((await call(url,'GET',user('unknown',[]))).status,403);
  }finally{
    if(previous===undefined)delete process.env.CIAM_BUSINESS_DATA_DIR;
    else process.env.CIAM_BUSINESS_DATA_DIR=previous;
    rmSync(dir,{recursive:true,force:true});
  }
});
