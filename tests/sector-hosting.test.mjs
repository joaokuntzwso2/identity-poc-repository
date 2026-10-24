import test from 'node:test';
import assert from 'node:assert/strict';
import {assertPlan} from '../scripts/wso2/tenant-brand-clients.mjs';
import {sectorSidecarFetch} from '../scripts/wso2/bootstrap-tenant-control-plane.mjs';
const domains={aurora:'aurora.identity.test',brisa:'brisa.identity.test'};
const sectors={aurora:'https://aurora-sector.identity.test/sector.json',brisa:'https://brisa-sector.identity.test/sector.json'};
const plan=(url='http://127.0.0.1:4100/callback')=>({apps:[
  {key:'AURORA_WEB',name:'Aurora Web',brand:'aurora',callback:url},
  {key:'AURORA_MOBILE',name:'Aurora Mobile',brand:'aurora',callback:'http://127.0.0.1:4101/callback'},
  {key:'BRISA_WEB',name:'Brisa Web',brand:'brisa',callback:'http://127.0.0.1:4102/callback'},
  {key:'BRISA_MOBILE',name:'Brisa Mobile',brand:'brisa',callback:'http://127.0.0.1:4103/callback'}
]});
test('local HTTP callbacks rejected unless explicit loopback exception',()=>{
  const before=process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS;
  delete process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS;
  try{assert.throws(()=>assertPlan(plan(),domains,sectors),/INVALID_BRAND_HTTPS_CALLBACK/)}
  finally{if(before===undefined)delete process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS;else process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS=before;}
});
test('explicit local mode permits only IP literal 127.0.0.1',()=>{
  const before=process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS;
  process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS='allow-loopback-v1';
  try{
    assert.equal(assertPlan(plan(),domains,sectors).length,4);
    assert.throws(()=>assertPlan(plan('http://192.168.1.1:4100/callback'),domains,sectors),/INVALID_BRAND_HTTPS_CALLBACK/);
    assert.throws(()=>assertPlan(plan('http://evil.example.test:4100/callback'),domains,sectors),/INVALID_BRAND_HTTPS_CALLBACK/);
    assert.throws(()=>assertPlan(plan('http://127.0.0.1:4100/callback#fragment'),domains,sectors),/INVALID_BRAND_HTTPS_CALLBACK/);
  }finally{if(before===undefined)delete process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS;else process.env.WSO2_LAB_LOCAL_HTTP_CALLBACKS=before;}
});
test('bridge disabled preserves injected fetch unchanged',()=>{
  const fetchImpl=async()=>({ok:true});
  assert.equal(sectorSidecarFetch(fetchImpl,{}),fetchImpl);
});
