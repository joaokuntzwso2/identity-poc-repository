import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {sectorUris,assertSectorDocuments,documents} from '../scripts/wso2/sector.mjs';

const env={
  DEMO_AURORA_SECTOR_BASE_URL:'https://aurora-sector.identity.test',
  DEMO_BRISA_SECTOR_BASE_URL:'https://brisa-sector.identity.test'
};
const plan={apps:[
  {brand:'aurora',key:'AURORA_WEB',callback:'http://127.0.0.1:4100/callback'},
  {brand:'aurora',key:'AURORA_MOBILE',callback:'http://127.0.0.1:4101/callback'},
  {brand:'brisa',key:'BRISA_WEB',callback:'http://127.0.0.1:4102/callback'},
  {brand:'brisa',key:'BRISA_MOBILE',callback:'http://127.0.0.1:4103/callback'}
]};

test('the real sector URL generator matches exact sidecar paths',()=>{
  const urls=sectorUris(env);
  assert.deepEqual(urls,{
    aurora:'https://aurora-sector.identity.test/sector.json',
    brisa:'https://brisa-sector.identity.test/sector.json'
  });
  assert.notEqual(new URL(urls.aurora).hostname,new URL(urls.brisa).hostname);
});

test('bridge and Nginx sidecar expect the same immutable /sector.json path',()=>{
  const root=resolve(import.meta.dirname,'..');
  const bridge=readFileSync(resolve(root,'scripts/wso2/bootstrap-tenant-control-plane.mjs'),'utf8');
  const sidecar=readFileSync(resolve(root,'scripts/wso2/sector-sidecar-bootstrap.py'),'utf8');
  assert.match(bridge,/u\.pathname!=='\/sector\.json'/);
  assert.match(bridge,/path:'\/sector\.json'/);
  assert.match(sidecar,/location = \/sector\.json \{/);
  for(const uri of Object.values(sectorUris(env))){
    assert.equal(new URL(uri).pathname,'/sector.json');
    assert.equal(new URL(uri).protocol,'https:');
  }
});

test('sector document preflight uses the real generated paths and exact callback arrays',async()=>{
  const urls=sectorUris(env);
  const lists=documents(plan);
  const seen=[];
  await assertSectorDocuments(plan,env,async url=>{
    seen.push(url);
    const brand=url===urls.aurora?'aurora':url===urls.brisa?'brisa':null;
    assert.ok(brand,'unapproved sector document URL');
    return new Response(JSON.stringify(lists[brand]),{status:200});
  });
  assert.deepEqual(seen,[urls.aurora,urls.brisa]);
});

test('a wrong sector callback list cannot pass readback verification',async()=>{
  await assert.rejects(assertSectorDocuments(plan,env,async()=>new Response('[]',{status:200})),
    /SECTOR_REDIRECT_MISMATCH_/);
});

test('distinct paths on a shared hostname are not sufficient for pairwise sectors',()=>{
  assert.throws(()=>sectorUris({...env,DEMO_BRISA_SECTOR_BASE_URL:env.DEMO_AURORA_SECTOR_BASE_URL}),
    /SECTOR_HOSTS_MUST_DIFFER_NOT_ONLY_PATHS/);
});
