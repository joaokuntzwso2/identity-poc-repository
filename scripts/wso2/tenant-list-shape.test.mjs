import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Isolate the production parser without importing/bootstrap-executing the module.
const here=dirname(fileURLToPath(import.meta.url));
const source=readFileSync(join(here,'tenant-brand-bootstrap.mjs'),'utf8');
const match=source.match(/^function tenantList\(data\)\{[\s\S]*?^\}/m);
assert.ok(match, 'production tenantList() function must be present');
const tenantList=runInNewContext(`${match[0]}\ntenantList`, Object.create(null), {timeout: 1000});
const empty={count:0,links:[],startIndex:1,totalResults:0};

// Captured LIVE shape: these four keys, no tenants. Counter values are a
// candidate fixture until confirmed by the pagination-only diagnostic.
test('7.3 empty-list omission is accepted with zero counts',()=>{
 assert.equal(JSON.stringify(tenantList(empty)),'[]');
});
test('empty-list omission also tolerates zero-based startIndex',()=>{
 assert.equal(JSON.stringify(tenantList({...empty,startIndex:0})),'[]');
});
test('documented tenant list still works',()=>{
 const data={totalResults:1,startIndex:1,count:1,links:[],tenants:[{domain:'example.invalid'}]};
 assert.equal(tenantList(data)[0].domain,'example.invalid');
});
test('existing top-level array compatibility is preserved',()=>{
 assert.equal(tenantList([{domain:'example.invalid'}]).length,1);
});
test('missing tenants with nonzero total is rejected',()=>{
 assert.throws(()=>tenantList({...empty,totalResults:1}),/TENANT_LIST_RESPONSE_SHAPE_UNRECOGNIZED/);
});
test('missing tenants with nonzero count is rejected',()=>{
 assert.throws(()=>tenantList({...empty,count:1}),/TENANT_LIST_RESPONSE_SHAPE_UNRECOGNIZED/);
});
test('missing tenants with invalid pagination is rejected',()=>{
 for(const bad of [{...empty,count:'0'},{...empty,startIndex:'1'},
  {...empty,links:null},{...empty,links:[{rel:'next'}]},
  {...empty,traceId:'unexpected'},{...empty,tenants:null},
  {count:0,links:[],startIndex:1},{}]){
  assert.throws(()=>tenantList(bad),/TENANT_LIST_RESPONSE_SHAPE_UNRECOGNIZED/);
 }
});
