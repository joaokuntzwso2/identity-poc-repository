import test from 'node:test';
import assert from 'node:assert/strict';
import { GateError, TENANT, PARTNER, makeTransport, planPartner,
  createPartner, rootMetadata, childMetadata, inventoryChild, disableChildUser } from '../../scripts/p2/guarded-org.mjs';

const ROOT = '11111111-1111-4111-8111-111111111111';
const CHILD = '22222222-2222-4222-8222-222222222222';
const USER = '33333333-3333-4333-8333-333333333333';
const prefix = `/t/${TENANT}/o/api/server/v1/organizations`;
const base = `https://localhost:9444${prefix}`;
const good = { id:CHILD,name:PARTNER.name,orgHandle:PARTNER.orgHandle,status:'ACTIVE',parent:{id:ROOT} };
const callFrom = (handlers, capture = []) => async (method,path,body) => {
  capture.push({method,path,body});
  for (const [predicate,result] of handlers) if (predicate(method,path,body)) return typeof result === 'function' ? result() : result;
  throw Error(`Unexpected ${method} ${path}`);
};
const eq = (method,path) => (m,p) => m === method && (path instanceof RegExp ? path.test(p) : p === path);

test('transport confines all API calls to Aurora tenant and refuses HTTP downgrade', async () => {
  assert.throws(() => makeTransport({origin:'http://localhost:9444/',bearer:'x'.repeat(40)}), GateError);
  const call = makeTransport({origin:'https://localhost:9444/',bearer:'x'.repeat(40),fetcher:async()=>{throw Error('no');}});
  await assert.rejects(call('GET','/t/brisa.identity.test/o/scim2/Users'), /CROSS_TENANT_OR_PATH_DENIED/);
  await assert.rejects(call('GET','/api/server/v1/tenants'), /CROSS_TENANT_OR_PATH_DENIED/);
  await assert.rejects(call('PATCH','/t/aurora.identity.test/o/api/server/v1/organizations/../delete'), /CROSS_TENANT_OR_PATH_DENIED/);
  await assert.rejects(call('GET','/t/aurora.identity.test/o/api/server/v1/organizations/%2e%2e/%2e%2e/%2e%2e/scim2/Users'), /NORMALIZED_PATH_OUTSIDE_AURORA_DENIED/);
});
test('transport sends bearer only to tenant-pinned WSO2 endpoint; strips no redirects', async () => {
  let seen;
  const call = makeTransport({origin:'https://localhost:9444/',bearer:'x'.repeat(40),fetcher:async (url,opts)=>{
    seen={url,opts}; return {status:200,text:async()=>'{"id":"test"}'};
  }});
  const out = await call('GET', prefix + '/metadata');
  assert.equal(out.status,200); assert.equal(seen.url,base+'/metadata');
  assert.equal(seen.opts.headers.authorization,`Bearer ${'x'.repeat(40)}`);
  assert.equal(seen.opts.redirect,'manual');
});
test('root, child mismatch fails closed; only exact expected UUID accepted', () => {
  assert.throws(() => rootMetadata({id:CHILD},ROOT), /ROOT_ORGANIZATION_CONTEXT_MISMATCH/);
  assert.throws(() => childMetadata({id:ROOT,parent:{id:ROOT}},CHILD,ROOT), /CHILD_ORGANIZATION_CONTEXT_MISMATCH/);
  assert.deepEqual(Object.keys(rootMetadata({id:ROOT},ROOT)),['rootFingerprint']);
});
test('absence produces a plan but no POST', async () => {
  const seen=[];
  const call=callFrom([
    [eq('GET',prefix+'/metadata'),{status:200,body:{id:ROOT}}],
    [eq('GET',new RegExp('\\?filter=')),{status:200,body:{organizations:[]}}]
  ],seen);
  assert.equal((await planPartner(call,ROOT)).action,'CREATE');
  assert.deepEqual(seen.map(x=>x.method),['GET','GET']);
});
test('existing exact partner is idempotent; mismatched parent is denied', async () => {
  const handlers = [[eq('GET',prefix+'/metadata'),{status:200,body:{id:ROOT}}],
    [eq('GET',new RegExp('\\?filter=')),{status:200,body:{organizations:[{id:CHILD}]}}]];
  const right=callFrom([...handlers,[eq('GET',prefix+'/'+CHILD),{status:200,body:good}]]);
  assert.equal((await planPartner(right,ROOT)).action,'ALREADY_PRESENT');
  const wrong=callFrom([...handlers,[eq('GET',prefix+'/'+CHILD),{status:200,body:{...good,parent:{id:USER}}}]]);
  await assert.rejects(planPartner(wrong,ROOT),/PARTNER_ORGANIZATION_READBACK_MISMATCH/);
});
test('creation journals before POST, performs immutable readback, no blind retries', async () => {
  const trace=[];
  const call=callFrom([
    [eq('GET',prefix+'/metadata'),{status:200,body:{id:ROOT}}],
    [eq('GET',new RegExp('\\?filter=')),{status:200,body:{organizations:[]}}],
    [eq('POST',prefix),()=>{trace.push('POST');return {status:201,body:{id:CHILD}};}],
    [eq('GET',prefix+'/'+CHILD),{status:200,body:good}]
  ]);
  const r=await createPartner(call,ROOT,async()=>{trace.push('JOURNAL');});
  assert.equal(r.created,true); assert.deepEqual(trace,['JOURNAL','POST']);
  const uncertain=callFrom([
    [eq('GET',prefix+'/metadata'),{status:200,body:{id:ROOT}}],
    [eq('GET',new RegExp('\\?filter=')),{status:200,body:{organizations:[]}}],
    [eq('POST',prefix),{status:503,body:{}}]
  ]);
  await assert.rejects(createPartner(uncertain,ROOT,async()=>{}),/ORG_CREATE_OUTCOME_UNCERTAIN_HTTP_503/);
});
test('inventory requires organization context and full SCIM pagination', async () => {
  const call=callFrom([
    [eq('GET',prefix+'/metadata'),{status:200,body:{id:CHILD,parent:{id:ROOT}}}],
    [eq('GET',new RegExp('/o/scim2/Users')), {status:200,body:{Resources:[{id:USER,active:true}],totalResults:2}}]
  ]);
  await assert.rejects(inventoryChild(call,CHILD,ROOT),/SCIM_USERS_INVENTORY_INCOMPLETE/);
});
test('suspension refuses unverified user, journals before PATCH and reads WSO2 state', async () => {
  const p=`/t/${TENANT}/o/scim2/Users/${USER}`;
  let isActive=true; const trace=[];
  const call=callFrom([
    [eq('GET',prefix+'/metadata'),{status:200,body:{id:CHILD,parent:{id:ROOT}}}],
    [eq('GET',p),()=>({status:200,body:{id:USER,active:isActive}})],
    [eq('PATCH',p),()=>{ trace.push('PATCH'); isActive=false; return {status:200,body:{}}; }]
  ]);
  const r=await disableChildUser(call,CHILD,ROOT,USER,async()=>trace.push('JOURNAL'));
  assert.equal(r.action,'DISABLED_AND_VERIFIED'); assert.deepEqual(trace,['JOURNAL','PATCH']);
});
test('SCIM user ID from another org cannot reach mutation', async () => {
  const trace=[];
  const call=callFrom([
    [eq('GET',prefix+'/metadata'),{status:200,body:{id:CHILD,parent:{id:ROOT}}}],
    [eq('GET',new RegExp('/o/scim2/Users/')),{status:404,body:{}}]
  ],trace);
  await assert.rejects(disableChildUser(call,CHILD,ROOT,USER,async()=>{throw Error('must not journal');}),/CHILD_TARGET_USER_HTTP_404/);
  assert.deepEqual(trace.map(x=>x.method),['GET','GET']);
});
