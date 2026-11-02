/** Opt-in MUTATING tests; connect ONLY to an operator-approved throwaway database. */
import test from 'node:test';
import assert from 'node:assert/strict';
const approved=process.env.CIAM_TEST_DB_MUTATION_APPROVED==='YES' &&
 !!process.env.CIAM_TEST_BUSINESS_DATABASE_URL &&
 /_test(\?|$)/.test(process.env.CIAM_TEST_BUSINESS_DATABASE_URL);
test('PostgreSQL: concurrent approvals, idempotency, subject and tenant isolation',
 {skip:!approved && 'Requires disposable *_test DB and explicit authorization'},async()=>{
 const {createBusinessCase,approveBusinessCase,precheckBusinessApproval,listBusinessCases,closeBusinessPool}=await import('../src/business-db.js');
 const pg=await import('pg');
 const u=new URL(process.env.CIAM_TEST_BUSINESS_DATABASE_URL);
 if(!u.pathname.endsWith('_test'))throw new Error('REFUSING_NON_TEST_DB');
 process.env.CIAM_BUSINESS_DATABASE_URL=process.env.CIAM_TEST_BUSINESS_DATABASE_URL;
 const client=new pg.default.Client({connectionString:process.env.CIAM_TEST_BUSINESS_DATABASE_URL});
 await client.connect();
 const issuerA=`https://unit-test.example/t/aurora-${process.pid}/oauth2/token`;
 const issuerB=`https://unit-test.example/t/brisa-${process.pid}/oauth2/token`;
 try{
  // A distinct, disposable DB is required; don't drop or truncate pre-existing data.
  const count=await client.query('SELECT count(*)::int AS n FROM business.service_requests');
  if(count.rows[0].n!==0)throw new Error('NON_EMPTY_DISPOSABLE_TEST_DB');
  const emptyBrands=await client.query('SELECT count(*)::int AS n FROM business.brands');
  if(emptyBrands.rows[0].n!==0)throw new Error('NON_EMPTY_DISPOSABLE_TEST_BRANDS');
  // Simulate interrupted import: uncommitted tenant row must roll back cleanly.
  await client.query('BEGIN');
  try {
   await client.query(`INSERT INTO business.brands(brand,issuer) VALUES('aurora',$1)`,[issuerA]);
  }finally{await client.query('ROLLBACK');}
  assert.equal((await client.query('SELECT count(*)::int AS n FROM business.brands')).rows[0].n,0);
  await client.query(`INSERT INTO business.brands(brand,issuer) VALUES('aurora',$1),('brisa',$2)`,[issuerA,issuerB]);
  const cmd={brand:'aurora',issuer:issuerA,subject:'buyer',title:'Legitimate request',description:'safe',idempotencyKey:'create-idempotency-key'};
  const first=await createBusinessCase(cmd);
  await closeBusinessPool(); // restart/reconnect must not lose a committed case
  assert.equal((await listBusinessCases({brand:'aurora',issuer:issuerA,subject:'buyer'})).length,1);
  const replay=await createBusinessCase(cmd);
  assert.equal(first.id,replay.id);assert.equal(replay.replayed,true);
  const simultaneousCreates=await Promise.all(Array.from({length:8},()=>createBusinessCase(cmd)));
  assert.ok(simultaneousCreates.every(x=>x.id===first.id && x.replayed));
  assert.equal((await client.query(`SELECT count(*)::int AS n FROM business.service_requests
    WHERE brand='aurora'`)).rows[0].n,1);
  await assert.rejects(()=>createBusinessCase({...cmd,title:'Different title'}),e=>e.status===409);
  await assert.rejects(()=>precheckBusinessApproval({brand:'aurora',caseId:first.id,issuer:issuerA,subject:'buyer'}),e=>e.status===403);
  await assert.rejects(()=>precheckBusinessApproval({brand:'brisa',caseId:first.id,issuer:issuerB,subject:'seller'}),e=>e.status===404);
  const ownerList=await listBusinessCases({brand:'aurora',issuer:issuerA,subject:'someone-else'});
  assert.equal(ownerList.length,0);
  assert.equal((await listBusinessCases({brand:'aurora',issuer:issuerA,subject:'buyer'})).length,1);
  const attack=await listBusinessCases({brand:'aurora',issuer:issuerA,subject:"' OR true --"});
  assert.equal(attack.length,0);
  await assert.rejects(()=>approveBusinessCase({brand:'aurora',caseId:first.id,issuer:issuerA,subject:'seller',authTime:1}),e=>e.status===403);
  const approval={brand:'aurora',caseId:first.id,issuer:issuerA,subject:'seller',authTime:Math.floor(Date.now()/1000)};
  const results=await Promise.allSettled(Array.from({length:8},(_,i)=>approveBusinessCase({...approval,idempotencyKey:`approval-unique-${i}`})));
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(results.filter(x=>x.status==='rejected').length,7);
  const winnerIndex=results.findIndex(x=>x.status==='fulfilled');
  const approvedReplay=await approveBusinessCase({...approval,idempotencyKey:`approval-unique-${winnerIndex}`});
  assert.equal(approvedReplay.replayed,true);
  const decisions=await client.query('SELECT count(*)::int AS n FROM business.seller_decisions WHERE case_id=$1',[first.id]);
  assert.equal(decisions.rows[0].n,1);
  const ev=await client.query('SELECT action,count(*)::int AS n FROM business.case_events WHERE case_id=$1 GROUP BY action',[first.id]);
  assert.deepEqual(Object.fromEntries(ev.rows.map(x=>[x.action,x.n])),{created:1,approved:1});
 }finally{await closeBusinessPool();await client.end();}
});
