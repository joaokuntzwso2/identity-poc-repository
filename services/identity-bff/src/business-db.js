/** Application-owned PostgreSQL cases. WSO2's database must never be used. */
import { createRequire } from 'node:module';
import { randomUUID, createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, isAbsolute } from 'node:path';
import { actorFingerprint, BRANDS } from './business-ledger.js';
const requireBusinessDriver = createRequire(import.meta.url);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const KEY = /^[\x21-\x7e]{8,128}$/;
const hash = v => createHash('sha256').update(v).digest('hex');
export class BusinessError extends Error {
  constructor(code,status=409) { super(code); this.code=code; this.status=status; }
}
let pool;
export function businessPool(env=process.env) {
  if (pool) return pool;
  if (!env.CIAM_BUSINESS_DATABASE_URL) throw new BusinessError('business_database_not_configured',503);
  const url = new URL(env.CIAM_BUSINESS_DATABASE_URL);
  const database = decodeURIComponent(url.pathname.slice(1));
  if (!/^postgres(ql)?:$/.test(url.protocol) || !database ||
      /^(postgres|template0|template1|wso2.*|ciam_identity|identitydb)$/i.test(database) ||
      env.CIAM_BUSINESS_DATABASE_URL === env.IDENTITY_CONSENT_DATABASE_URL)
    throw new BusinessError('dedicated_business_database_required',503);
  const prod = env.NODE_ENV === 'production';
  if (prod && !env.CIAM_BUSINESS_PG_CA_FILE) throw new BusinessError('business_pg_ca_required',503);
  // JSONL startup and isolated HTTP fixtures must not load the optional PG driver.
  // Only an explicitly configured PostgreSQL pool resolves this dependency.
  const { Pool } = requireBusinessDriver('pg');
  pool = new Pool({connectionString:env.CIAM_BUSINESS_DATABASE_URL,
    max:Number(env.CIAM_BUSINESS_POOL_MAX||10),
    connectionTimeoutMillis:5000,idleTimeoutMillis:30000,
    ...(env.CIAM_BUSINESS_PG_CA_FILE ? {ssl:{ca:readFileSync(env.CIAM_BUSINESS_PG_CA_FILE,'utf8'),rejectUnauthorized:true}} :
      {ssl:prod?{rejectUnauthorized:true}:false})});
  pool.on('error', () => { /* pool idle client failures must never contain credentials in logs */ });
  return pool;
}
export async function closeBusinessPool() { if (pool) { const p=pool;pool=undefined;await p.end(); } }
const validateBrand = brand => { if (!BRANDS.includes(brand)) throw new BusinessError('invalid_brand',400); };
function validateIdentity(brand,issuer,subject) {
  validateBrand(brand);
  if (typeof issuer !== 'string' || typeof subject !== 'string' ||
      !issuer || !subject || issuer.length > 1024 || subject.length > 1024)
    throw new BusinessError('invalid_actor',401);
  return actorFingerprint(issuer,subject);
}
function validateCaseId(id) { if (!UUID.test(id || '')) throw new BusinessError('invalid_case_id',400); }
function normalizeKey(value) {
  if (value === undefined || value === null) return null; // Legacy browser compatibility.
  if (typeof value !== 'string' || !KEY.test(value)) throw new BusinessError('invalid_idempotency_key',400);
  return hash(value);
}
async function tx(action) {
  const client = await businessPool().connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout = '8s'");
    const result=await action(client);
    await client.query('COMMIT'); return result;
  } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; }
  finally { client.release(); }
}
async function pinnedIssuer(client,brand,issuer) {
  const r = await client.query('SELECT issuer FROM business.brands WHERE brand=$1',[brand]);
  if (r.rowCount!==1 || r.rows[0].issuer!==issuer) throw new BusinessError('tenant_issuer_mismatch',403);
}
async function idemReserve(client,{brand,actor,operation,keyHash,requestHash}) {
  if (!keyHash) return null;
  const inserted=await client.query(`INSERT INTO business.operation_idempotency
   (brand,actor,operation,key_hash,request_hash) VALUES ($1,$2,$3,$4,$5)
   ON CONFLICT DO NOTHING RETURNING key_hash`,[brand,actor,operation,keyHash,requestHash]);
  if (inserted.rowCount) return {new:true};
  const existing=await client.query(`SELECT request_hash,result FROM business.operation_idempotency
    WHERE brand=$1 AND actor=$2 AND operation=$3 AND key_hash=$4`,[brand,actor,operation,keyHash]);
  if (existing.rowCount!==1 || existing.rows[0].request_hash.trim()!==requestHash)
    throw new BusinessError('idempotency_key_conflict',409);
  if (!existing.rows[0].result) throw new BusinessError('operation_in_progress',503);
  return {new:false,result:existing.rows[0].result};
}
async function idemComplete(client,{brand,actor,operation,keyHash},result) {
  if (keyHash) await client.query(`UPDATE business.operation_idempotency SET result=$5::jsonb
    WHERE brand=$1 AND actor=$2 AND operation=$3 AND key_hash=$4`,
    [brand,actor,operation,keyHash,JSON.stringify(result)]);
}
export function assertPostgresCutover(env=process.env) {
  const dir=env.CIAM_BUSINESS_DATA_DIR;
  if (!dir || !isAbsolute(dir) || !existsSync(resolve(dir,'business-postgres-cutover.json')))
    throw new BusinessError('business_pg_cutover_not_activated',503);
  const marker=JSON.parse(readFileSync(resolve(dir,'business-postgres-cutover.json'),'utf8'));
  if (marker.backend !== 'postgres' || !/^[0-9a-f]{64}$/.test(marker.fingerprint))
    throw new BusinessError('business_pg_cutover_invalid',503);
  return marker;
}
export async function businessHealth() {
  const row=await businessPool().query(`SELECT COUNT(*)::int AS n FROM business.brands`);
  return {status:'UP',brands:row.rows[0].n};
}
export async function createBusinessCase({brand,issuer,subject,title,description,idempotencyKey}) {
  const actor=validateIdentity(brand,issuer,subject);
  if (typeof title!=='string' || title.trim().length<3 || title.length>120 ||
      typeof description!=='string' || description.length>1000)
    throw new BusinessError('invalid_case_fields',400);
  const cleanTitle=title.trim(), keyHash=normalizeKey(idempotencyKey);
  const requestHash=hash(JSON.stringify([brand,issuer,subject,cleanTitle,description]));
  return tx(async c=>{
    await pinnedIssuer(c,brand,issuer);
    const idem={brand,actor,operation:'create',keyHash,requestHash};
    const reservation=await idemReserve(c,idem);
    if (reservation && !reservation.new) return {...reservation.result,replayed:true};
    const id=randomUUID(),at=new Date().toISOString();
    await c.query(`INSERT INTO business.service_requests
       (id,brand,owner_actor,owner_issuer,owner_subject,title,description,created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[id,brand,actor,issuer,subject,cleanTitle,description,at]);
    await c.query(`INSERT INTO business.case_events
       (brand,case_id,sequence,action,actor,actor_issuer,actor_subject,happened_at,source)
       VALUES ($1,$2,1,'created',$3,$4,$5,$6,'application')`,[brand,id,actor,issuer,subject,at]);
    const result={id,status:'OPEN',persistent:true};
    await idemComplete(c,idem,result); return result;
  });
}
export async function listBusinessCases({brand,issuer,subject,review=false}) {
  const actor=validateIdentity(brand,issuer,subject);
  await pinnedIssuer(businessPool(),brand,issuer);
  // One MVCC snapshot for request state and ordered event history; no split-query race.
  const r=await businessPool().query(`SELECT r.id,r.title,r.description,r.created_at,
       r.status,r.approved_at,
       COALESCE((SELECT jsonb_agg(jsonb_build_object('action',e.action,
         'at',to_char(e.happened_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
         ORDER BY e.sequence) FROM business.case_events e
           WHERE e.brand=r.brand AND e.case_id=r.id),'[]'::jsonb) AS history
       FROM business.service_requests r
       WHERE r.brand=$1 AND ($2::boolean OR r.owner_actor=$3)
       ORDER BY r.created_at,r.id LIMIT 1000`,[brand,Boolean(review),actor]);
  return r.rows.map(x=>({id:x.id,title:x.title,description:x.description,
    createdAt:x.created_at.toISOString(),status:x.status,
    approvedAt:x.approved_at?.toISOString() || null,history:x.history}));
}
export async function precheckBusinessApproval({brand,caseId,issuer,subject}) {
  const actor=validateIdentity(brand,issuer,subject);validateCaseId(caseId);
  await pinnedIssuer(businessPool(),brand,issuer);
  const r=await businessPool().query(`SELECT owner_actor,status FROM business.service_requests
      WHERE brand=$1 AND id=$2`,[brand,caseId]);
  if (!r.rowCount) throw new BusinessError('case_not_found',404);
  if (r.rows[0].owner_actor.trim()===actor) throw new BusinessError('self_approval_denied',403);
  if (r.rows[0].status!=='OPEN') throw new BusinessError('case_not_open',409);
  return true;
}
export async function approveBusinessCase({brand,caseId,issuer,subject,authTime,idempotencyKey}) {
  const actor=validateIdentity(brand,issuer,subject);validateCaseId(caseId);
  // Caller must have already completed the signed, approval-bound WSO2 step-up.
  if (!Number.isSafeInteger(authTime) || Math.abs(Math.floor(Date.now()/1000)-authTime)>300)
    throw new BusinessError('fresh_wso2_assurance_required',403);
  const keyHash=normalizeKey(idempotencyKey);
  const requestHash=hash(JSON.stringify([brand,caseId,issuer,subject]));
  return tx(async c=>{
    await pinnedIssuer(c,brand,issuer);
    const idem={brand,actor,operation:'approve',keyHash,requestHash};
    const reservation=await idemReserve(c,idem);
    if (reservation && !reservation.new) return {...reservation.result,replayed:true};
    const row=await c.query(`SELECT owner_actor,status FROM business.service_requests
       WHERE brand=$1 AND id=$2 FOR UPDATE`,[brand,caseId]);
    if (!row.rowCount) throw new BusinessError('case_not_found',404);
    if (row.rows[0].owner_actor.trim()===actor) throw new BusinessError('self_approval_denied',403);
    if (row.rows[0].status!=='OPEN') throw new BusinessError('case_not_open',409);
    const at=new Date().toISOString();
    const updated=await c.query(`UPDATE business.service_requests
       SET status='APPROVED',approved_at=$3,approved_by=$4
       WHERE brand=$1 AND id=$2 AND status='OPEN'`,[brand,caseId,at,actor]);
    if (updated.rowCount!==1) throw new BusinessError('case_not_open',409);
    await c.query(`INSERT INTO business.seller_decisions
      (brand,case_id,seller_actor,seller_issuer,seller_subject,assurance_auth_time,decided_at)
      VALUES ($1,$2,$3,$4,$5,to_timestamp($6),$7)`,
      [brand,caseId,actor,issuer,subject,authTime,at]);
    await c.query(`INSERT INTO business.case_events
       (brand,case_id,sequence,action,actor,actor_issuer,actor_subject,happened_at,source)
       VALUES ($1,$2,2,'approved',$3,$4,$5,$6,'application')`,[brand,caseId,actor,issuer,subject,at]);
    const result={id:caseId,status:'APPROVED',persistent:true};
    await idemComplete(c,idem,result);return result;
  });
}
