#!/usr/bin/env node
/** Guarded P1.17 schema / JSONL import / reconciliation / cutover. No WSO2 writes. */
import pg from 'pg';
import {readFileSync,openSync,writeSync,fsyncSync,closeSync,existsSync} from 'node:fs';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {inventoryLedgers, sha256} from '../services/identity-bff/src/business-ledger.js';
const here=dirname(fileURLToPath(import.meta.url));
const schema=readFileSync(resolve(here,'../db/business/001_init.sql'),'utf8');
const sqlHash=sha256(schema);
const command=process.argv[2], approval=process.argv.find(x=>x.startsWith('--approve='))?.slice(10);
const dir=process.env.CIAM_BUSINESS_DATA_DIR;
const show=x=>process.stdout.write(JSON.stringify(x,null,2)+'\n');
function inventory() {
 if(!dir || !dir.startsWith('/')) throw new Error('ABSOLUTE_BUSINESS_DATA_DIR_REQUIRED');
 return inventoryLedgers(dir);
}
function externalSummary(found) {
 return {fingerprint:found.fingerprint, schemaSha256:sqlHash,
   brands:found.ledgers.map(x=>({brand:x.brand,fileSha256:x.sha256,bytes:x.bytes,
   cases:x.records.length,events:x.events.length,approved:x.records.filter(y=>y.status==='APPROVED').length}))};
}
function approved(expected) {
 if(process.env.CIAM_OPERATOR_APPROVED_WRITES!=='YES' || approval!==expected)
   throw new Error('OPERATOR_APPROVAL_REQUIRED: inventory and pass --approve=<fingerprint>; set CIAM_OPERATOR_APPROVED_WRITES=YES');
}
function migrationPool() {
 const cs=process.env.CIAM_BUSINESS_MIGRATOR_DATABASE_URL;
 if(!cs) throw new Error('MIGRATOR_DB_URL_REQUIRED');
 const u=new URL(cs),name=decodeURIComponent(u.pathname.slice(1));
 if(!/^postgres(ql)?:$/.test(u.protocol) || !name ||
     /^(postgres|template0|template1|wso2.*|ciam_identity|identitydb)$/i.test(name))
   throw new Error('REFUSING_IDENTITY_OR_SYSTEM_DATABASE');
 if(cs===process.env.IDENTITY_CONSENT_DATABASE_URL) throw new Error('REFUSING_IDENTITY_DATABASE');
 const ca=process.env.CIAM_BUSINESS_PG_CA_FILE;
 if(process.env.NODE_ENV==='production' && !ca) throw new Error('TLS_CA_REQUIRED');
 return new pg.Pool({connectionString:cs,max:2,ssl:ca?{ca:readFileSync(ca,'utf8'),rejectUnauthorized:true}:false,
   connectionTimeoutMillis:5000});
}
const issuers=()=>Object.fromEntries(['aurora','brisa'].map(b=>[b,process.env[`CIAM_${b.toUpperCase()}_ISSUER`]]));
async function queryWithTransaction(pool,job) {
 const c=await pool.connect();
 try{ await c.query('BEGIN');await c.query("SET LOCAL statement_timeout='30s'");
   const result=await job(c);await c.query('COMMIT');return result;
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}
}
async function migrateSchema(pool) {
 approved(sqlHash);const c=await pool.connect();
 try {
  const r=await c.query("SELECT to_regclass('business.schema_migrations') IS NOT NULL AS installed");
  if(r.rows[0].installed) {
    const version=await c.query('SELECT checksum FROM business.schema_migrations WHERE version=1');
    if(version.rowCount===1 && version.rows[0].checksum===sqlHash) return {alreadyInstalled:true};
    throw new Error('SCHEMA_VERSION_CONFLICT');
  }
  await c.query('BEGIN');
  try {
    await c.query(schema);
    await c.query('INSERT INTO business.schema_migrations(version,checksum) VALUES (1,$1)',[sqlHash]);
    await c.query('COMMIT');
  }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}
  return {installed:true,schemaSha256:sqlHash};
 }finally{c.release();}
}
async function verifyImported(client,found) {
 for(const ledger of found.ledgers) {
  const imp=await client.query('SELECT file_sha256,case_count,event_count FROM business.jsonl_imports WHERE brand=$1',[ledger.brand]);
  if(imp.rowCount!==1 || imp.rows[0].file_sha256.trim()!==ledger.sha256 ||
     imp.rows[0].case_count!==ledger.records.length || imp.rows[0].event_count!==ledger.events.length)
    throw new Error(`IMPORT_MANIFEST_MISMATCH:${ledger.brand}`);
  const cases=await client.query(`SELECT id,owner_actor,title,description,status,created_at,approved_at,approved_by
    FROM business.service_requests WHERE brand=$1 ORDER BY id`,[ledger.brand]);
  const current=new Map(cases.rows.map(x=>[x.id,x]));
  if(current.size!==ledger.records.length)throw new Error(`CASE_COUNT_MISMATCH:${ledger.brand}`);
  for(const e of ledger.records) {
    const x=current.get(e.id);
    if(!x || x.owner_actor.trim()!==e.owner || x.title!==e.title || x.description!==e.description ||
       x.status!==e.status || x.created_at.toISOString()!==e.createdAt ||
       (x.approved_at?.toISOString() || null)!==e.approvedAt || (x.approved_by?.trim() || null)!==e.approvedBy)
      throw new Error(`CASE_DATA_MISMATCH:${ledger.brand}:${e.id}`);
  }
  const sellers=await client.query(`SELECT case_id,seller_actor,decided_at,assurance_auth_time
      FROM business.seller_decisions WHERE brand=$1`,[ledger.brand]);
  const expectedSellers=ledger.records.filter(r=>r.status==='APPROVED');
  if(sellers.rowCount!==expectedSellers.length)throw new Error(`SELLER_DECISION_COUNT_MISMATCH:${ledger.brand}`);
  const sellerById=new Map(sellers.rows.map(x=>[x.case_id,x]));
  for(const r of expectedSellers){
    const x=sellerById.get(r.id);
    if(!x || x.seller_actor.trim()!==r.approvedBy ||
       x.decided_at.toISOString()!==r.approvedAt)
      throw new Error(`SELLER_DECISION_MISMATCH:${ledger.brand}:${r.id}`);
  }
  const events=await client.query(`SELECT case_id,sequence,action,actor,happened_at,source,ledger_position
      FROM business.case_events WHERE brand=$1 ORDER BY case_id,sequence`,[ledger.brand]);
  if(events.rowCount!==ledger.events.length) throw new Error(`EVENT_COUNT_MISMATCH:${ledger.brand}`);
  const actual=new Map(events.rows.map(x=>[`${x.case_id}:${x.sequence}`,x]));
  for(const e of ledger.events) {
    const x=actual.get(`${e.id}:${e.sequence}`);
    if(!x || x.actor.trim()!==e.actor || x.action!==e.action || x.happened_at.toISOString()!==e.at || x.source!=='jsonl' || x.ledger_position!==e.position)
      throw new Error(`EVENT_MISMATCH:${ledger.brand}:${e.id}:${e.sequence}`);
  }
 }
 return {verified:true,brands:found.ledgers.map(x=>({brand:x.brand,cases:x.records.length,events:x.events.length}))};
}
async function applyLedger(pool,found) {
 approved(found.fingerprint);
 const bound=issuers();
 for(const brand of ['aurora','brisa']){
   if(!bound[brand] || !/^https:\/\//.test(bound[brand]) || bound[brand].length>1024)
    throw new Error(`EXPLICIT_HTTPS_ISSUER_REQUIRED:${brand}`);
 }
 return queryWithTransaction(pool,async c=>{
   // One advisory lock for the full two-brand import. Never race a second importer.
   await c.query('SELECT pg_advisory_xact_lock(117,119)');
   const versions=await c.query('SELECT checksum FROM business.schema_migrations WHERE version=1');
   if(versions.rowCount!==1 || versions.rows[0].checksum!==sqlHash) throw new Error('SCHEMA_NOT_CURRENT');
   for(const l of found.ledgers) {
     const already=await c.query('SELECT count(*)::int AS n FROM business.service_requests WHERE brand=$1',[l.brand]);
     const imported=await c.query('SELECT 1 FROM business.jsonl_imports WHERE brand=$1',[l.brand]);
     if(already.rows[0].n!==0 || imported.rowCount) throw new Error('TARGET_BRAND_NOT_EMPTY');
     await c.query(`INSERT INTO business.brands(brand,issuer) VALUES($1,$2)
       ON CONFLICT(brand) DO NOTHING`,[l.brand,bound[l.brand]]);
     const issuer=await c.query('SELECT issuer FROM business.brands WHERE brand=$1',[l.brand]);
     if(issuer.rows[0]?.issuer!==bound[l.brand])throw new Error('BRAND_ISSUER_CONFLICT');
     for(const r of l.records) await c.query(`INSERT INTO business.service_requests
       (id,brand,owner_actor,title,description,status,created_at,approved_at,approved_by)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
       [r.id,l.brand,r.owner,r.title,r.description,r.status,r.createdAt,r.approvedAt,r.approvedBy]);
     for(const r of l.records.filter(x=>x.status==='APPROVED')) await c.query(`INSERT INTO business.seller_decisions
       (brand,case_id,seller_actor,decided_at) VALUES ($1,$2,$3,$4)`,
       [l.brand,r.id,r.approvedBy,r.approvedAt]);
     for(const e of l.events) await c.query(`INSERT INTO business.case_events
       (brand,case_id,sequence,action,actor,happened_at,source,ledger_position)
       VALUES($1,$2,$3,$4,$5,$6,'jsonl',$7)`,[l.brand,e.id,e.sequence,e.action,e.actor,e.at,e.position]);
     await c.query(`INSERT INTO business.jsonl_imports(brand,file_sha256,case_count,event_count)
       VALUES($1,$2,$3,$4)`,[l.brand,l.sha256,l.records.length,l.events.length]);
   }
   return verifyImported(c,found);
 });
}
async function main() {
 const found=['inventory','apply-ledger','verify','activate'].includes(command)?inventory():null;
 if(command==='inventory') {show(externalSummary(found));return;}
 if(command==='schema-hash') {show({schemaSha256:sqlHash});return;}
 if(!['migrate-schema','apply-ledger','verify','activate'].includes(command))
  throw new Error('USAGE: schema-hash | inventory | migrate-schema --approve=<schemaSha256> | apply-ledger --approve=<inventoryFingerprint> | verify | activate --approve=<inventoryFingerprint>');
 const pool=migrationPool();
 try{
  if(command==='migrate-schema'){show(await migrateSchema(pool));return;}
  if(command==='apply-ledger'){show(await applyLedger(pool,found));return;}
  const verified=await queryWithTransaction(pool,c=>verifyImported(c,found));
  if(command==='verify'){show({...verified,...externalSummary(found)});return;}
  approved(found.fingerprint);
  const marker=resolve(dir,'business-postgres-cutover.json');
  if(existsSync(marker)) throw new Error('CUTOVER_MARKER_ALREADY_EXISTS');
  // Operator must first STOP the BFF and prevent concurrent legacy writers.
  // The marker blocks all further JSONL writes and makes PostgreSQL the only writer.
  const fd=openSync(marker,'wx',0o600);
  try{writeSync(fd,JSON.stringify({backend:'postgres',fingerprint:found.fingerprint,
    activatedAt:new Date().toISOString(),brands:externalSummary(found).brands},null,2)+'\n');fsyncSync(fd);}
  finally{closeSync(fd);}
  show({activated:true,marker,...verified});
 }finally{await pool.end();}
}
main().catch(e=>{process.stderr.write(`BUSINESS_MIGRATION_FAILED: ${e.message}\n`);process.exitCode=1;});
