import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, lstatSync, rmSync, symlinkSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {randomUUID, createHash} from 'node:crypto';
import { bootstrapBusinessLedgers } from '../../../scripts/bootstrap-business-ledgers.mjs';
import {actorFingerprint, inventoryLedgers} from '../src/business-ledger.js';

function withPrivateDir(fn) {
  const top = mkdtempSync(join(tmpdir(),'p117-brand-bootstrap-'));
  const dir = join(top,'data');
  mkdirSync(dir,{mode:0o700});
  try{return fn(dir);}finally{rmSync(top,{recursive:true,force:true});}
}
const digest=b=>createHash('sha256').update(b).digest('hex');
const sample=(brand)=>Buffer.from(`${JSON.stringify({brand,id:randomUUID(),action:'created',actor:actorFingerprint('https://issuer.example','subject'),title:'Test case',description:'Keep history',at:'2026-10-29T12:00:00.000Z'})}\n`);

test('bootstrap initializes both Aurora and Brisa empty ledgers, with private permissions',()=>withPrivateDir(dir=>{
 const r=bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir,CIAM_CASES_BACKEND:'jsonl'});
 assert.deepEqual(r.ledgers.map(x=>x.result),['created_empty','created_empty']);
 for(const brand of ['aurora','brisa']) {
   const file=join(dir,`requests-${brand}.jsonl`);
   assert.equal(readFileSync(file).length,0);
   assert.equal(lstatSync(file).mode & 0o777,0o600);
 }
 assert.equal(inventoryLedgers(dir).ledgers.length,2);
}));

test('repeated bootstrap preserves Aurora contents and an already empty Brisa file byte-for-byte',()=>withPrivateDir(dir=>{
 const aurora=sample('aurora');
 writeFileSync(join(dir,'requests-aurora.jsonl'),aurora,{mode:0o600});
 const first=bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir});
 assert.deepEqual(first.ledgers.map(x=>x.result),['preserved','created_empty']);
 const before=digest(readFileSync(join(dir,'requests-aurora.jsonl')));
 const second=bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir});
 assert.deepEqual(second.ledgers.map(x=>x.result),['preserved','preserved']);
 assert.equal(digest(readFileSync(join(dir,'requests-aurora.jsonl'))),before);
 assert.deepEqual(readFileSync(join(dir,'requests-aurora.jsonl')),aurora);
}));

test('refuses to create missing Brisa ledger if Aurora is malformed',()=>withPrivateDir(dir=>{
 writeFileSync(join(dir,'requests-aurora.jsonl'),'not json\n',{mode:0o600});
 assert.throws(()=>bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir}),/LEDGER_INVALID_JSON/);
 assert.throws(()=>lstatSync(join(dir,'requests-brisa.jsonl')),/ENOENT/);
}));

test('cutover and PostgreSQL backend both prohibit auto-creating JSONL files',()=>withPrivateDir(dir=>{
 writeFileSync(join(dir,'business-postgres-cutover.json'),'{}',{mode:0o600});
 assert.throws(()=>bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir}),/AFTER_CUTOVER/);
 rmSync(join(dir,'business-postgres-cutover.json'));
 assert.throws(()=>bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir,CIAM_CASES_BACKEND:'postgres'}),/POSTGRES_MODE/);
 assert.throws(()=>lstatSync(join(dir,'requests-brisa.jsonl')),/ENOENT/);
}));

test('refuses symlink and insecure preexisting files without touching them',()=>withPrivateDir(dir=>{
 const elsewhere=join(dir,'other');
 writeFileSync(elsewhere,'private',{mode:0o600});
 symlinkSync(elsewhere,join(dir,'requests-aurora.jsonl'));
 assert.throws(()=>bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir}),/UNSAFE_LEDGER_FILE/);
 assert.equal(readFileSync(elsewhere,'utf8'),'private');
 rmSync(join(dir,'requests-aurora.jsonl'));
 writeFileSync(join(dir,'requests-aurora.jsonl'),sample('aurora'),{mode:0o600});
 chmodSync(join(dir,'requests-aurora.jsonl'),0o644);
 assert.throws(()=>bootstrapBusinessLedgers({CIAM_BUSINESS_DATA_DIR:dir}),/UNSAFE_LEDGER_FILE/);
 assert.throws(()=>lstatSync(join(dir,'requests-brisa.jsonl')),/ENOENT/);
}));
