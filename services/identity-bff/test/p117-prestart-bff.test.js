import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root=resolve(fileURLToPath(new URL('../../..',import.meta.url)));
const script=join(root,'scripts','prepare-business-ledgers.mjs');
const packageFile=join(root,'package.json');
function run(env){return spawnSync(process.execPath,[script],{env:{...process.env,...env},encoding:'utf8'});}
test('npm start:bff has a prestart hook; ciam:preflight is unchanged',()=>{
  const scripts=JSON.parse(readFileSync(packageFile,'utf8')).scripts;
  assert.equal(scripts['prestart:bff'],'python3 scripts/p2/partner_v13.py ensure && python3 scripts/p2/partner_access_v14.py status && python3 scripts/p2/partner_business_plan_v15.py status && python3 scripts/p2/partner_portal_v16_3.py bootstrap && python3 scripts/p2/partner_share_v17_2.py bootstrap && python3 scripts/p2/partner_directory_v18.py bootstrap && node scripts/prepare-business-ledgers.mjs');
  assert.equal(scripts['start:bff'],'node scripts/ciam-live-start.mjs');
  assert.equal(scripts['ciam:preflight'],'node scripts/ciam-live-start.mjs --check');
});
test('prestart initializes both zero-byte ledgers, and is idempotent',()=>{
  const dir=mkdtempSync(join(tmpdir(),'p117-npm-prestart-'));
  try {
    let p=run({CIAM_CASES_BACKEND:'jsonl',CIAM_BUSINESS_DATA_DIR:dir});
    assert.equal(p.status,0,p.stderr);assert.match(p.stdout,/BUSINESS_LEDGER_PRESTART/);
    for (const brand of ['aurora','brisa']) assert.equal(readFileSync(join(dir,`requests-${brand}.jsonl`)).length,0);
    p=run({CIAM_CASES_BACKEND:'jsonl',CIAM_BUSINESS_DATA_DIR:dir});
    assert.equal(p.status,0,p.stderr);
    assert.match(p.stdout,/preserved/);
  } finally {rmSync(dir,{recursive:true,force:true});}
});
test('PostgreSQL mode never creates JSONL files, and invalid backend fails closed',()=>{
  const dir=mkdtempSync(join(tmpdir(),'p117-npm-prestart-pg-'));
  try {
    let p=run({CIAM_CASES_BACKEND:'postgres',CIAM_BUSINESS_DATA_DIR:dir});
    assert.equal(p.status,0,p.stderr);
    assert.equal(existsSync(join(dir,'requests-aurora.jsonl')),false);
    assert.equal(existsSync(join(dir,'requests-brisa.jsonl')),false);
    p=run({CIAM_CASES_BACKEND:'unknown',CIAM_BUSINESS_DATA_DIR:dir});
    assert.notEqual(p.status,0);
    assert.equal(existsSync(join(dir,'requests-aurora.jsonl')),false);
  } finally {rmSync(dir,{recursive:true,force:true});}
});
test('after cutover, JSONL prestart fails closed with no file creation',()=>{
  const dir=mkdtempSync(join(tmpdir(),'p117-npm-prestart-cutover-'));
  try {
    writeFileSync(join(dir,'business-postgres-cutover.json'),'{}',{mode:0o600});
    const p=run({CIAM_CASES_BACKEND:'jsonl',CIAM_BUSINESS_DATA_DIR:dir});
    assert.notEqual(p.status,0);
    assert.equal(existsSync(join(dir,'requests-brisa.jsonl')),false);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
