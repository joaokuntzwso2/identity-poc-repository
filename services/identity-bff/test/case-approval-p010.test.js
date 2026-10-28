import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { precheckApproval, commitApprovedCase } from '../src/case-approval-p010.js';
const id='123e4567-e89b-42d3-a456-426614174000';
const actor=(iss,sub)=>createHash('sha256').update(JSON.stringify([iss,sub])).digest('hex');
test('persistent Aurora approval preserves ledger, audits assurance, denies repeat/self/Brisa',()=>{
 const dir=mkdtempSync(join(tmpdir(),'p010-ledger-'));
 const old=process.env.CIAM_BUSINESS_DATA_DIR;process.env.CIAM_BUSINESS_DATA_DIR=dir;
 try{
  const creation={brand:'aurora',id,action:'created',actor:actor('aurora-issuer','customer-1'),at:'2026-10-28T00:00:00Z',title:'Example',description:'Example text'};
  writeFileSync(join(dir,'requests-aurora.jsonl'),JSON.stringify(creation)+'\n',{mode:0o600});
  assert.throws(()=>precheckApproval({brand:'aurora',caseId:id,issuer:'aurora-issuer',subject:'customer-1'}),/self_approval_denied/);
  assert.throws(()=>precheckApproval({brand:'brisa',caseId:id,issuer:'brisa-issuer',subject:'seller'}),/case_not_found/);
  precheckApproval({brand:'aurora',caseId:id,issuer:'aurora-issuer',subject:'seller-1'});
  const result=commitApprovedCase({brand:'aurora',caseId:id,issuer:'aurora-issuer',subject:'seller-1',authTime:1800000000});
  assert.equal(result.status,'APPROVED');
  const lines=readFileSync(join(dir,'requests-aurora.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(lines.length,2);assert.equal(lines[0].title,'Example');
  assert.equal(lines[1].assurance,'WSO2_SIGNED_TOTP_STEP_UP');
  assert.equal(lines[1].authTime,1800000000);
  assert.throws(()=>commitApprovedCase({brand:'aurora',caseId:id,issuer:'aurora-issuer',subject:'seller-1',authTime:1800000001}),/case_not_open/);
 }finally{if(old===undefined)delete process.env.CIAM_BUSINESS_DATA_DIR;else process.env.CIAM_BUSINESS_DATA_DIR=old;rmSync(dir,{recursive:true,force:true});}
});
