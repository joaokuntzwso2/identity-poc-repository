#!/usr/bin/env node
/** Verify the existing role-API journal PIN against the GET-only live WSO2 API. */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readAuthorityJournalPin, evaluateAuthorityReadback, commandFailureSummary } from './ciam-readback-policy.mjs';
const exec=promisify(execFile);
const pin=await readAuthorityJournalPin();
if(!pin.ok){
  console.error('PROFILE_AUTHORITY_STOP: '+pin.reason);
  process.exit(2);
}
const root=resolve(dirname(fileURLToPath(import.meta.url)), '..');
try{
  const r=await exec('bash',['scripts/ciam-v10.sh','authorization-reconcile'],{
    cwd:root,env:{...process.env,WSO2_CIAM_V10_ROLE_API:pin.version},
    timeout:120000,maxBuffer:1024*1024
  });
  const result=evaluateAuthorityReadback(r.stdout,pin.version);
  if(!result.ok){console.error('PROFILE_AUTHORITY_STOP: '+result.reason);process.exit(2);}
  // Prints only the accepted API contract version for the guarded shell launcher.
  process.stdout.write(pin.version+'\n');
}catch(e){
  console.error('PROFILE_AUTHORITY_STOP: '+commandFailureSummary(e));
  process.exit(2);
}
