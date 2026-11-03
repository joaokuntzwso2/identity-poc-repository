import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkAuthorityJournal, readAuthorityJournalPin, evaluateAuthorityReadback, commandFailureSummary } from '../scripts/ciam-readback-policy.mjs';
const brands=['aurora','brisa'];
const journal=()=>({roleApiVersion:'v2',apiIdentifier:'https://api.ciam-v10.test/profile',scope:'ciam:profile:read',
  acceptance:'API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED',
  tenants:Object.fromEntries(brands.map(b=>[b,{resource:{state:'verified'},authorizations:{web:{state:'verified'},app:{state:'verified'}},
    role_web:{state:'verified'},role_app:{state:'verified'}}]))});
const reconcile=()=>({stage:'CIAM_V10_AUTHORITY',mode:'READ_ONLY_RECONCILIATION',remoteWrites:0,roleApiVersion:'v2',
  tenants:Object.fromEntries(brands.map(b=>[b,{businessAPI:'PRESENT_SCOPE_VERIFIED',channels:{web:{apiAuthorization:'SCOPE_VERIFIED',role:'PRESENT'},app:{apiAuthorization:'SCOPE_VERIFIED',role:'PRESENT'}}}]))});
test('verified journal and GET-only readback qualify precisely scoped profile resource proof',()=>{
  assert.deepEqual(checkAuthorityJournal(journal()),{ok:true,version:'v2'});
  assert.equal(evaluateAuthorityReadback(JSON.stringify(reconcile()),'v2').ok,true);
});
test('missing role, revoked auth or unexpected API audience never pass',()=>{
  const j=journal();j.tenants.brisa.role_app.state='missing';
  assert.equal(checkAuthorityJournal(j).reason,'JOURNAL_STATE_INCOMPLETE');
  const a=reconcile();a.tenants.aurora.channels.web.apiAuthorization='REMOVED_OR_UNCERTAIN_DO_NOT_REGRANT';
  assert.equal(evaluateAuthorityReadback(JSON.stringify(a),'v2').reason,'READBACK_API_OR_ROLE_MISSING');
  const bad=journal();bad.apiIdentifier='urn:wrong';
  assert.equal(checkAuthorityJournal(bad).ok,false);
});
test('wrong role API version, write-like output and malformed JSON fail closed',()=>{
  assert.equal(evaluateAuthorityReadback(JSON.stringify(reconcile()),'v3').reason,'READBACK_ROLE_VERSION_MISMATCH');
  const wrong=reconcile();wrong.remoteWrites=1;
  assert.equal(evaluateAuthorityReadback(JSON.stringify(wrong),'v2').reason,'READBACK_NOT_GET_ONLY');
  assert.equal(evaluateAuthorityReadback('not json','v2').reason,'READBACK_NOT_JSON');
});
test('readback errors cannot leak passwords or tokens in generated report text',()=>{
  const s=commandFailureSummary({exitCode:3,stderr:'secret=this_is_a_token ROLE_API_VERSION_JOURNAL_PIN_MISMATCH_NO_AUTOMATIC_MIGRATION bearer=ZZ'});
  assert.match(s,/ROLE_API_VERSION_JOURNAL_PIN_MISMATCH_NO_AUTOMATIC_MIGRATION/);
  assert.doesNotMatch(s,/this_is_a_token|bearer=|ZZ/);
});
test('private journal must be owner-only regular file; symlinks and open perms are refused', async()=>{
  const temp=await mkdtemp(join(tmpdir(),'ciam-pin-test-'));
  try{
    const privateDir=join(temp,'private');await mkdir(privateDir,{mode:0o700});
    const target=join(privateDir,'bootstrap-authority-v10.private.json');
    await writeFile(target,JSON.stringify(journal()),{mode:0o600});
    const options={env:{CIAM_V10_HOME:temp}};
    assert.equal((await readAuthorityJournalPin(options)).ok,true);
    await chmod(target,0o644);
    assert.equal((await readAuthorityJournalPin(options)).reason,'JOURNAL_UNSAFE');
  }finally{await rm(temp,{recursive:true,force:true});}
});
