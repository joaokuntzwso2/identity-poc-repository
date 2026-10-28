import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
const script = readFileSync(new URL('../deploy/ciam-v10/p010/aurora-acr-totp-adaptive.js', import.meta.url), 'utf8');
const ACR = 'urn:ciampoc:assurance:totp:v1';
function run(acrList, { basicSuccess = true, totpSuccess = true } = {}) {
  const seen=[];
  const context={requestedAcr:acrList};
  const sandbox={executeStep(step,opts){
    seen.push(step);
    const success = step===1 ? basicSuccess : totpSuccess;
    if (success && opts?.onSuccess) opts.onSuccess(context);
  }};
  runInNewContext(script,sandbox,{timeout:300});
  sandbox.onLoginRequest(context);
  return {seen,acr:context.selectedAcr};
}
test('normal OIDC login remains Basic only',()=>{
  const result=run([]);
  assert.deepEqual(result.seen,[1]);assert.equal(result.acr,undefined);
});
test('ordinary login cannot mint approval assurance',()=>{
  for (const ac of [undefined,null,['unrelated-acr'],['urn:ciampoc:assurance:totp:v1-extra']]) {
    assert.equal(run(ac).acr,undefined);
  }
});
test('requested approval executes Basic then TOTP and selects ACR only on both successes',()=>{
  const result=run([ACR]);assert.deepEqual(result.seen,[1,2]);assert.equal(result.acr,ACR);
});
test('failed basic step never initiates TOTP or selects ACR',()=>{
  const result=run([ACR],{basicSuccess:false});assert.deepEqual(result.seen,[1]);assert.equal(result.acr,undefined);
});
test('failed or canceled TOTP never selects ACR',()=>{
  const result=run([ACR],{totpSuccess:false});assert.deepEqual(result.seen,[1,2]);assert.equal(result.acr,undefined);
});
