// OFFLINE_TEST. WSO2 conditional JavaScript simulated with a local JS VM.
// It does not prove GA 7.3 engine compatibility or live TOTP enrollment.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {fileURLToPath} from 'node:url';
const dir = path.dirname(fileURLToPath(import.meta.url));
const template = fs.readFileSync(path.join(dir,'../scripts/magalu-adaptive.js'),'utf8');
const policies = Object.fromEntries(['aurora','brisa'].map(b =>
  [b,JSON.parse(fs.readFileSync(path.join(dir,'../policy',`${b}.json`),'utf8'))]));

function execute(brand, {failures=0, requestedAcr=[], passwordWorks=true, passwordFailuresBeforeSuccess=0, totpWorks=true, graalGraphCallbacks=false}={}) {
  const policy=policies[brand];
  const source=template.replace('__MAGALU_THRESHOLD__',String(policy.loginAttempts.stepUpAfterFailures))
    .replace('__MAGALU_AURORA__',String(brand==='aurora'));
  const steps=[];
  let attemptsAtStepOne=0;
  const context={requestedAcr,steps:{1:{subject:{localClaims:{
    'http://wso2.org/claims/identity/failedLoginAttemptsBeforeSuccess':String(failures)
  }}}}};
  // Real Graal graph nodes may execute callbacks separately from the lexical
  // frame that created them. Re-evaluation exposes invalid closure captures.
  let sandbox;
  const invoke=(callback)=>{
    const fn = graalGraphCallbacks
      ? vm.runInContext(`(${callback.toString()})`, sandbox)
      : callback;
    fn(context);
  };
  sandbox={executeStep:(number,handlers={})=>{
    steps.push(number);
    if(number===1) {
      attemptsAtStepOne++;
      if (attemptsAtStepOne <= passwordFailuresBeforeSuccess) {
        if (handlers.onFail) invoke(handlers.onFail);
      } else if (passwordWorks && handlers.onSuccess) {
        invoke(handlers.onSuccess);
      }
    }
    if(number===2 && totpWorks && handlers.onSuccess) invoke(handlers.onSuccess);
  }};
  vm.createContext(sandbox);
  vm.runInContext(source,sandbox);
  sandbox.onLoginRequest(context);
  return {steps,acr:context.selectedAcr,failedClaim:context.steps[1].subject.localClaims['http://wso2.org/claims/identity/failedLoginAttemptsBeforeSuccess']};
}

test('Aurora below threshold retains the password-only flow',()=>{
  assert.deepEqual(execute('aurora',{failures:2}).steps,[1]);
});
test('Aurora reaches the threshold and requires genuine TOTP step',()=>{
  assert.deepEqual(execute('aurora',{failures:3}).steps,[1,2]);
});
test('Brisa uses its own higher threshold',()=>{
  assert.deepEqual(execute('brisa',{failures:3}).steps,[1]);
  assert.deepEqual(execute('brisa',{failures:4}).steps,[1,2]);
});
test('Aurora seller approval ACR always steps up even without failures',()=>{
  const r=execute('aurora',{requestedAcr:['urn:ciampoc:assurance:totp:v1']});
  assert.deepEqual(r.steps,[1,2]);
  assert.equal(r.acr,'urn:ciampoc:assurance:totp:v1');
});
test('No approval ACR is set when TOTP fails',()=>{
  const r=execute('aurora',{requestedAcr:['urn:ciampoc:assurance:totp:v1'],totpWorks:false});
  assert.deepEqual(r.steps,[1,2]);
  assert.equal(r.acr,undefined);
});
test('Brisa never asserts Aurora approval ACR',()=>{
  const r=execute('brisa',{requestedAcr:['urn:ciampoc:assurance:totp:v1']});
  assert.deepEqual(r.steps,[1]);
  assert.equal(r.acr,undefined);
});
test('Wrong password does not bypass primary step',()=>{
  assert.deepEqual(execute('aurora',{failures:99,passwordWorks:false}).steps,[1]);
});

test('Failed first factor retries step one, never bypassing it',()=>{
  assert.deepEqual(execute('aurora', {failures:3, passwordFailuresBeforeSuccess:2}).steps, [1,1,1,2]);
  assert.deepEqual(execute('brisa', {failures:1, passwordFailuresBeforeSuccess:1}).steps, [1,1]);
});

test('Failed-login claim resets only when TOTP completes',()=>{
  assert.equal(execute('aurora',{failures:3,totpWorks:false}).failedClaim,'3');
  assert.equal(execute('aurora',{failures:3,totpWorks:true}).failedClaim,'0');
});

// The previous script passed ordinary Node VM tests but failed in the actual
// WSO2 7.3 Graal graph with ReferenceError: approval is not defined.
// Detaching each callback is a conservative offline regression gate.
test('Graal graph callbacks do not capture local approval / user / attemptStepUp',()=>{
  assert.deepEqual(execute('aurora',{graalGraphCallbacks:true,failures:0}).steps,[1]);
  assert.deepEqual(execute('aurora',{graalGraphCallbacks:true,failures:3,totpWorks:true}).steps,[1,2]);
  assert.equal(execute('aurora',{graalGraphCallbacks:true,failures:3,totpWorks:true}).failedClaim,'0');
  assert.equal(execute('aurora',{graalGraphCallbacks:true,failures:3,totpWorks:false}).failedClaim,'3');
  assert.equal(execute('aurora',{graalGraphCallbacks:true,requestedAcr:['urn:ciampoc:assurance:totp:v1']}).acr,'urn:ciampoc:assurance:totp:v1');
  assert.equal(execute('aurora',{graalGraphCallbacks:true,requestedAcr:['urn:ciampoc:assurance:totp:v1'],totpWorks:false}).acr,undefined);
  assert.equal(execute('brisa',{graalGraphCallbacks:true,requestedAcr:['urn:ciampoc:assurance:totp:v1'],failures:4}).acr,undefined);
  assert.deepEqual(execute('aurora',{graalGraphCallbacks:true,passwordFailuresBeforeSuccess:1,failures:3}).steps,[1,1,2]);
});

test('No loops or captured locals in the compiled script',()=>{
  assert.doesNotMatch(template,/\bfor\s*\(/);
  assert.doesNotMatch(template,/\bwhile\s*\(/);
  assert.doesNotMatch(template,/if\s*\(approval\b/);
  assert.doesNotMatch(template,/if\s*\(attemptStepUp\b/);
});
