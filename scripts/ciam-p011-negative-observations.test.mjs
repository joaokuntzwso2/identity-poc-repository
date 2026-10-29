import test from 'node:test';
import assert from 'node:assert/strict';
import {REQUIRED_CASE_NEGATIVES, assertCaseDenial, caseNegativeMatrix} from './ciam-p011-negative-observations.mjs';
test('complete actual-response matrix requires every independently observed denial', () => {
  const row = {};
  assert.equal(caseNegativeMatrix(row), false);
  for (const [name, code] of Object.entries(REQUIRED_CASE_NEGATIVES))
    assertCaseDenial(row, name, code);
  assert.equal(caseNegativeMatrix(row), true);
  delete row.customerMissingCsrfHttp;
  assert.equal(caseNegativeMatrix(row), false);
});
test('wrong status fails closed with only safe numeric evidence', () => {
  const row = {};
  assert.throws(() => assertCaseDenial(row,'sellerCreateHttp',201),/LIVE_NEGATIVE_DENIAL_FAILED/);
  assert.equal(row.sellerCreateHttp, 201);
  assert.equal(caseNegativeMatrix(row), false);
});
test('unrecognized keys and nonnumeric HTTP values refused', () => {
  const row = {};
  assert.throws(() => assertCaseDenial(row,'token','secret-token'),/LIVE_NEGATIVE_OBSERVATION_INVALID/);
  assert.throws(() => assertCaseDenial(row,'customerApprovalHttp','403'),/LIVE_NEGATIVE_OBSERVATION_INVALID/);
  assert.deepEqual(row, {});
});
test('mocked evidence or response body alone never supplies a live result', () => {
  assert.equal(caseNegativeMatrix({status:'PASS',mocked:true}), false);
  assert.equal(caseNegativeMatrix(null), false);
});
