import test from 'node:test';
import assert from 'node:assert/strict';
import { parseVerifiedVersion,capabilityMatrix } from '../../../scripts/p2-capability-core.mjs';
test('base GA blocks both update-only capabilities',()=>{
  const v=parseVerifiedVersion('7.3.0');assert.equal(v.updateLevel,0);
  const m=capabilityMatrix(v);
  assert.equal(m.p225Consent.state,'BLOCKED_UPDATE_LEVEL');
  assert.equal(m.tokenExchangeDelegation.state,'BLOCKED_UPDATE_LEVEL');
});
test('version 7.3.0.12 only makes consent eligible, not complete',()=>{
  const m=capabilityMatrix(parseVerifiedVersion('7.3.0.12'));
  assert.equal(m.p225Consent.state,'ELIGIBLE_PENDING_RUNTIME_API_AND_CONFIG_VERIFICATION');
  assert.equal(m.tokenExchangeDelegation.state,'BLOCKED_UPDATE_LEVEL');
});
test('version 7.3.0.18 is not proof of live acceptance',()=>{
  const m=capabilityMatrix(parseVerifiedVersion('7.3.0.18'));
  assert.equal(m.tokenExchangeDelegation.state,'ELIGIBLE_PENDING_RUNTIME_API_AND_CONFIG_VERIFICATION');
  assert.notEqual(m.p225Consent.state,'COMPLETE');
});
test('invalid or unknown versions remain blocked',()=>{
  for(const value of ['7.2.0','7.3.0.18-dev','7.3.0.00000'])assert.equal(parseVerifiedVersion(value),null);
  assert.equal(capabilityMatrix(null).p225Consent.state,'BLOCKED_UPDATE_LEVEL_UNVERIFIED');
});
