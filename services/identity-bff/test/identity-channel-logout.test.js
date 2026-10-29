import test from 'node:test';
import assert from 'node:assert/strict';
import { endChannelSession } from '../src/channel-logout.js';

const clients = Object.freeze({
  'aurora-web': {}, 'aurora-app': {}, 'brisa-web': {}, 'brisa-app': {}
});
function fixture() {
  return {
    logins: {
      'aurora-web': { accessToken: 'aurora-web-token' },
      'aurora-app': { accessToken: 'aurora-app-token' },
      'brisa-web': { accessToken: 'brisa-web-token' }
    },
    pending: {
      a: { key: 'aurora-web', kind: 'case-approval', caseId: 'a' },
      b: { key: 'aurora-app', kind: 'login' },
      c: { key: 'brisa-web', kind: 'case-approval', caseId: 'b' },
      d: { key: 'aurora-web', kind: 'login' }
    }
  };
}

test('Aurora Web local logout preserves Aurora Mobile and Brisa Web', () => {
  const s = fixture();
  assert.equal(endChannelSession(s, 'aurora-web', clients), true);
  assert.equal(Object.hasOwn(s.logins, 'aurora-web'), false);
  assert.deepEqual(Object.keys(s.logins).sort(), ['aurora-app', 'brisa-web']);
});

test('logout cancels only target-channel pending login and MFA transactions', () => {
  const s = fixture();
  assert.equal(endChannelSession(s, 'aurora-web', clients), true);
  assert.deepEqual(Object.keys(s.pending).sort(), ['b', 'c']);
  assert.equal(s.pending.c.kind, 'case-approval');
});

test('unknown channel and malformed sessions fail closed without erasing other logins', () => {
  const s = fixture();
  const copy = structuredClone(s);
  assert.equal(endChannelSession(s, 'aurora-unknown', clients), false);
  assert.equal(endChannelSession(s, '', clients), false);
  assert.equal(endChannelSession(null, 'aurora-web', clients), false);
  assert.deepEqual(s, copy);
});

test('repeat logout is idempotent and does not touch other channel state', () => {
  const s = fixture();
  assert.equal(endChannelSession(s, 'aurora-web', clients), true);
  const after = structuredClone(s);
  assert.equal(endChannelSession(s, 'aurora-web', clients), true);
  assert.deepEqual(s, after);
});
