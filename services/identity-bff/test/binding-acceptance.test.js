import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyAndRecordBinding } from '../src/binding-acceptance.js';

process.env.WSO2_CIAM_BINDING_RUN_ID = 'local-test-run-0001';
const client = { clientId: 'test-client', issuer: 'https://localhost:9444/t/aurora.identity.test/oauth2/token' };
const login = { verified: true, claims: { iss: client.issuer, sub: 'not-exported' }, accessToken: 'not-exported' };

test('accepted introspection creates only sanitized proof', async () => {
  const seen = [];
  const bound = await verifyAndRecordBinding({key:'aurora-web', client, login,
    inspect: async () => ({active:true}), record: x => seen.push(x) });
  assert.equal(bound, true);
  assert.equal(seen[0].state, 'EXACT_SESSION_TOKEN_SUBJECT_BOUND');
  assert.ok(!JSON.stringify(seen).includes(login.claims.sub));
  assert.ok(!JSON.stringify(seen).includes(login.accessToken));
});
test('missing or inactive subject binding fails closed', async () => {
  const seen = [];
  assert.equal(await verifyAndRecordBinding({key:'brisa-app',client,login,
    inspect: async () => ({active:false}),record:x=>seen.push(x)}),false);
  assert.equal(seen[0].state,'NOT_VERIFIED');
  assert.equal(await verifyAndRecordBinding({key:'brisa-app',client,login,
    inspect: async () => { throw Error('token is secret'); },record:x=>seen.push(x)}),false);
  assert.equal(seen.at(-1).state,'NOT_VERIFIED');
});
test('unknown client channels are refused', async () => {
  await assert.rejects(verifyAndRecordBinding({key:'carbon-super',client,login,record:()=>{}}),
    /BINDING_PROBE_CONTEXT_INVALID/);
});
