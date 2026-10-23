import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { consentKey, validateConsentInput, DurableConsentRepository } from '../src/identity/consent-repository.js';
const d = {
    subjectKey: consentKey({ issuer: 'https://issuer.example', subject: 'not-a-real-id' }), issuer: 'https://issuer.example', brand: 'aurora',
    clientKey: 'aurora-web', targetBrand: 'brisa', purpose: 'delivery', scope: 'profile.read'
};
test('key is scoped to issuer and subject; never contains raw PII', () => {
    assert.notEqual(consentKey({ issuer: 'a', subject: 'b' }), consentKey({ issuer: 'b', subject: 'b' }));
    assert.match(d.subjectKey, /^[0-9a-f]{64}$/);
});
test('consent requires origin/target isolation and explicit purpose/scope', () => {
    assert.throws(() => validateConsentInput({ ...d, targetBrand: 'aurora' }));
    assert.throws(() => validateConsentInput({ ...d, scope: '' }));
    assert.throws(() => validateConsentInput({ ...d, brand: 'other' }));
    assert.ok(validateConsentInput(d));
});
test('missing consent denies by default even with database connection', async () => {
    const repo = new DurableConsentRepository({ query: async () => ({ rows: [] }) });
    assert.equal((await repo.evaluate(d)).decision, 'DENY');
});
test('grant writes state and event in a single transaction', async () => {
    const calls = [];
    const client = { query: async (sql, args) => { calls.push([sql, args]); return sql.includes('SELECT revision') ? { rows: [{ revision: 2 }] } : { rows: [] }; }, release: () => calls.push(['RELEASE']) };
    const repo = new DurableConsentRepository({ connect: async () => client });
    const result = await repo.record({ ...d, decision: 'GRANTED' });
    assert.equal(result.revision, 3); assert.equal(result.decision, 'GRANTED');
    assert.ok(calls.some(c => c[0] === 'COMMIT')); assert.ok(calls.some(c => c[0].startsWith('INSERT INTO identity_poc.consent_events')));
});
test('write failure rolls back and releases connection', async () => {
    const calls = []; const client = { query: async sql => { calls.push(sql); if (sql.includes('SELECT revision')) throw new Error('db_down'); return { rows: [] }; }, release: () => calls.push('RELEASE') };
    const repo = new DurableConsentRepository({ connect: async () => client });
    await assert.rejects(repo.record({ ...d, decision: 'GRANTED' }), /db_down/);
    assert.ok(calls.includes('ROLLBACK')); assert.ok(calls.includes('RELEASE'));
});
