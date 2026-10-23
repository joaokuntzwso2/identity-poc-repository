import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyRs256Jwt, assertDelegation } from '../../../scripts/identity/token-exchange-core.mjs';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'key1', use: 'sig', alg: 'RS256' };
function jwt(payload) {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'key1' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url'); const input = `${header}.${body}`;
    const sig = sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url'); return `${input}.${sig}`;
}
const issuer = 'https://idp.example'; const exp = Math.floor(Date.now() / 1000) + 3600;
test('cryptographic JWT validation including issuer and signature', () => {
    const signed = jwt({ iss: issuer, sub: 'synthetic', exp, scope: 'profile.read order.read' });
    assert.equal(verifyRs256Jwt(signed, { issuer, jwks: { keys: [jwk] } }).sub, 'synthetic');
    assert.throws(() => verifyRs256Jwt(signed, { issuer: 'https://wrong.example', jwks: { keys: [jwk] } }), /issuer/);
    const tampered = signed.replace('synthetic', 'invalid'); // no change to base64, checked below
    assert.ok(tampered === signed);
    const pieces = signed.split('.'); pieces[1] = Buffer.from(JSON.stringify({ iss: issuer, sub: 'tampered', exp })).toString('base64url');
    assert.throws(() => verifyRs256Jwt(pieces.join('.'), { issuer, jwks: { keys: [jwk] } }), /signature/);
});
test('actor preserved and privilege reduced', () => {
    const proof = assertDelegation({
        subject: { sub: 'person', scope: 'order.read order.write' }, actor: { sub: 'agent' },
        issued: { sub: 'person', act: { sub: 'agent' }, scope: 'order.read', aud: 'orders' },
        response: { issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', scope: 'order.read' },
        requestedScope: 'order.read', expectedAudience: 'orders'
    });
    assert.equal(proof.status, 'DELEGATION_ASSERTIONS_PASSED');
});
test('reject escalation and missing actor and missing issued_token_type', () => {
    const x = {
        subject: { sub: 'person', scope: 'order.read' }, actor: { sub: 'agent' }, issued: { sub: 'person', act: { sub: 'agent' }, scope: 'order.write' },
        response: { issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' }, requestedScope: 'order.write'
    };
    assert.throws(() => assertDelegation(x), /scope_escalation/);
    assert.throws(() => assertDelegation({ ...x, issued: { ...x.issued, scope: 'order.read', act: undefined } }), /actor_chain/);
    assert.throws(() => assertDelegation({ ...x, issued: { ...x.issued, scope: 'order.read' }, response: {} }), /issued_token_type/);
});
import { performTokenExchange } from '../../../scripts/identity/token-exchange-service.mjs';
test('sends genuine actor-aware RFC 8693 form only to approved token endpoint', async () => {
    let seen;
    const answer = await performTokenExchange({
        tokenEndpoint: 'https://issuer.example/oauth2/token', clientId: 'client-1', clientSecret: 'private',
        subjectToken: 'subject.jwt.sig', actorToken: 'agent.jwt.sig', scope: 'order.read', audience: 'orders',
        fetchFn: async (u, options) => { seen = { u, options }; return { ok: true, json: async () => ({ access_token: 'test-return-only', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' }) }; }
    });
    assert.equal(answer.access_token, 'test-return-only');
    assert.equal(seen.options.body.get('actor_token'), 'agent.jwt.sig');
    assert.equal(seen.options.body.get('actor_token_type'), 'urn:ietf:params:oauth:token-type:jwt');
    assert.equal(seen.options.body.get('subject_token'), 'subject.jwt.sig');
    assert.equal(seen.options.body.get('grant_type'), 'urn:ietf:params:oauth:grant-type:token-exchange');
    assert.equal(seen.options.body.get('audience'), 'orders');
    assert.equal(seen.options.redirect, 'error');
    await assert.rejects(performTokenExchange({ tokenEndpoint: 'http://evil.example', clientId: 'a', clientSecret: 'b', subjectToken: 'c', actorToken: 'd', scope: 's' }), /untrusted_token_endpoint/);
});
