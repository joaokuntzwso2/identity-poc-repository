import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyIdToken } from '../src/oidc.js';
const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = keyPair.publicKey.export({ format: 'jwk' });
Object.assign(jwk, { kid: 'test-key-1', use: 'sig', alg: 'RS256' });
let server, issuer, port;
function makeToken(claimOverrides = {}, signatureKey = keyPair.privateKey) {
    const now = Math.floor(Date.now() / 1000);
    const payload = { iss: issuer, aud: 'test-oidc-client', sub: 'test-sector-pairwise', nonce: 'test-nonce', iat: now, exp: now + 200, ...claimOverrides };
    const a = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'test-key-1' })).toString('base64url');
    const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const c = sign('RSA-SHA256', Buffer.from(`${a}.${b}`), signatureKey).toString('base64url');
    return `${a}.${b}.${c}`;
}
test.before(async () => {
    server = createServer((req, res) => {
        const metadata = { issuer, authorization_endpoint: `${issuer.replace('/oauth2/token', '')}/oauth2/authorize`, token_endpoint: issuer, jwks_uri: `${issuer.replace('/oauth2/token', '')}/jwks`, subject_types_supported: ['pairwise'] };
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(req.url === '/jwks' ? { keys: [jwk] } : metadata));
    }); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); port = server.address().port;
    issuer = `http://127.0.0.1:${port}/oauth2/token`; process.env.ALLOW_INSECURE_LOCAL = 'true';
});
test.after(async () => { await new Promise(resolve => server.close(resolve)); });
test('JWKS-based signature verification accepts signed OIDC test fixture', async () => {
    const d = await verifyIdToken(makeToken(), { issuer, clientId: 'test-oidc-client', nonce: 'test-nonce' });
    assert.equal(d.sub, 'test-sector-pairwise');
});
test('JWKS verification rejects tampered signature and invalid nonce', async () => {
    const token = makeToken();
    const seg = token.split('.'); seg[2] = (seg[2][0] === 'A' ? 'B' : 'A') + seg[2].slice(1);
    await assert.rejects(() => verifyIdToken(seg.join('.'), { issuer, clientId: 'test-oidc-client', nonce: 'test-nonce' }), /Invalid JWT signature/);
    await assert.rejects(() => verifyIdToken(token, { issuer, clientId: 'test-oidc-client', nonce: 'incorrect-nonce' }), /nonce mismatch/);
});
