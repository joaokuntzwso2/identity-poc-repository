import test from 'node:test';
import assert from 'node:assert/strict';
import { getRuntimeEnv } from '../../../scripts/ciam-live-start.mjs';

test('canonical CIAM startup includes existing four-client live launch, cases and TOTP assurance', () => {
  const env = getRuntimeEnv();
  assert.equal(env.IDENTITY_MODE, 'live-wso2');
  assert.equal(env.ALLOW_INSECURE_LOCAL, 'true');
  assert.equal(env.PUBLIC_ORIGIN, 'http://127.0.0.1:4400');
  assert.equal(env.PORT, '4400');
  assert.equal(env.WSO2_BFF_PRIVATE_MANIFEST, 'var/wso2/identity-bff-v10.private.json');
  assert.equal(env.WSO2_CASES_SCOPES_ENABLED, '1');
  assert.equal(env.WSO2_CASES_API_AUDIENCE, 'urn:ciampoc:service-requests:v1');
  assert.equal(env.WSO2_TOTP_STEPUP_ACR, 'urn:ciampoc:assurance:totp:v1');
  assert.equal(env.WSO2_TOTP_STEPUP_AMR, 'totp');
  assert.ok(env.CIAM_BUSINESS_DATA_DIR.startsWith('/'));
  assert.ok(env.NODE_EXTRA_CA_CERTS.endsWith('/.config/ciam/wso2-local.pem'));
});

test('the launcher retains existing bootstrap-provided authority settings', () => {
  const old = process.env.WSO2_BUSINESS_API_AUDIENCE;
  try {
    process.env.WSO2_BUSINESS_API_AUDIENCE = 'urn:example:existing:profile';
    assert.equal(getRuntimeEnv().WSO2_BUSINESS_API_AUDIENCE, 'urn:example:existing:profile');
  } finally {
    if (old === undefined) delete process.env.WSO2_BUSINESS_API_AUDIENCE;
    else process.env.WSO2_BUSINESS_API_AUDIENCE = old;
  }
});

test('production refuses locally-insecure launch', () => {
  const old = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    assert.throws(() => getRuntimeEnv(), /LOCAL_HTTP_NOT_ALLOWED_IN_PRODUCTION/);
  } finally {
    if (old === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = old;
  }
});
