import test from 'node:test';
import assert from 'node:assert/strict';
import {APP_SCOPES, TENANT, PARTNER, CLIENT_NAME, SCOPE} from '../../../scripts/p224-user-token-core.mjs';

test('WSO2 GA application listing uses view, not a nonexistent list scope', () => {
  assert.deepEqual([...APP_SCOPES], [
    'internal_org_application_mgt_view',
    'internal_org_application_mgt_create',
    'internal_org_application_mgt_update'
  ]);
  assert.ok(!APP_SCOPES.includes('internal_org_application_mgt_list'));
});

test('user-token acceptance remains pinned to Verde and a single SCIM permission', () => {
  assert.equal(TENANT,'aurora.identity.test');
  assert.equal(PARTNER,'629e590a-9072-406d-95a8-71f0cfc52cbe');
  assert.equal(CLIENT_NAME,'Identity Lab P2 Verde User Token Acceptance');
  assert.equal(SCOPE,'internal_org_user_mgt_list');
});
