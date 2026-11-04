import test from 'node:test';
import assert from 'node:assert/strict';
import { rootMetadata, TENANT } from '../../scripts/p2/guarded-org.mjs';
const root = '12345678-1234-4234-8234-123456789abc';
const parent = '22345678-1234-4234-8234-123456789abc';
test('WSO2 TENANT metadata permits documented parent with exact tenant handle', () => {
  assert.ok(rootMetadata({id:root,type:'TENANT',orgHandle:TENANT,parent:{id:parent}},root).rootFingerprint);
});
test('parent metadata cannot pass for another tenant or child', () => {
  assert.throws(() => rootMetadata({id:root,type:'ORGANIZATION',orgHandle:TENANT,parent:{id:parent}},root));
  assert.throws(() => rootMetadata({id:root,type:'TENANT',orgHandle:'brisa.identity.test',parent:{id:parent}},root));
});
