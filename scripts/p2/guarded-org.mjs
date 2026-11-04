/**
 * P2 source-only, deliberately narrow WSO2 7.3 org + SCIM operator adapter.
 * Does not mint tokens, grant permissions, manage Carbon Super or perform browser auth.
 * WSO2 API docs: /t/{tenant}/o/api/server/v1/organizations and /t/{tenant}/o/scim2.
 */
import { createHash } from 'node:crypto';

export const TENANT = 'aurora.identity.test';
export const PARTNER = Object.freeze({
  name: 'Aurora Returns & Fulfillment Partner',
  orgHandle: 'aurora-returns-fulfillment',
  description: 'Partner team for Aurora returns and fulfillment assistance; customer business access is separately authorized.'
});
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ORG_BASE = `/t/${TENANT}/o/api/server/v1/organizations`;
const SCIM_BASE = `/t/${TENANT}/o/scim2`;
const ALLOWED_PATHS = [ORG_BASE, SCIM_BASE];

export class GateError extends Error {
  constructor(code) { super(code); this.name = 'GateError'; this.code = code; }
}
export function insist(condition, code) { if (!condition) throw new GateError(code); }
export function fingerprint(id) {
  insist(typeof id === 'string' && id.length < 512, 'IDENTIFIER_INVALID');
  return createHash('sha256').update(id).digest('hex').slice(0, 16);
}
export function makeTransport({ origin, bearer, fetcher = globalThis.fetch }) {
  let parsed;
  try { parsed = new URL(origin); } catch { throw new GateError('ORIGIN_INVALID'); }
  insist(parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '' &&
    !parsed.search && !parsed.hash && parsed.pathname === '/' &&
    parsed.hostname === 'localhost' && parsed.port === '9444', 'PINNED_LOCAL_HTTPS_ORIGIN_REQUIRED');
  insist(typeof bearer === 'string' && bearer.trim() === bearer && bearer.length > 24,
    'PRIVATE_BEARER_TOKEN_INVALID');
  return async (method, path, payload = null) => {
    insist(['GET', 'POST', 'PATCH'].includes(method), 'HTTP_METHOD_DENIED');
    insist(path.startsWith('/') && !path.startsWith('//') && !path.includes('..') &&
      !path.includes('\\') && !path.includes('#') &&
      ALLOWED_PATHS.some(prefix => path === prefix || path.startsWith(prefix + '/') || path.startsWith(prefix + '?')),
      'CROSS_TENANT_OR_PATH_DENIED');
    insist(!(method === 'GET' && payload !== null), 'GET_WITH_BODY_DENIED');
    const target = new URL(path, parsed);
    insist(target.origin === parsed.origin &&
      ALLOWED_PATHS.some(prefix => target.pathname === prefix || target.pathname.startsWith(prefix + '/')),
      'NORMALIZED_PATH_OUTSIDE_AURORA_DENIED');
    const headers = {
      authorization: `Bearer ${bearer}`,
      accept: path.includes('/scim2/') ? 'application/scim+json' : 'application/json'
    };
    if (payload !== null) headers['content-type'] = path.includes('/scim2/') ? 'application/scim+json' : 'application/json';
    let response;
    try {
      response = await fetcher(target.href, {
        method, headers, redirect: 'manual', signal: AbortSignal.timeout(12_000),
        ...(payload === null ? {} : { body: JSON.stringify(payload) })
      });
    } catch { throw new GateError('WSO2_REQUEST_OUTCOME_UNKNOWN_NO_RETRY'); }
    insist(Number.isInteger(response.status) && response.status >= 100 && response.status <= 599, 'WSO2_STATUS_INVALID');
    insist(response.status < 300 || response.status >= 400, 'WSO2_REDIRECT_REFUSED');
    let txt;
    try { txt = await response.text(); } catch { throw new GateError('WSO2_RESPONSE_READ_FAILED'); }
    insist(txt.length < 256_000, 'WSO2_RESPONSE_TOO_LARGE');
    let body = {};
    if (txt.trim()) { try { body = JSON.parse(txt); } catch { throw new GateError('WSO2_JSON_INVALID'); } }
    return { status: response.status, body };
  };
}
export function rootMetadata(metadata, expectedRootId) {
  insist(UUID.test(expectedRootId), 'EXPECTED_ROOT_UUID_REQUIRED');
  // Only an unambiguous ID at the documented metadata root is accepted.
  insist(metadata && metadata.id === expectedRootId, 'ROOT_ORGANIZATION_CONTEXT_MISMATCH');
  insist(!metadata.parent?.id, 'EXPECTED_AURORA_ROOT_NOT_DESCENDANT');
  return { rootFingerprint: fingerprint(expectedRootId) };
}
export function childMetadata(metadata, expectedChildId, parentId) {
  insist(UUID.test(expectedChildId) && UUID.test(parentId) && expectedChildId !== parentId,
    'CHILD_PARENT_IDS_INVALID');
  insist(metadata && metadata.id === expectedChildId, 'CHILD_ORGANIZATION_CONTEXT_MISMATCH');
  insist(metadata.parent?.id === parentId, 'CHILD_PARENT_CONTEXT_MISMATCH');
  return { childFingerprint: fingerprint(expectedChildId) };
}
function validateOrg(o, expectedParentId) {
  insist(o && UUID.test(o.id) && o.name === PARTNER.name &&
    o.orgHandle === PARTNER.orgHandle && o.parent?.id === expectedParentId,
    'PARTNER_ORGANIZATION_READBACK_MISMATCH');
  insist(o.status === 'ACTIVE', 'PARTNER_ORGANIZATION_NOT_ACTIVE');
  return o;
}
export async function planPartner(call, expectedParentId) {
  const m = await call('GET', `${ORG_BASE}/metadata`);
  insist(m.status === 200, `ROOT_METADATA_HTTP_${m.status}`);
  rootMetadata(m.body, expectedParentId);
  const query = new URLSearchParams({ filter: `name eq ${PARTNER.name}`, limit: '100', recursive: 'false' });
  const result = await call('GET', `${ORG_BASE}?${query}`);
  insist(result.status === 200, `ORG_LIST_HTTP_${result.status}`);
  insist(Array.isArray(result.body.organizations) &&
    !result.body.links?.some(link => link?.rel === 'next'), 'ORG_INVENTORY_INCOMPLETE');
  insist(result.body.organizations.length <= 1, 'AMBIGUOUS_PARTNER_NAME');
  insist(result.body.totalResults === undefined || result.body.totalResults === result.body.organizations.length,
    'ORG_LIST_TOTAL_INCONSISTENT');
  if (!result.body.organizations.length) return { action: 'CREATE', parentFingerprint: fingerprint(expectedParentId) };
  const candidate = result.body.organizations[0];
  insist(UUID.test(candidate?.id), 'ORG_LIST_ITEM_INVALID');
  const check = await call('GET', `${ORG_BASE}/${candidate.id}`);
  insist(check.status === 200, `PARTNER_GET_HTTP_${check.status}`);
  validateOrg(check.body, expectedParentId);
  return { action: 'ALREADY_PRESENT', parentFingerprint: fingerprint(expectedParentId),
    organizationFingerprint: fingerprint(check.body.id), id: check.body.id };
}
export async function createPartner(call, expectedParentId, beforeMutation) {
  const plan = await planPartner(call, expectedParentId);
  if (plan.action === 'ALREADY_PRESENT') return { ...plan, created: false };
  // Durable journal intent MUST be written before POST to prevent blind retries.
  await beforeMutation({ expectedParentId, name: PARTNER.name, orgHandle: PARTNER.orgHandle });
  const result = await call('POST', ORG_BASE, { ...PARTNER, parentId: expectedParentId });
  insist(result.status === 201, `ORG_CREATE_OUTCOME_UNCERTAIN_HTTP_${result.status}`);
  insist(UUID.test(result.body?.id), 'ORG_CREATE_ID_MISSING_NO_RETRY');
  const check = await call('GET', `${ORG_BASE}/${result.body.id}`);
  insist(check.status === 200, `ORG_CREATED_READBACK_HTTP_${check.status}`);
  validateOrg(check.body, expectedParentId);
  return { action: 'CREATED_AND_VERIFIED', created: true, organizationFingerprint: fingerprint(check.body.id), id: check.body.id };
}
export async function inventoryChild(call, childId, parentId) {
  const meta = await call('GET', `${ORG_BASE}/metadata`);
  insist(meta.status === 200, `CHILD_METADATA_HTTP_${meta.status}`);
  childMetadata(meta.body, childId, parentId);
  const result = await call('GET', `${SCIM_BASE}/Users?startIndex=1&count=100`);
  insist(result.status === 200, `CHILD_SCIM_USERS_HTTP_${result.status}`);
  insist(Array.isArray(result.body?.Resources) && Number.isInteger(result.body.totalResults), 'SCIM_USERS_RESPONSE_INVALID');
  insist(result.body.totalResults <= result.body.Resources.length, 'SCIM_USERS_INVENTORY_INCOMPLETE');
  return { organizationFingerprint: fingerprint(childId), users: result.body.Resources.map(u => ({
    idFingerprint: fingerprint(u.id), active: u.active === true ? true : u.active === false ? false : 'UNKNOWN'
  })) };
}
export async function disableChildUser(call, childId, parentId, userId, beforeMutation) {
  insist(UUID.test(userId), 'TARGET_USER_ID_INVALID');
  const meta = await call('GET', `${ORG_BASE}/metadata`);
  insist(meta.status === 200, `CHILD_METADATA_HTTP_${meta.status}`);
  childMetadata(meta.body, childId, parentId);
  const p = `${SCIM_BASE}/Users/${userId}`;
  const before = await call('GET', p);
  insist(before.status === 200, `CHILD_TARGET_USER_HTTP_${before.status}`);
  insist(before.body?.id === userId, 'CHILD_TARGET_USER_ID_MISMATCH');
  if (before.body.active === false) return { action: 'ALREADY_DISABLED', userFingerprint: fingerprint(userId) };
  insist(before.body.active === true, 'TARGET_ACTIVE_STATE_UNVERIFIED');
  await beforeMutation({ childId, userId, operation: 'set-active-false' });
  const r = await call('PATCH', p, {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{ op: 'replace', path: 'active', value: false }]
  });
  insist(r.status === 200 || r.status === 204, `USER_PATCH_OUTCOME_UNCERTAIN_HTTP_${r.status}`);
  const after = await call('GET', p);
  insist(after.status === 200 && after.body?.id === userId && after.body.active === false,
    'USER_DISABLE_READBACK_NOT_CONFIRMED');
  return { action: 'DISABLED_AND_VERIFIED', userFingerprint: fingerprint(userId) };
}
