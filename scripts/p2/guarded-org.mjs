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
  insist(!metadata.parent?.id || (metadata.type === 'TENANT' &&
    (metadata.orgHandle === TENANT || metadata.domain === TENANT)),
    'EXPECTED_AURORA_ROOT_NOT_DESCENDANT');
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
const PARTNER_LIST_QUERY = new URLSearchParams({ filter: `name eq ${PARTNER.name}`, limit: '100', recursive: 'false' });
const ORG_LIST_MAX_PAGES = 25;
const ORG_LIST_MAX_RESULTS = 2500;

/** Only a same-origin, same-tenant cursor for the SAME filtered search is followed. */
function nextPathFor(href, seen, pinnedQuery) {
  insist(typeof href === 'string' && href.length >= 1 && href.length < 8192 &&
    !href.includes('\\') && !href.includes('#') && !href.includes('..') &&
    !href.startsWith('//'), 'ORG_NEXT_LINK_UNTRUSTED');
  let url;
  try { url = new URL(href, 'https://localhost:9444'); }
  catch { throw new GateError('ORG_NEXT_LINK_UNTRUSTED'); }
  insist(url.protocol === 'https:' && url.hostname === 'localhost' && url.port === '9444' &&
    !url.username && !url.password && !url.hash &&
    (url.pathname === ORG_BASE || url.pathname === '/o/api/server/v1/organizations'),
    'ORG_NEXT_LINK_UNTRUSTED');
  const params = url.searchParams;
  const allowed = new Set(['filter', 'limit', 'recursive', 'after', 'next']);
  insist([...params.keys()].every(k => allowed.has(k)) &&
    [...allowed].every(k => params.getAll(k).length <= 1), 'ORG_NEXT_QUERY_UNTRUSTED');
  insist(pinnedQuery.has('filter') ? (!params.has('filter') || params.get('filter') === pinnedQuery.get('filter')) : !params.has('filter'),
    'ORG_NEXT_FILTER_CHANGED');
  insist(!params.has('limit') || params.get('limit') === '100', 'ORG_NEXT_LIMIT_CHANGED');
  insist(!params.has('recursive') || params.get('recursive') === 'false', 'ORG_NEXT_RECURSIVE_CHANGED');
  const cursors = ['after', 'next'].filter(k => params.has(k));
  insist(cursors.length === 1 && params.get(cursors[0]).length > 0 &&
    params.get(cursors[0]).length <= 4096, 'ORG_NEXT_CURSOR_INVALID');
  const cursor = `${cursors[0]}:${params.get(cursors[0])}`;
  insist(!seen.has(cursor), 'ORG_PAGINATION_LOOP');
  seen.add(cursor);
  // Rebuild instead of following the external href. Keep the original filter
  // even when WSO2 emits a cursor-only link.
  const pinned = new URLSearchParams(pinnedQuery);
  pinned.set(cursors[0], params.get(cursors[0]));
  return `${ORG_BASE}?${pinned}`;
}
export function organizationNextPath(href, seen = new Set()) {
  return nextPathFor(href, seen, PARTNER_LIST_QUERY);
}

function orgLinks(body) {
  insist(body && typeof body === 'object' && !Array.isArray(body), 'ORG_LIST_RESPONSE_INVALID');
  insist(body.links === undefined || (Array.isArray(body.links) && body.links.length <= 12),
    'ORG_LIST_LINKS_INVALID');
  const links = body.links ?? [];
  insist(links.every(l => l && typeof l === 'object' &&
    typeof l.rel === 'string' && (l.href === undefined || typeof l.href === 'string')),
    'ORG_LIST_LINKS_INVALID');
  const next = links.filter(x => x.rel === 'next');
  insist(next.length <= 1, 'ORG_MULTIPLE_NEXT_LINKS');
  insist(next.length === 0 || (typeof next[0].href === 'string' && next[0].href.length > 0),
    'ORG_NEXT_LINK_MISSING_HREF');
  return next.length ? next[0].href : null;
}

/** A missing collection is never treated as empty merely because HTTP is 200. */
async function attestEmptyHierarchy(call, rootId, firstRoot) {
  const explicit = x => x?.id === rootId && x?.type === 'TENANT' &&
    (x.orgHandle === TENANT || x.domain === TENANT) && x.hasChildren === false;
  insist(explicit(firstRoot), 'ORG_EMPTY_COLLECTION_NOT_ATTESTED');
  const second = await call('GET', `${ORG_BASE}/metadata`);
  insist(second.status === 200, `ROOT_RECHECK_HTTP_${second.status}`);
  rootMetadata(second.body, rootId);
  insist(explicit(second.body), 'ORG_EMPTY_ROOT_RECHECK_DISAGREEMENT');
}

/** When filtered empty collections are omitted on GA and the root has children,
 * enumerate EVERY immediate child via a separate unfiltered, pinned GET inventory.
 * Never use an unsupported empty filtered envelope as proof of absence.
 */
async function verifyViaUnfilteredInventory(call, firstRoot) {
  const query = new URLSearchParams({ limit:'100', recursive:'false' });
  let path = `${ORG_BASE}?${query}`;
  const seen = new Set(), ids = new Set(), found = [];
  let expectedTotal;
  for (let page = 0; page < ORG_LIST_MAX_PAGES; page++) {
    const result = await call('GET', path);
    insist(result.status === 200, `ORG_FALLBACK_LIST_HTTP_${result.status}`);
    const body = result.body;
    const next = orgLinks(body);
    insist(Array.isArray(body.organizations) && body.organizations.length <= 100,
      'ORG_FALLBACK_COLLECTION_INCOMPLETE');
    const total = body.totalResults;
    if (total !== undefined) {
      insist(Number.isSafeInteger(total) && total >= 0 && total <= ORG_LIST_MAX_RESULTS,
        'ORG_FALLBACK_TOTAL_INVALID');
      if (expectedTotal === undefined) expectedTotal = total;
      else insist(expectedTotal === total, 'ORG_FALLBACK_TOTAL_CHANGED');
    }
    for (const org of body.organizations) {
      insist(org && UUID.test(org.id) && typeof org.name === 'string' &&
        org.name.length > 0 && !ids.has(org.id), 'ORG_FALLBACK_ITEM_INVALID');
      ids.add(org.id);
      if (org.name === PARTNER.name) found.push(org);
      insist(found.length <= 1, 'AMBIGUOUS_PARTNER_NAME');
    }
    insist(ids.size <= ORG_LIST_MAX_RESULTS, 'ORG_FALLBACK_TOO_MANY_ITEMS');
    if (!next) {
      insist(expectedTotal === undefined || expectedTotal === ids.size,
        'ORG_FALLBACK_TOTAL_INCONSISTENT');
      insist(!(firstRoot?.hasChildren === true && ids.size === 0),
        'ORG_FALLBACK_ROOT_CHILDREN_CONTRADICTION');
      return found;
    }
    insist(body.organizations.length > 0, 'ORG_FALLBACK_EMPTY_PAGE_WITH_NEXT');
    path = nextPathFor(next, seen, query);
  }
  throw new GateError('ORG_FALLBACK_PAGE_LIMIT');
}

/** Complete a filtered inventory; never assert absence from an incomplete page. */
export async function listPartnerOrganizations(call, rootId, firstRoot) {
  let path = `${ORG_BASE}?${PARTNER_LIST_QUERY}`;
  const cursorSeen = new Set();
  const ids = new Set();
  const matches = [];
  let expectedTotal;
  for (let page = 0; page < ORG_LIST_MAX_PAGES; page++) {
    const r = await call('GET', path);
    insist(r.status === 200, `ORG_LIST_HTTP_${r.status}`);
    const body = r.body;
    const next = orgLinks(body);
    const rawTotal = body.totalResults;
    if (rawTotal !== undefined) {
      insist(Number.isSafeInteger(rawTotal) && rawTotal >= 0 && rawTotal <= ORG_LIST_MAX_RESULTS,
        'ORG_LIST_TOTAL_INVALID');
      if (expectedTotal === undefined) expectedTotal = rawTotal;
      else insist(expectedTotal === rawTotal, 'ORG_LIST_TOTAL_CHANGED');
    }
    if (!Array.isArray(body.organizations)) {
      insist(page === 0 && (body.organizations === undefined || body.organizations === null) &&
        (rawTotal === undefined || rawTotal === 0) && !next &&
        (body.links === undefined || Array.isArray(body.links)), 'ORG_INVENTORY_INCOMPLETE');
      // Some GA builds omit an empty filtered collection. If the tenant root
      // certifies no children twice, no partner can exist. Otherwise enumerate
      // the full direct-child inventory, never assume omitted means empty.
      if (firstRoot?.hasChildren === false) {
        await attestEmptyHierarchy(call, rootId, firstRoot);
        return [];
      }
      return verifyViaUnfilteredInventory(call, firstRoot);
    }
    insist(body.organizations.length <= 100 && matches.length + body.organizations.length <= ORG_LIST_MAX_RESULTS,
      'ORG_LIST_PAGE_TOO_LARGE');
    for (const item of body.organizations) {
      insist(item && UUID.test(item.id) &&
        (item.name === undefined || item.name === PARTNER.name) &&
        (item.orgHandle === undefined || item.orgHandle === PARTNER.orgHandle),
        'ORG_LIST_PARTNER_ITEM_UNVERIFIED');
      insist(!ids.has(item.id), 'ORG_DUPLICATE_ID_ACROSS_PAGES');
      ids.add(item.id);
      matches.push(item);
    }
    insist(matches.length <= 1, 'AMBIGUOUS_PARTNER_NAME');
    if (!next) {
      insist(expectedTotal === undefined || expectedTotal === matches.length,
        'ORG_LIST_TOTAL_INCONSISTENT');
      return matches;
    }
    insist(body.organizations.length > 0, 'ORG_EMPTY_PAGE_WITH_NEXT_LINK');
    path = organizationNextPath(next, cursorSeen);
  }
  throw new GateError('ORG_PAGINATION_PAGE_LIMIT');
}

/** Report response structure only; never print identities, tokens, URLs or handles. */
export async function inspectPartnerInventory(call, rootId) {
  const meta = await call('GET', `${ORG_BASE}/metadata`);
  insist(meta.status === 200, `ROOT_METADATA_HTTP_${meta.status}`);
  rootMetadata(meta.body, rootId);
  const r = await call('GET', `${ORG_BASE}?${PARTNER_LIST_QUERY}`);
  insist(r.status === 200, `ORG_LIST_HTTP_${r.status}`);
  const body = r.body;
  const next = orgLinks(body);
  return {
    mode: 'GET_ONLY',
    rootHasChildren: typeof meta.body.hasChildren === 'boolean' ? meta.body.hasChildren : 'UNSPECIFIED',
    collection: Array.isArray(body.organizations) ? 'array' :
      body.organizations === null ? 'null' : body.organizations === undefined ? 'omitted' : 'unsupported',
    firstPageCount: Array.isArray(body.organizations) ? body.organizations.length : null,
    totalResults: Number.isSafeInteger(body.totalResults) ? body.totalResults : 'UNSPECIFIED',
    nextPageLink: Boolean(next),
    linkCount: Array.isArray(body.links) ? body.links.length : 0,
    managementWrites: 0
  };
}

export async function planPartner(call, expectedParentId) {
  const m = await call('GET', `${ORG_BASE}/metadata`);
  insist(m.status === 200, `ROOT_METADATA_HTTP_${m.status}`);
  rootMetadata(m.body, expectedParentId);
  const organizations = await listPartnerOrganizations(call, expectedParentId, m.body);
  if (!organizations.length) return { action: 'CREATE', parentFingerprint: fingerprint(expectedParentId) };
  const candidate = organizations[0];
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
