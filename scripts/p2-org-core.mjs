/** P2.24: strictly tenant-bound WSO2 Organization Management API v1 operations.
 * These functions are intentionally independent of the browser/BFF; never expose an
 * organization management token to front-end code. No retries after writes.
 */
import { createHash } from 'node:crypto';

export const ROOT_TENANTS = Object.freeze(['aurora.identity.test', 'brisa.identity.test']);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
function requireName(s, field, re) {
  if (typeof s !== 'string' || !re.test(s)) throw new Error(`invalid_${field}`);
  return s;
}
export function rootTenant(t) {
  if (!ROOT_TENANTS.includes(t)) throw new Error('root_tenant_not_allowlisted');
  return t;
}
function identifier(id) { return requireName(id, 'organization_id', UUID); }
export function organizationUrl(base, tenant) {
  rootTenant(tenant);
  const url = new URL(base);
  if (url.username || url.password || url.search || url.hash) throw new Error('invalid_base_url');
  return new URL(`/t/${tenant}/o/api/server/v1/organizations`, url);
}
export function approvalDigest({ tenant, name, handle, parentId, action='CREATE', id='' }) {
  rootTenant(tenant);
  identifier(parentId);
  return createHash('sha256').update(JSON.stringify({ action, tenant, name, handle, parentId, id })).digest('hex');
}
function validateDescription(x) { return typeof x === 'string' && x.length <= 256 ? x : ''; }
function validateIdentity(name, handle) {
  requireName(name, 'partner_name', /^[\p{L}\p{N}][\p{L}\p{N} ._-]{2,79}$/u);
  requireName(handle, 'partner_handle', /^[a-z][a-z0-9-]{2,39}$/);
  if (handle === 'aurora' || handle === 'brisa' || handle === 'carbon' || handle === 'super')
    throw new Error('reserved_partner_handle');
}
async function getRoot(client, uri) {
  const root = await client('GET', `${uri}/self`);
  if (!root || !UUID.test(root.id) || (root.parent && root.parent.id) ||
      (root.type && root.type !== 'TENANT') ||
      (root.hasChildren !== undefined && typeof root.hasChildren !== 'boolean'))
    throw new Error('cannot_verify_root_organization');
  return root;
}
/**
 * WSO2 supplies pagination URLs as metadata. Validate each one, but NEVER fetch
 * an untrusted href. Rebuild each GET from the tenant-pinned organization URL.
 */
const ORG_PAGE_SIZE = 100;
const ORG_MAX_PAGES = 50;
const ORG_MAX_ROWS = 5000;
function inventoryError(reason='INVALID_OR_INCOMPLETE') {
  return new Error('organization_inventory_incomplete:' + reason);
}
function nextOrganizationPage(links, uri, seenCursors) {
  if (links === undefined) return null;
  if (!Array.isArray(links) || links.length > 20) throw inventoryError('LINKS_MALFORMED');
  const next = links.filter(x => x && x.rel === 'next');
  if (next.length > 1) throw inventoryError('DUPLICATE_NEXT_LINK');
  if (!next.length) return null;
  const href = next[0].href;
  if (typeof href !== 'string' || !href || href.length > 2048 || /[\r\n]/.test(href))
    throw inventoryError('NEXT_LINK_MISSING_OR_INVALID');
  const pinned = new URL(uri);
  let link;
  try { link = new URL(href, pinned); } catch { throw inventoryError('NEXT_LINK_MALFORMED'); }
  // WSO2 documents tenantless /o/ paths in Link metadata. This is the ONLY
  // alternate path permitted; requests themselves always include the tenant.
  const tenantless = '/o/api/server/v1/organizations';
  if (link.origin !== pinned.origin || link.username || link.password || link.hash ||
      (link.pathname !== pinned.pathname && link.pathname !== tenantless))
    throw inventoryError('NEXT_LINK_OUTSIDE_TENANT');
  const allowed = new Set(['limit', 'recursive', 'after', 'next']);
  for (const key of link.searchParams.keys()) {
    if (!allowed.has(key) || link.searchParams.getAll(key).length !== 1)
      throw inventoryError('NEXT_QUERY_INVALID');
  }
  if (link.searchParams.has('recursive') && link.searchParams.get('recursive') !== 'false')
    throw inventoryError('NEXT_RECURSIVE_INVALID');
  const limitString = link.searchParams.get('limit');
  const limit = limitString === null ? ORG_PAGE_SIZE : Number(limitString);
  if (limitString !== null && !/^[1-9][0-9]*$/.test(limitString))
    throw inventoryError('NEXT_LIMIT_INVALID');
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > ORG_PAGE_SIZE)
    throw inventoryError('NEXT_LIMIT_INVALID');
  const cursorKind = link.searchParams.has('after') ? 'after' : 'next';
  if (link.searchParams.has('after') === link.searchParams.has('next'))
    throw inventoryError('NEXT_CURSOR_MISSING_OR_DUPLICATE');
  const cursor = link.searchParams.get(cursorKind);
  if (typeof cursor !== 'string' || !cursor || cursor.length > 1024 ||
      /[\x00-\x1f\x7f]/.test(cursor))
    throw inventoryError('NEXT_CURSOR_INVALID');
  if (seenCursors.has(cursorKind + ':' + cursor)) throw inventoryError('CURSOR_LOOP');
  seenCursors.add(cursorKind + ':' + cursor);
  // Construct our own URL. The advertised href is never sent to fetch().
  const request = new URL(uri);
  request.searchParams.set('limit', String(limit));
  request.searchParams.set('recursive', 'false');
  request.searchParams.set(cursorKind, cursor);
  return { url: request.href, limit };
}
/**
 * Some 7.3 installations omit the collection value for a truly empty hierarchy.
 * That representation is NOT sufficient to prove an empty inventory on its own.
 * Only accept it on the FIRST page when two independent root /self reads agree
 * that the pinned tenant root has no children, and no next link or error exists.
 */
function emptyCollectionShape(page, uri) {
  if (!page || typeof page !== 'object' || Array.isArray(page)) return false;
  // In the GA runtime, an entirely empty collection may serialize as {}.
  // This rule is NOT sufficient by itself: caller also requires two /self
  // confirmations with hasChildren === false and the correct root UUID.
  const allowed = new Set(['organizations', 'links', 'count', 'totalResults']);
  if (Object.keys(page).some(key => !allowed.has(key))) return false;
  if (page.organizations !== null && page.organizations !== undefined) return false;
  if (page.count !== undefined && page.count !== 0) return false;
  if (page.totalResults !== undefined && page.totalResults !== 0) return false;
  if (page.links === null || page.links === undefined) return true;
  if (!Array.isArray(page.links) || page.links.length > 1) return false;
  if (page.links.length === 0) return true;
  // A self link is harmless metadata only if it points to this exact tenant.
  // In particular, an empty collection with a next/previous link is never final.
  const link = page.links[0];
  if (!link || typeof link !== 'object' || Array.isArray(link) ||
      link.rel !== 'self' || typeof link.href !== 'string' ||
      !link.href || link.href.length > 2048 || /[\r\n]/.test(link.href)) return false;
  const pinned = new URL(uri);
  let parsed;
  try { parsed = new URL(link.href, pinned); } catch { return false; }
  if (parsed.origin !== pinned.origin || parsed.username || parsed.password || parsed.hash ||
      (parsed.pathname !== pinned.pathname &&
       parsed.pathname !== '/o/api/server/v1/organizations')) return false;
  for (const key of parsed.searchParams.keys()) {
    if (!['limit', 'recursive'].includes(key) || parsed.searchParams.getAll(key).length !== 1) return false;
  }
  if (parsed.searchParams.has('recursive') && parsed.searchParams.get('recursive') !== 'false') return false;
  if (parsed.searchParams.has('limit') &&
      (!/^[1-9][0-9]*$/.test(parsed.searchParams.get('limit')) ||
       Number(parsed.searchParams.get('limit')) > ORG_PAGE_SIZE)) return false;
  return true;
}
function pageMetadataCode(page) {
  // Enumerations and counts only. Never include names, payload values,
  // private URLs, cursor values, organization IDs or bearer tokens.
  if (!page || typeof page !== 'object' || Array.isArray(page)) return 'BODY_INVALID';
  const keys = Object.keys(page);
  const recognized = new Set(['organizations', 'links', 'count', 'totalResults']);
  const unexpected = keys.some(key => !recognized.has(key));
  const links = page.links;
  const linkState = links === undefined ? 'NONE' : links === null ? 'NULL' :
    !Array.isArray(links) ? 'INVALID' : links.length === 0 ? 'EMPTY' :
    links.some(link => link?.rel === 'next') ? 'NEXT' :
    links.every(link => link?.rel === 'self') ? 'SELF' : 'OTHER';
  const count = page.count === undefined ? 'ABSENT' : page.count === 0 ? 'ZERO' : 'NONZERO';
  return `KEYS_${Math.min(keys.length, 99)}_UNKNOWN_${unexpected ? 'YES' : 'NO'}_LINKS_${linkState}_COUNT_${count}`;
}
function pageShapeReason(page, index) {
  const part = !page || typeof page !== 'object' || Array.isArray(page) ? 'NOT_OBJECT'
    : page.organizations === undefined ? 'ORGS_OMITTED'
    : page.organizations === null ? 'ORGS_NULL'
    : Array.isArray(page.organizations) ? 'ORGS_ARRAY'
    : 'ORGS_INVALID_TYPE';
  return `PAGE_${index}_${part}`;
}
async function listImmediateChildren(client, uri, root) {
  const first = new URL(uri);
  first.searchParams.set('limit', String(ORG_PAGE_SIZE));
  first.searchParams.set('recursive', 'false');
  let request = {url: first.href, limit: ORG_PAGE_SIZE};
  const seenIds = new Set(), seenCursors = new Set(), records = [];
  for (let pageIndex = 0; pageIndex < ORG_MAX_PAGES; pageIndex++) {
    const page = await client('GET', request.url);
    if (!page || typeof page !== 'object' || Array.isArray(page))
      throw inventoryError(pageShapeReason(page, pageIndex));
    if (!Array.isArray(page.organizations)) {
      if (pageIndex === 0 && root.hasChildren === false && emptyCollectionShape(page, uri)) {
        // A second trusted API readback, not a guessed empty list, is required.
        const confirmation = await getRoot(client, uri);
        if (confirmation.id !== root.id || confirmation.hasChildren !== false)
          throw inventoryError('EMPTY_ROOT_RECHECK_MISMATCH');
        return [];
      }
      throw inventoryError(pageShapeReason(page, pageIndex) +
        (root.hasChildren === true ? '_ROOT_HAS_CHILDREN' :
          root.hasChildren === false ? '_ROOT_NO_CHILDREN' : '_ROOT_CHILD_COUNT_UNKNOWN') +
        ':' + pageMetadataCode(page));
    }
    if (page.organizations.length > request.limit)
      throw inventoryError(`PAGE_${pageIndex}_OVERSIZE`);
    if (pageIndex > 0 && page.organizations.length === 0)
      throw inventoryError(`PAGE_${pageIndex}_EMPTY_AFTER_CURSOR`);
    // A root attesting children cannot have a complete empty first page.
    if (pageIndex === 0 && root.hasChildren === true && page.organizations.length === 0 &&
        (!Array.isArray(page.links) || !page.links.some(link => link?.rel === 'next')))
      throw inventoryError('EMPTY_LIST_CONFLICTS_WITH_ROOT');
    for (const org of page.organizations) {
      if (!org || !UUID.test(org.id || '') || typeof org.name !== 'string' ||
          (org.orgHandle !== undefined && typeof org.orgHandle !== 'string') ||
          seenIds.has(org.id) || records.length >= ORG_MAX_ROWS)
        throw inventoryError('DUPLICATE_OR_INVALID_RECORD');
      seenIds.add(org.id);
      records.push(org);
    }
    const next = nextOrganizationPage(page.links, uri, seenCursors);
    if (!next) {
      // A full final page without pagination metadata could be truncated.
      if (page.organizations.length === request.limit) throw inventoryError('FULL_PAGE_WITHOUT_NEXT');
      if (root.hasChildren === false && records.length)
        throw inventoryError('LIST_CONFLICTS_WITH_ROOT');
      return records;
    }
    if (!page.organizations.length) throw inventoryError('EMPTY_PAGE_WITH_NEXT');
    request = next;
  }
  throw inventoryError('PAGE_LIMIT_EXCEEDED');
}

async function locate(client, uri, root, name, handle) {
  const entries = await listImmediateChildren(client, uri, root);
  // Some documented list examples omit orgHandle. Read those objects back so
  // a different-name, same-handle collision cannot be mistaken for absence.
  const candidates = [];
  for (const entry of entries) {
    if (entry.orgHandle !== undefined && entry.name !== name && entry.orgHandle !== handle)
      continue;
    const detail = await client('GET', `${uri}/${identifier(entry.id)}`);
    if (!detail || detail.id !== entry.id ||
        typeof detail.name !== 'string' || typeof detail.orgHandle !== 'string')
      throw inventoryError('DETAIL_READBACK_INVALID');
    if (detail.parent?.id !== root.id) throw new Error('partner_parent_or_identity_mismatch');
    if (detail.name === name || detail.orgHandle === handle) candidates.push(detail);
  }
  if (candidates.length > 1 ||
      candidates.some(x => x.name !== name || x.orgHandle !== handle))
    throw new Error('partner_name_or_handle_collision');
  return candidates.length ? candidates[0] : null;
}

export async function planPartner({ client, base, tenant, name, handle }) {
  validateIdentity(name, handle);
  const uri = organizationUrl(base, tenant).href;
  const root = await getRoot(client, uri);
  const existing = await locate(client, uri, root, name, handle);
  return {
    tenant, parentId: root.id, name, handle, existingId: existing?.id ?? null,
    currentStatus: existing?.status ?? null,
    decision: existing ? 'EXISTS_READBACK_VERIFIED' : 'CREATE_REQUIRES_APPROVAL',
    approval: approvalDigest({tenant,name,handle,parentId:root.id})
  };
}
function verifyPartner(readback, expected, id) {
  if (readback?.id !== id || readback.parent?.id !== expected.parentId ||
    readback.name !== expected.name || readback.orgHandle !== expected.handle)
    throw new Error('partner_post_write_readback_mismatch');
  return { id: readback.id, status: readback.status, verified: true, tenant: expected.tenant,
    parentId: expected.parentId, name: expected.name, handle: expected.handle };
}
export async function applyPartner({ client, base, tenant, name, handle, approval, description='' }) {
  // Re-plan immediately before writing to limit stale-state races. Never retry POST.
  const plan = await planPartner({client,base,tenant,name,handle});
  if (approval !== plan.approval) throw new Error('operator_approval_fingerprint_mismatch');
  const uri = organizationUrl(base,tenant).href;
  if (plan.existingId) {
    const existing = await client('GET', `${uri}/${plan.existingId}`);
    return { action:'NOOP', ...verifyPartner(existing, plan, plan.existingId) };
  }
  const result = await client('POST', uri, { name, orgHandle:handle,
    description:validateDescription(description) });
  if (!UUID.test(result?.id || '')) {
    // Unknown state must be resolved manually with a fresh read-only plan.
    throw new Error('create_response_without_id_manual_readback_required');
  }
  const record = await client('GET', `${uri}/${result.id}`);
  const verified = verifyPartner(record, plan, result.id);
  if (verified.status !== 'ACTIVE') throw new Error('partner_create_not_active_on_readback');
  return { action:'CREATED', ...verified };
}
export async function planPartnerDeactivation({client,base,tenant,name,handle}) {
  const plan = await planPartner({client,base,tenant,name,handle});
  if (!plan.existingId) throw new Error('partner_not_found');
  return { ...plan, decision:plan.currentStatus === 'DISABLED' ? 'ALREADY_DISABLED' : 'DISABLE_REQUIRES_APPROVAL',
    disableApproval:approvalDigest({tenant,name,handle,parentId:plan.parentId,action:'DISABLE',id:plan.existingId}) };
}
export async function deactivatePartner({client,base,tenant,name,handle,approval}) {
  const plan=await planPartnerDeactivation({client,base,tenant,name,handle});
  if (approval !== plan.disableApproval) throw new Error('operator_approval_fingerprint_mismatch');
  const uri=organizationUrl(base,tenant).href;
  const record=await client('GET',`${uri}/${plan.existingId}`);
  verifyPartner(record,plan,plan.existingId);
  if (record.status === 'DISABLED') return { action:'NOOP',...verifyPartner(record,plan,plan.existingId) };
  if (record.status !== 'ACTIVE') throw new Error('unrecognized_partner_status');
  if (record.hasChildren !== false && record.hasChildren !== undefined)
    throw new Error('child_organization_may_have_dependents_offboarding_blocked');
  const body = {name:record.name,orgHandle:record.orgHandle,description:record.description || '',
    status:'DISABLED',attributes:Array.isArray(record.attributes) ? record.attributes : []};
  await client('PUT',`${uri}/${plan.existingId}`,body);
  const confirmed=await client('GET',`${uri}/${plan.existingId}`);
  const verified=verifyPartner(confirmed,plan,plan.existingId);
  if (verified.status !== 'DISABLED') throw new Error('partner_disable_not_verified');
  return {action:'DISABLED',...verified};
}
