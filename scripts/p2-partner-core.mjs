/** P2.24 delegated organization SCIM2 administration (no browser tokens).
 * Invoked using a WSO2-issued, organization-context access token. Every operation
 * re-confirms GET /organizations/self, organization ID, parent and ACTIVE state.
 * All mutations require a plan's exact approval SHA-256, then positive readback.
 */
import { createHash } from 'node:crypto';

export const ROOT_TENANTS = Object.freeze(['aurora.identity.test', 'brisa.identity.test']);
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const NAME_RE = /^p2-partner-[a-z][a-z0-9-]{2,32}$/;

function uuid(x, field) { if (typeof x !== 'string' || !UUID.test(x)) throw Error(`invalid_${field}`); return x; }
function tenant(x) { if (!ROOT_TENANTS.includes(x)) throw Error('root_tenant_not_allowlisted'); return x; }
function groupName(x) { if (typeof x !== 'string' || !NAME_RE.test(x)) throw Error('group_name_not_allowlisted'); return x; }
function clientCheck(client) { if (typeof client !== 'function') throw Error('client_required'); }
export function endpoints({ base='https://localhost:9444', rootTenant, orgId, rootId }) {
  tenant(rootTenant); uuid(orgId, 'partner_id'); uuid(rootId, 'root_id');
  if (orgId.toLowerCase() === rootId.toLowerCase()) throw Error('partner_cannot_be_root');
  const u = new URL(base);
  if (u.protocol !== 'https:' || !['localhost', '127.0.0.1'].includes(u.hostname) ||
      u.port !== '9444' || u.pathname !== '/' || u.search || u.hash || u.username || u.password)
    throw Error('only_existing_local_https_9444');
  // Organization scope comes exclusively from WSO2-issued token, not a browser-supplied org ID.
  const path = `/t/${rootTenant}/o`;
  return Object.freeze({ org:`${u.origin}${path}/api/server/v1/organizations/self`,
    groups:`${u.origin}${path}/scim2/Groups`, users:`${u.origin}${path}/scim2/Users` });
}
function digest(fields) { return createHash('sha256').update(JSON.stringify(fields)).digest('hex'); }
function members(group) {
  const entries=group?.members === undefined ? [] : group.members;
  if (!Array.isArray(entries) || entries.length > 200) throw Error('group_members_unverifiable');
  const ids = entries.map(x=>uuid(x?.value, 'member_id').toLowerCase());
  if (new Set(ids).size !== ids.length) throw Error('duplicate_member_ids');
  return ids.sort();
}
function safeGroup(group, expectedId, expectedName) {
  if (!group || (expectedId && group.id !== expectedId)) throw Error('group_id_mismatch');
  uuid(group.id, 'group_id');
  const name=group.displayName;
  if (typeof name !== 'string' || !/^(?:PRIMARY\/)?p2-partner-[a-z][a-z0-9-]{2,32}$/.test(name))
    throw Error('group_not_allowlisted');
  if (expectedName && name !== expectedName && name !== `PRIMARY/${expectedName}`)
    throw Error('group_name_mismatch');
  // Do not administer groups already mapped to application/administrative roles.
  if (!Array.isArray(group.roles) && group.roles !== undefined) throw Error('unverifiable_group_roles');
  if ((group.roles || []).length) throw Error('group_has_role_assignments_prohibited');
  return { id:group.id, displayName:name, ids:members(group) };
}
async function context(client, config) {
  clientCheck(client); const urls=endpoints(config);
  const self=await client('GET',urls.org);
  if (!self || self.id !== config.orgId || self.parent?.id !== config.rootId ||
      self.status !== 'ACTIVE' || self.id === config.rootId)
    throw Error('token_organization_context_or_status_mismatch');
  return urls;
}
/** SCIM 2.0 ListResponse inventory: verify *all* pages before any write.
 * RFC 7644 permits omitting Resources only when totalResults is zero.
 * Never infer zero from a missing totalResults or an empty HTTP response.
 */
const SCIM_PAGE_SIZE=100;
const SCIM_MAX_PAGES=30;
const SCIM_MAX_RESULTS=3000;
const SCIM_LIST_RESPONSE='urn:ietf:params:scim:api:messages:2.0:ListResponse';
function incomplete(kind,reason) { throw Error(`scim_inventory_not_complete:${kind}_${reason}`); }
function validatePage(page,kind,index,expectedTotal) {
  if (!page || typeof page!=='object' || Array.isArray(page)) incomplete(kind,'NOT_OBJECT');
  const total=page.totalResults;
  if (!Number.isSafeInteger(total) || total<0) incomplete(kind,'TOTAL_RESULTS_INVALID');
  if (total>SCIM_MAX_RESULTS) incomplete(kind,'TOTAL_RESULTS_EXCEEDS_BOUND');
  if (expectedTotal!==null && total!==expectedTotal) incomplete(kind,'TOTAL_RESULTS_CHANGED');
  if (page.schemas!==undefined && (!Array.isArray(page.schemas) ||
      !page.schemas.includes(SCIM_LIST_RESPONSE))) incomplete(kind,'SCHEMA_INVALID');
  let rows;
  if (total===0 && page.Resources===undefined) rows=[];
  else if (Array.isArray(page.Resources)) rows=page.Resources;
  else incomplete(kind,'RESOURCES_MISSING_OR_INVALID');
  if(rows.length>SCIM_PAGE_SIZE || rows.length>total) incomplete(kind,'PAGE_SIZE_INVALID');
  if (total===0 && rows.length!==0) incomplete(kind,'ZERO_TOTAL_HAS_RESOURCES');
  if (total>0 && rows.length===0) incomplete(kind,'EMPTY_NONZERO_PAGE');
  const partial=index!==1 || total>rows.length;
  if (page.startIndex!==undefined && page.startIndex!==index) incomplete(kind,'START_INDEX_MISMATCH');
  if (page.itemsPerPage!==undefined && page.itemsPerPage!==rows.length)
    incomplete(kind,'ITEMS_PER_PAGE_MISMATCH');
  if (partial && (!Number.isSafeInteger(page.startIndex) ||
       !Number.isSafeInteger(page.itemsPerPage))) incomplete(kind,'PAGINATION_METADATA_MISSING');
  return {total,rows};
}
async function listResources(client,uri,kind) {
  const all=[],seen=new Set();
  let total=null,index=1;
  for (let pageNumber=0;pageNumber<SCIM_MAX_PAGES;pageNumber++) {
    // The transport accepts only canonical, pinned startIndex/count requests.
    const response=await client('GET',`${uri}?startIndex=${index}&count=${SCIM_PAGE_SIZE}`);
    const current=validatePage(response,kind,index,total);
    if (total===null) total=current.total;
    for(const item of current.rows) {
      if (!item || typeof item.id!=='string' || !UUID.test(item.id)) incomplete(kind,'RESOURCE_ID_INVALID');
      const id=item.id.toLowerCase();
      if(seen.has(id)) incomplete(kind,'DUPLICATE_RESOURCE_ID');
      seen.add(id);all.push(item);
    }
    if(all.length===total) return all;
    if(all.length>total) incomplete(kind,'PAGE_OVERFLOW');
    index=all.length+1;
  }
  incomplete(kind,'PAGE_LIMIT_EXCEEDED');
}
function urlFor(url, id) { return `${url}/${uuid(id, 'resource_id')}`; }
export async function inspectPartner({ client, config }) {
  const urls=await context(client,config);
  const g=await listResources(client,urls.groups,'GROUPS');
  const u=await listResources(client,urls.users,'USERS');
  return { action:'INSPECT', rootTenant:config.rootTenant, partnerId:config.orgId,
    rootId:config.rootId, source:'WSO2_SCIM2_LIVE_READ', userCount:u.length,
    groupCount:g.length, userAttributesEmitted:false };
}
export async function planGroup({ client, config, name }) {
  groupName(name); const urls=await context(client,config);
  const rows=await listResources(client,urls.groups,'GROUPS');
  const collisions=rows.filter(x=>x.displayName === name || x.displayName === `PRIMARY/${name}`);
  if (collisions.length > 1) throw Error('ambiguous_group_inventory');
  let existingId=null;
  if (collisions.length) {
    const found=safeGroup(await client('GET',urlFor(urls.groups,collisions[0].id)),collisions[0].id,name);
    existingId=found.id;
  }
  return { action:'GROUP_PLAN', decision:existingId?'ALREADY_EXISTS':'CREATE_REQUIRES_APPROVAL',
    rootTenant:config.rootTenant, partnerId:config.orgId, group:name, existingId,
    approval:digest({op:'GROUP_CREATE',tenant:config.rootTenant,org:config.orgId,root:config.rootId,name}) };
}
export async function createGroup({ client, config, name, approval }) {
  const p=await planGroup({client,config,name});
  if (approval !== p.approval) throw Error('operator_approval_fingerprint_mismatch');
  const urls=endpoints(config);
  if (p.existingId) return { action:'NOOP',id:p.existingId,verified:true,partnerId:config.orgId };
  // Do not retry if response is ambiguous: re-run a read-only plan.
  const response=await client('POST',urls.groups,{schemas:[GROUP_SCHEMA],displayName:name,members:[]});
  const id=uuid(response?.id,'created_group_id');
  await context(client,config);
  const readback=safeGroup(await client('GET',urlFor(urls.groups,id)),id,name);
  if (readback.ids.length) throw Error('created_group_has_unexpected_members');
  return { action:'CREATED',id,verified:true,partnerId:config.orgId,group:name };
}
export async function planMembership({ client,config,groupId,userId,op }) {
  if (op !== 'ADD' && op !== 'REMOVE') throw Error('invalid_membership_action');
  uuid(groupId,'group_id'); uuid(userId,'user_id');
  if (groupId !== config.allowedGroupId) throw Error('group_id_not_in_operator_allowlist');
  const urls=await context(client,config);
  const group=safeGroup(await client('GET',urlFor(urls.groups,groupId)),groupId);
  const user=await client('GET',urlFor(urls.users,userId));
  if (!user || user.id !== userId || !user.userName || typeof user.userName !== 'string' ||
      user.active === false) throw Error('user_missing_inactive_or_wrong_organization');
  const present=group.ids.includes(userId.toLowerCase());
  const needed=op === 'ADD'?!present:present;
  return { action:`MEMBER_${op}_PLAN`,decision:needed?'REQUIRES_APPROVAL':'ALREADY_DESIRED',
    rootTenant:config.rootTenant,partnerId:config.orgId,groupId,userId,
    approval:digest({op,tenant:config.rootTenant,org:config.orgId,root:config.rootId,
      groupId,userId,members:group.ids,groupName:group.displayName}) };
}
export async function changeMembership({ client,config,groupId,userId,op,approval }) {
  const p=await planMembership({client,config,groupId,userId,op});
  if (p.approval !== approval) throw Error('operator_approval_fingerprint_mismatch');
  if (p.decision === 'ALREADY_DESIRED')
    return {action:'NOOP',partnerId:config.orgId,groupId,userId,verified:true};
  const urls=endpoints(config);
  const user=await client('GET',urlFor(urls.users,userId));
  if (user?.id !== userId || !user.userName || user.active === false)
    throw Error('user_changed_before_write');
  const lastGroup=safeGroup(await client('GET',urlFor(urls.groups,groupId)),groupId);
  const lastApproval=digest({op,tenant:config.rootTenant,org:config.orgId,root:config.rootId,
    groupId,userId,members:lastGroup.ids,groupName:lastGroup.displayName});
  if (lastApproval !== approval) throw Error('group_changed_before_write');
  const operation=op==='ADD'
    ? {op:'add',path:'members',value:[{value:userId,display:user.userName}]}
    : {op:'remove',path:`members[value eq ${userId}]`};
  await client('PATCH',urlFor(urls.groups,groupId),{schemas:[PATCH_SCHEMA],Operations:[operation]});
  // Fresh readback. Ambiguous failures are not retried.
  await context(client,config);
  const after=safeGroup(await client('GET',urlFor(urls.groups,groupId)),groupId);
  if (after.ids.includes(userId.toLowerCase()) !== (op==='ADD'))
    throw Error('membership_write_not_verified_manual_review_required');
  return {action:op==='ADD'?'MEMBER_ADDED':'MEMBER_REMOVED',partnerId:config.orgId,
    groupId,userId,verified:true,source:'WSO2_SCIM2_READBACK'};
}
