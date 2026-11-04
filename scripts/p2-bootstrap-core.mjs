/** Automatic P2.24 reconciliation. Never authorizes its own privilege. */
import { planPartner, applyPartner } from './p2-org-core.mjs';
import { inspectPartner, planGroup, createGroup } from './p2-partner-core.mjs';
export const ROOT_SCOPES = Object.freeze(['internal_org_organization_view','internal_org_organization_create']);
export const PARTNER_SCOPES = Object.freeze([
  'internal_org_organization_view','internal_org_user_mgt_list','internal_org_user_mgt_view',
  'internal_org_group_mgt_view','internal_org_group_mgt_create','internal_org_group_mgt_update'
]);
export const DEFAULT_PLAN = Object.freeze({tenant:'aurora.identity.test',name:'Verde Logistics',handle:'verde-logistics',group:'p2-partner-operations'});
const must=(v,code)=>{if(!v)throw Error(code);return v;};
export function checkScopes(granted,expected) {
  const scopes=new Set(typeof granted==='string'?granted.split(/\s+/).filter(Boolean):[]);
  const missing=expected.filter(s=>!scopes.has(s));
  if(missing.length) throw Error(`BOOTSTRAP_AUTHORITY_BLOCKED_missing_scopes:${missing.join(',')}`);
  return true;
}
export function validatePlan(plan) {
  if (!plan || plan.tenant !== DEFAULT_PLAN.tenant || plan.name !== DEFAULT_PLAN.name ||
      plan.handle !== DEFAULT_PLAN.handle || plan.group !== DEFAULT_PLAN.group)
    throw Error('BOOTSTRAP_TARGET_BLOCKED_not_fixed_aurora_partner');
  return plan;
}
/** Explicit caller intention is the bootstrap command itself. No browser or external ID controls target. */
export async function reconcile({base='https://localhost:9444',plan=DEFAULT_PLAN,
  tokenProvider,rootClientFactory,partnerClientFactory,shareApplication,write=false}) {
  validatePlan(plan);
  must(tokenProvider && rootClientFactory && partnerClientFactory,'bootstrap_dependencies_required');
  const rootToken=await tokenProvider.root(plan.tenant,ROOT_SCOPES);
  checkScopes(rootToken.scope,ROOT_SCOPES);
  const rootClient=rootClientFactory(rootToken.access_token);
  const organization=await planPartner({client:rootClient,base,tenant:plan.tenant,name:plan.name,handle:plan.handle});
  const result={phase:'P2.24',mode:write?'APPLY':'CHECK',tenant:plan.tenant,
    partnerName:plan.name,partnerHandle:plan.handle,rootId:organization.parentId,
    existingId:organization.existingId,decisions:[],liveEvidence:'PENDING'};
  if(!write) {
    result.decisions.push(organization.decision);
    if (organization.existingId && shareApplication) {
      const sharing=await shareApplication(organization.existingId,'check');
      result.applicationSharing=sharing.state;
      if (sharing.state==='VERIFIED') {
        // Full read-only partner SCIM preflight; no group or application writes.
        const partnerToken=await tokenProvider.partner(plan.tenant,organization.existingId,
          PARTNER_SCOPES,rootToken.access_token);
        checkScopes(partnerToken.scope,PARTNER_SCOPES);
        const config={base,rootTenant:plan.tenant,rootId:organization.parentId,
          orgId:organization.existingId};
        const partnerClient=partnerClientFactory(partnerToken.access_token,config);
        const inventory=await inspectPartner({client:partnerClient,config});
        const group=await planGroup({client:partnerClient,config,name:plan.group});
        result.scimInventory='VERIFIED';
        result.counts={users:inventory.userCount,groups:inventory.groupCount};
        result.groupDecision=group.decision;
        result.existingGroupId=group.existingId;
      }
    }
    return result;
  }
  // The bootstrap invocation is the explicit scope-bounded authorization. No approval digest is user-copied.
  const committed=await applyPartner({client:rootClient,base,tenant:plan.tenant,
    name:plan.name,handle:plan.handle,approval:organization.approval});
  must(committed.verified && committed.parentId===organization.parentId,'bootstrap_partner_readback_failed');
  result.partnerId=committed.id;
  result.decisions.push(committed.action);
  must(typeof shareApplication==='function','bootstrap_sharing_stage_required');
  const sharing=await shareApplication(committed.id,'apply');
  must(sharing?.state==='VERIFIED' && sharing.remoteReadback==='VERIFIED',
    'bootstrap_partner_application_sharing_not_verified');
  result.applicationSharing='VERIFIED';
  // Critical boundary: root bearer cannot perform partner SCIM. Obtain an actual switched token.
  const partnerToken=await tokenProvider.partner(plan.tenant,committed.id,PARTNER_SCOPES,rootToken.access_token);
  checkScopes(partnerToken.scope,PARTNER_SCOPES);
  const config={base,rootTenant:plan.tenant,rootId:organization.parentId,orgId:committed.id};
  const partnerClient=partnerClientFactory(partnerToken.access_token,config);
  const scopeReadback=await inspectPartner({client:partnerClient,config});
  must(scopeReadback.partnerId===committed.id,'bootstrap_partner_context_readback_failed');
  const group=await planGroup({client:partnerClient,config,name:plan.group});
  const groupResult=await createGroup({client:partnerClient,config,name:plan.group,approval:group.approval});
  must(groupResult.verified && groupResult.partnerId===committed.id,'bootstrap_group_readback_failed');
  result.groupId=groupResult.id;
  result.decisions.push(groupResult.action);
  result.groupName=plan.group;
  result.counts={users:scopeReadback.userCount,groups:scopeReadback.groupCount};
  result.liveEvidence='WSO2_READBACK_VERIFIED';
  return result;
}
