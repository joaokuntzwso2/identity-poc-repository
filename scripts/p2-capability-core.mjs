/** Matrix gates are based on documented update-level prerequisites, never guessed from OIDC discovery. */
export const DOCUMENTED_MINIMUMS = Object.freeze({
  consentManagementV2: 12,
  actorAwareTokenExchangeDelegation: 18
});
export function parseVerifiedVersion(input) {
  if (typeof input !== 'string') return null;
  const m = /^7\.3\.0(?:\.(\d{1,4}))?$/.exec(input);
  if (!m) return null;
  return { product:'7.3.0', updateLevel:Number(m[1] || 0), source:'OPERATOR_ASSERTED_NOT_RUNTIME_PROVEN' };
}
export function capabilityMatrix(version) {
  const gated = (minimum) => !version
    ? {state:'BLOCKED_UPDATE_LEVEL_UNVERIFIED',minimumUpdate:minimum}
    : version.updateLevel < minimum
      ? {state:'BLOCKED_UPDATE_LEVEL',minimumUpdate:minimum,observedUpdate:version.updateLevel}
      : {state:'ELIGIBLE_PENDING_RUNTIME_API_AND_CONFIG_VERIFICATION',minimumUpdate:minimum,observedUpdate:version.updateLevel};
  return {
    p224B2BOrganizations:{state:'PENDING_MANAGEMENT_SCOPES_AND_LIVE_READBACK',tenantBoundary:'AURORA_OR_BRISA_CHILD_ONLY'},
    p225Consent: gated(DOCUMENTED_MINIMUMS.consentManagementV2),
    p226AdaptiveAuthentication:{state:'PENDING_APP_POLICY_CONFIG_AND_REAL_AMR_ACR_AUTH_TIME'},
    p227Passkeys:{state:'PENDING_FIDO2_ORIGIN_BROWSER_AND_CREDENTIAL_LIVE_TEST'},
    p228Federation:{state:'PENDING_TRUSTED_EXTERNAL_IDP_AND_LIVE_TEST'},
    p229Lifecycle:{state:'PENDING_SCIM_GOVERNANCE_CONFIG_AND_REVOCATION_TEST'},
    p230Audit:{state:'PENDING_OBSERVED_WSO2_EVENT_SOURCES_AND_RETENTION_CONTROLS'},
    p231Branding:{state:'PENDING_TENANT_BRAND_CONFIG_AND_BROWSER_ACCEPTANCE'},
    tokenExchangeDelegation:gated(DOCUMENTED_MINIMUMS.actorAwareTokenExchangeDelegation)
  };
}
