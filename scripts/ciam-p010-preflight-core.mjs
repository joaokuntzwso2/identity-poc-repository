/** Pure, synthetic-fixture-testable assessment. Live caller supplies real readbacks only. */
export const CLIENTS = Object.freeze([
  ['aurora-web', 'aurora','web'], ['aurora-app','aurora','app'],
  ['brisa-web','brisa','web'], ['brisa-app','brisa','app']
]);
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
export function assessReadbacks(me, status, policy) {
  const out = {}, expected = new Set(CLIENTS.map(([k]) => k));
  const statuses = Array.isArray(status?.statuses) ? status.statuses : [];
  const duplicates = statuses.length !== 4 || new Set(statuses.map(x=>x?.key)).size !== statuses.length;
  const unknown = statuses.some(x=>!expected.has(x?.key));
  const goodIdentity = object(me) && me.identitySource === 'NO_VERIFIED_IDENTITY' && me.authenticated === false;
  const goodMode = object(status) && status.identityMode === 'live-wso2';
  const goodPolicy = object(policy) && policy.mode === 'GET_ONLY' && policy.remoteWrites === 0 &&
    policy.stage === 'P010_WSO2_APP_ASSURANCE_READBACK';
  let all = goodIdentity && goodMode && goodPolicy && !duplicates && !unknown;
  for (const [key,brand,channel] of CLIENTS) {
    const runtime = me?.clients?.[key];
    const discovery = statuses.find(x=>x?.key === key);
    const app = policy?.tenants?.[brand]?.[channel];
    const row = {
      runtimeConfigured: runtime?.configured === true,
      runtimeDiscoveryVerified: discovery?.discovery === true,
      wso2RegistrationVerified: app?.registeredApplicationVerified === true,
      callbackVerified: app?.callbackVerified === true,
      codeAndPkceS256Verified: app?.codeAndPkceS256Verified === true,
      applicationRoleAudienceVerified: app?.roleAudience === 'APPLICATION',
      authenticationSequenceType: typeof app?.sequenceType === 'string' ? app.sequenceType : 'NOT_ATTESTED',
      totpChallengePerformed: false, liveLoginVerified: false,
    };
    // The existing anonymous endpoint cannot attest actual login or matching secrets.
    row.readyForInteractiveLogin = row.runtimeConfigured && row.runtimeDiscoveryVerified &&
      row.wso2RegistrationVerified && row.callbackVerified &&
      row.codeAndPkceS256Verified && row.applicationRoleAudienceVerified;
    if (!row.readyForInteractiveLogin) all = false;
    out[key] = row;
  }
  return {
    stage:'P008_P010_RUNTIME_AND_MANAGEMENT_PREFLIGHT_V2', remoteWrites:0,
    browserLoginsPerformed:0, totpChallengePerformed:false,
    fourClientsReadyForInteractiveLogin: all,
    actualSignedTokenIssuerSubjectAndUserinfoAttested:false,
    configuredTotpAssuranceAttested:false,
    clients:out,
    status:all?'FOUR_REGISTERED_RUNTIME_DISCOVERY_VERIFIED_LIVE_LOGIN_MFA_PENDING':'BLOCKED_PREFLIGHT',
  };
}
