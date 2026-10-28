/** P0.09: approval-bound WSO2 OIDC reauthentication. No local OTP checking. */
import { random, makeAuthorizationUrl } from './oidc.js';

const CLIENTS = new Set(['aurora-web','aurora-app','brisa-web','brisa-app']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SAFE_ACR = /^[A-Za-z0-9_:./-]{1,160}$/;
const SAFE_AMR = /^[A-Za-z0-9_.:-]{1,80}$/;
// `attestationGate` is a constant diagnostic label, never a claim value.
export class StepUpDenied extends Error {
  constructor(code, status = 403, attestationGate) {
    super(code); this.code = code; this.status = status;
    if (attestationGate) this.attestationGate = attestationGate;
  }
}
const deny = (code, status, gate) => { throw new StepUpDenied(code, status, gate); };
export function totpPolicy(env = process.env) {
  const acr = env.WSO2_TOTP_STEPUP_ACR;
  const methods = (env.WSO2_TOTP_STEPUP_AMR || '').split(',').map(v => v.trim()).filter(Boolean);
  // Values must be independently inspected from a real WSO2 ID token and configured.
  if (!SAFE_ACR.test(acr || '') || !methods.length || methods.length > 4 ||
      methods.some(m => !SAFE_AMR.test(m)) || new Set(methods).size !== methods.length)
    deny('wso2_totp_assurance_mapping_not_configured', 503);
  return Object.freeze({ acr, methods, ttlSeconds: 300 });
}
export function beginApprovalChallenge({ session, key, brand, caseId, client, discovery, returnTo, policy, now = Date.now() }) {
  if (!session?.id || !session?.pending || !CLIENTS.has(key) || client?.brand !== brand ||
      !UUID.test(caseId) || !client.clientId || !client.redirectUri || !client.issuer)
    deny('stepup_context_invalid', 400);
  const login = session.logins?.[key];
  if (!login?.verified || login.claims?.iss !== client.issuer ||
      typeof login.claims.sub !== 'string' || !login.claims.sub)
    deny('stepup_login_required', 401);
  for (const [k,p] of Object.entries(session.pending))
    if (!p || !Number.isSafeInteger(p.at) || now - p.at > policy.ttlSeconds * 1000) delete session.pending[k];
  if (Object.keys(session.pending).length >= 8) deny('too_many_pending_authorizations', 429);
  if (Object.values(session.pending).some(p => p?.kind === 'case-approval'))
    deny('approval_challenge_already_pending', 409);
  const state = random(32), nonce = random(24), verifier = random(32);
  const intent = { kind: 'case-approval', key, brand, caseId, at: now,
    nonce, verifier, sessionId: session.id, issuer: client.issuer,
    subject: login.claims.sub, clientId: client.clientId,
    returnTo: returnTo || `/portal/${brand}/${key.endsWith('-app')?'mobile':'web'}` };
  session.pending[state] = intent;
  const destination = new URL(makeAuthorizationUrl(discovery, {
    clientId: client.clientId, redirectUri: client.redirectUri, state, nonce, verifier,
    scope: `${client.scope || 'openid'} ciam:cases:read ciam:cases:review ciam:cases:approve`, acrValues: policy.acr
  }));
  // Force a fresh WSO2 authentication transaction. Neither request parameter proves MFA.
  destination.searchParams.set('max_age', '0');
  destination.searchParams.set('prompt', 'login');
  // OIDC Core: auth_time is mandatory with max_age, but WSO2 may additionally
  // require an explicit essential ID Token claim request. Never assert a claim
  // merely because it was requested: verify the signed result below.
  // Only send the optional claims parameter if THIS issuer advertises support.
  if (discovery?.claims_parameter_supported === true) {
    destination.searchParams.set('claims', JSON.stringify({
      id_token: { auth_time: { essential: true } }
    }));
  }
  return { authorizationUrl: destination.toString(), expiresInSeconds: policy.ttlSeconds };
}
export function verifyApprovalResponse({ session, pending, key, client, claims, policy, now = Date.now() }) {
  if (pending?.kind !== 'case-approval' || !session?.id || pending.sessionId !== session.id ||
      pending.key !== key || pending.clientId !== client?.clientId ||
      pending.issuer !== client?.issuer || !UUID.test(pending.caseId) ||
      pending.brand !== client.brand || !session.logins?.[key]?.verified)
    deny('stepup_transaction_not_bound');
  const previous = session.logins[key].claims;
  if (previous?.sub !== pending.subject || previous?.iss !== client.issuer ||
      claims?.sub !== pending.subject || claims?.iss !== client.issuer)
    deny('stepup_subject_mismatch');
  const audience = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  if (!Array.isArray(audience) || !audience.includes(client.clientId) ||
      (claims.azp && claims.azp !== client.clientId)) deny('stepup_client_mismatch');
  if (!Number.isSafeInteger(pending.at) || now < pending.at || now - pending.at > policy.ttlSeconds * 1000)
    deny('stepup_expired');
  // Diagnose only signature-verified claim *classes*. Never disclose values.
  const auth = claims.auth_time;
  const atSec = Math.ceil(pending.at / 1000), nowSec = Math.floor(now / 1000);
  let gate = null;
  if (claims.acr !== policy.acr)
    gate = typeof claims.acr === 'string' && claims.acr ? 'SIGNED_ACR_MISMATCH' : 'SIGNED_ACR_MISSING';
  else if (!Array.isArray(claims.amr)) gate = 'SIGNED_AMR_MISSING_OR_INVALID';
  else if (!claims.amr.some(value => policy.methods.includes(value))) gate = 'SIGNED_AMR_TOTP_NOT_PRESENT';
  else if (auth === undefined) gate = 'SIGNED_AUTH_TIME_MISSING';
  else if (typeof auth !== 'number') gate = 'SIGNED_AUTH_TIME_WRONG_TYPE';
  else if (!Number.isSafeInteger(auth)) gate = 'SIGNED_AUTH_TIME_NON_INTEGER';
  else if (auth < atSec) gate = 'SIGNED_AUTH_TIME_BEFORE_TRANSACTION';
  else if (auth > nowSec + 2) gate = 'SIGNED_AUTH_TIME_IN_FUTURE';
  else if (nowSec - auth > policy.ttlSeconds) gate = 'SIGNED_AUTH_TIME_TOO_OLD';
  else if (!Number.isSafeInteger(claims.iat)) gate = 'SIGNED_IAT_MISSING_OR_INVALID';
  else if (claims.iat < Math.floor(pending.at / 1000)) gate = 'SIGNED_IAT_BEFORE_TRANSACTION';
  if (gate) deny('fresh_wso2_totp_not_attested', 403, gate);
  return Object.freeze({ brand: pending.brand, key, caseId: pending.caseId,
    issuer: client.issuer, subject: pending.subject, authTime: auth,
    methodAttested: true, policyAttested: true,
    returnTo: pending.returnTo });
}
