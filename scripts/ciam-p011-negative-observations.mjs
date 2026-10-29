/** Only exact HTTP deny codes, no URLs, bodies, sessions, or credentials. */
export const REQUIRED_CASE_NEGATIVES = Object.freeze({
  crossTenantHttp: 403,
  customerApprovalHttp: 403,
  wrongTenantClientHttp: 403,
  anonymousCasesHttp: 401,
  anonymousCreateHttp: 401,
  customerMissingCsrfHttp: 403,
  malformedCaseHttp: 400,
  customerWrongMethodHttp: 405,
  sellerCreateHttp: 403,
  sellerCrossTenantHttp: 403,
  duplicateApprovalHttp: 409,
});
const KNOWN_KEYS = new Set(Object.keys(REQUIRED_CASE_NEGATIVES));
export function assertCaseDenial(observations, name, status) {
  if (!KNOWN_KEYS.has(name) || !Number.isInteger(status) || status < 100 || status > 599)
    throw new Error('LIVE_NEGATIVE_OBSERVATION_INVALID');
  // Store only allowlisted integer HTTP status; never an error body or URL.
  observations[name] = status;
  if (status !== REQUIRED_CASE_NEGATIVES[name])
    throw new Error('LIVE_NEGATIVE_DENIAL_FAILED');
  return true;
}
export function caseNegativeMatrix(observations) {
  if (!observations || typeof observations !== 'object' || Array.isArray(observations)) return false;
  return Object.entries(REQUIRED_CASE_NEGATIVES).every(([key, status]) =>
    Object.hasOwn(observations, key) && observations[key] === status);
}
