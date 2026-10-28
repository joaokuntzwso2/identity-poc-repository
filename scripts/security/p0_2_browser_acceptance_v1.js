/* P0 #2: browser-only, same-session acceptance. No credentials, cookies or tokens are read. */
(() => {
  'use strict';
  const ORIGIN = 'http://127.0.0.1:4400';
  const KEY = 'ciam-v10:p0-2:aurora-web:read-only-baseline:v1';
  if (location.origin !== ORIGIN) throw new Error('REFUSE_WRONG_ORIGIN');
  const fetchJson = async (path) => {
    const response = await fetch(ORIGIN + path, {
      method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: { accept: 'application/json' }
    });
    const raw = await response.text();
    let body = {};
    try { body = JSON.parse(raw); } catch { throw new Error('REFUSE_NON_JSON_RESPONSE'); }
    if (body === null || typeof body !== 'object' || Array.isArray(body))
      throw new Error('REFUSE_BAD_RESPONSE_SHAPE');
    return { status: response.status, body };
  };
  const check = (value, code) => { if (!value) throw new Error(code); };
  const profilePath = '/api/protected/profile?client=aurora-web';
  const safeOutput = (obj) => { console.log(JSON.stringify(obj, null, 2)); return obj; };
  async function baseline() {
    const me = await fetchJson('/api/identity/me');
    check(me.status === 200 && me.body.identitySource === 'WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN' &&
      me.body.authenticated === true && me.body.clients?.['aurora-web']?.authenticated === true,
      'REFUSE_AURORA_NOT_AUTHENTICATED');
    check(me.body.clients?.['brisa-web']?.authenticated !== true &&
      me.body.clients?.['brisa-app']?.authenticated !== true &&
      me.body.clients?.['aurora-app']?.authenticated !== true,
      'REFUSE_OTHER_CLIENT_IN_SAME_SESSION');
    const p = await fetchJson(profilePath);
    check(p.status === 200 && p.body.allowed === true &&
      p.body.authorizedBy === 'WSO2_ACTIVE_ACCESS_TOKEN_SCOPE', 'REFUSE_NO_VERIFIED_HTTP_200');
    const cross = await fetchJson('/api/protected/profile?client=brisa-web');
    check(cross.status === 401 && cross.body.allowed === false, 'REFUSE_CROSS_CLIENT_NOT_DENIED');
    const fixture = await fetchJson('/api/scenarios');
    check(fixture.status === 503, 'REFUSE_SCENARIOS_AVAILABLE');
    const consent = await fetchJson('/api/consent');
    check(consent.status === 503, 'REFUSE_CONSENT_AVAILABLE');
    const record = { version: 1, origin: ORIGIN, at: Date.now(), phase: 'baseline',
      statuses: { profile: 200, crossClient: 401, scenarios: 503, consent: 503 } };
    sessionStorage.setItem(KEY, JSON.stringify(record));
    return safeOutput({ stage: 'CIAM_V10_P0_2_BROWSER_BASELINE', status: 'VERIFIED_BROWSER_BASELINE',
      ...record, secretsRead: false, managementWrites: 0,
      revocation: 'NOT_PERFORMED_BY_THIS_SCRIPT' });
  }
  async function after() {
    const raw = sessionStorage.getItem(KEY);
    check(raw !== null, 'REFUSE_BASELINE_NOT_CAPTURED');
    let prior;
    try { prior = JSON.parse(raw); } catch { throw new Error('REFUSE_CORRUPTED_BASELINE'); }
    check(prior?.version === 1 && prior.origin === ORIGIN && prior.phase === 'baseline' &&
      Number.isSafeInteger(prior.at) && Date.now() >= prior.at && Date.now() - prior.at <= 20 * 60_000,
      'REFUSE_BASELINE_TOO_OLD_OR_INVALID');
    // Do not query /api/identity/me first: it can delete an inactive BFF login.
    const p = await fetchJson(profilePath);
    const category = p.status === 401 && p.body.error === 'access_token_inactive'
      ? 'INACTIVE_TOKEN_DENIED_REVOCATION_CAUSE_UNVERIFIED'
      : p.status === 403 && p.body.error === 'wso2_scope_denied'
      ? 'ACTIVE_TOKEN_SCOPE_DENIED_PERMISSION_CAUSE_UNVERIFIED'
      : p.status === 503 && p.body.error === 'wso2_authority_unavailable'
      ? 'WSO2_AUTHORITY_UNAVAILABLE_DENIED_NOT_REVOCATION_EVIDENCE'
      : 'NOT_ACCEPTED';
    const accepted = category.startsWith('INACTIVE_TOKEN_') || category.startsWith('ACTIVE_TOKEN_');
    return safeOutput({ stage: 'CIAM_V10_P0_2_BROWSER_AFTER_AUTHORITY_CHANGE',
      status: accepted ? 'DENIAL_OBSERVED_CAUSE_REQUIRES_WSO2_READBACK' : 'NOT_VERIFIED',
      profileHttp: p.status, errorCode: typeof p.body.error === 'string' ? p.body.error : null,
      disposition: category, sameTabBaselineAvailable: true,
      note: 'Do not log out, restart BFF or open a fresh session between measurements. Browser denial alone does not prove WSO2 revocation.',
      secretsRead: false, managementWrites: 0 });
  }
  Object.defineProperty(window, 'CIAMV10Acceptance', {
    value: Object.freeze({ baseline, after }), configurable: true, writable: false
  });
  console.log('CIAM v10 acceptance loaded. Run await CIAMV10Acceptance.baseline() first; after separately verified WSO2 token revocation run await CIAMV10Acceptance.after().');
})();
