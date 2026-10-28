/** Privacy-preserving Playwright OIDC login progress and failure classification. */
export const OIDC_BROWSER_WAIT_MS = 240000;
export const SAFE_CLIENTS = Object.freeze(['aurora-web','aurora-app','brisa-web','brisa-app']);

export function safeClient(key) {
  if (!SAFE_CLIENTS.includes(key)) throw new Error('UNEXPECTED_CLIENT_KEY');
  return key.toUpperCase().replaceAll('-', '_');
}

export function safeStage(stage) {
  if (typeof stage !== 'string' || !/^(?:LOGIN_[A-Z_]+|USERINFO_[A-Z_]+|CASES_[A-Z_]+|STEPUP_[A-Z_]+|BROWSER_SETUP)$/.test(stage))
    throw new Error('INVALID_BROWSER_STAGE');
  return stage;
}

export function classifyBrowserLocation(raw, bffBase) {
  try {
    const loc = new URL(raw);
    const bff = new URL(bffBase);
    if (loc.origin === bff.origin) {
      if (/^\/portal\/(aurora|brisa)\/(web|mobile)(?:\/|$)/.test(loc.pathname)) return 'BFF_PORTAL';
      if (/^\/auth\//.test(loc.pathname)) return 'BFF_AUTH_ROUTE';
      return 'BFF_OTHER_ROUTE';
    }
    if (loc.protocol === 'https:' && loc.hostname === 'localhost' && loc.port === '9444') return 'LOCAL_WSO2_LOGIN';
    return 'OTHER_OR_UNTRUSTED_ORIGIN';
  } catch { return 'UNKNOWN_LOCATION'; }
}

export function safeFailureCode(error) {
  // Never expose an exception containing a URL, querystring, OAuth code or state.
  const message = typeof error?.message === 'string' ? error.message : '';
  if (/^(?:LIVE_LOGIN_NOT_VERIFIED|LIVE_USERINFO_NOT_VERIFIED|TENANT_ISSUER_MISMATCH)_(?:aurora|brisa)-(?:web|app)$/.test(message))
    return message.toUpperCase().replaceAll('-', '_');
  if (/^LOGIN_(?:STILL_ON_WSO2|BFF_AUTH_ROUTE|BROWSER_CLOSED|RETURN_NOT_OBSERVED)_(?:AURORA|BRISA)_(?:WEB|APP)$/.test(message))
    return message;
  if (new Set(['OIDC_REDIRECT_NOT_LOCAL_WSO2_OR_BFF','CUSTOMER_SCOPES_NOT_ISSUED',
    'PERSISTENT_CUSTOMER_CASE_CREATION_FAILED','OWNER_VISIBILITY_FAILED','CROSS_TENANT_NOT_DENIED',
    'SELLER_SCOPE_NOT_ISSUED','SELLER_REVIEW_NOT_VERIFIED','SEPARATE_TOTP_CHALLENGE_NOT_STARTED',
    'REAL_TOTP_APPROVAL_NOT_ATTESTED','CUSTOMER_POST_APPROVAL_STATE_NOT_VERIFIED',
    'UNEXPECTED_CLIENT_KEY','UNTRUSTED_PORTAL_RETURN_PATH']).has(message)) return message;
  if (/ERR_CERT_AUTHORITY_INVALID/.test(message)) return 'LOCAL_WSO2_CERTIFICATE_NOT_TRUSTED';
  if (/net::ERR_/.test(message)) return 'BROWSER_NAVIGATION_NETWORK_ERROR';
  if (/Timeout|timeout/.test(message)) return 'BROWSER_ACTION_TIMEOUT';
  if (/Execution context was destroyed/.test(message)) return 'BROWSER_NAVIGATION_INTERRUPTED';
  if (/Target page, context or browser has been closed/.test(message)) return 'BROWSER_CLOSED_BEFORE_LOGIN';
  return 'BROWSER_UNEXPECTED_ERROR';
}

export async function waitForPortalReturn(page, bffBase, portalPath, key, note, {timeoutMs=OIDC_BROWSER_WAIT_MS, log=console.log}={}) {
  const client = safeClient(key);
  const destination = new URL(portalPath,bffBase);
  if (destination.origin !== new URL(bffBase).origin ||
      !/^\/portal\/(aurora|brisa)\/(web|mobile)$/.test(destination.pathname))
    throw new Error('UNTRUSTED_PORTAL_RETURN_PATH');
  log(`Complete REAL WSO2 ${note} in Chromium for ${key}. The test will resume AUTOMATICALLY when the BFF portal returns; do not press Enter or type commands here.`);
  try {
    await page.waitForURL((u)=>u.origin===destination.origin && u.pathname===destination.pathname,
      {waitUntil:'domcontentloaded',timeout:timeoutMs});
    return {status:'PORTAL_RETURNED',locationClass:'BFF_PORTAL'};
  } catch {
    const locationClass = page.isClosed?.() ? 'BROWSER_CLOSED' : classifyBrowserLocation(page.url(),bffBase);
    const suffix = locationClass === 'LOCAL_WSO2_LOGIN' ? 'STILL_ON_WSO2' :
      locationClass === 'BFF_AUTH_ROUTE' ? 'BFF_AUTH_ROUTE' :
      locationClass === 'BROWSER_CLOSED' ? 'BROWSER_CLOSED' : 'RETURN_NOT_OBSERVED';
    const err = new Error(`LOGIN_${suffix}_${client}`);
    err.locationClass = locationClass;
    throw err;
  }
}
