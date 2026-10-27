/** P0 #1: mandatory default-deny boundary for the live WSO2 BFF.
 * Only these established, WSO2-backed/status routes may enter the existing
 * handlers. The BFF itself must still authenticate and authorize every call.
 * Never grant identity/permissions/consent here.
 */
const EXPLICIT_LIVE_API_METHODS = Object.freeze({
  '/api/health': 'GET',
  '/api/wso2-status': 'GET',
  '/api/identity/me': 'GET',
  '/api/protected/profile': 'GET',
  '/api/logout': 'POST',
});

export const LIVE_API_ALLOWLIST = Object.freeze(Object.keys(EXPLICIT_LIVE_API_METHODS));

export function liveApiDenial(pathname, method) {
  if (typeof pathname !== 'string' || !pathname.startsWith('/api/')) return null;
  if (Object.hasOwn(EXPLICIT_LIVE_API_METHODS, pathname)) {
    if (EXPLICIT_LIVE_API_METHODS[pathname] === method) return null;
    return { status: 405, body: { error: 'method_not_allowed', allowed: false } };
  }
  return {
    status: 503,
    body: {
      error: 'wso2_authoritative_integration_not_available',
      allowed: false,
      syntheticFallback: false,
    },
  };
}
