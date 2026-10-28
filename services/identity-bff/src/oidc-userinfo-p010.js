/** P0.10: OIDC UserInfo, not an application/business profile entitlement.
 * Requires a verified login, live WSO2 introspection, the actual `openid` scope,
 * and a UserInfo `sub` matching the signature-verified ID-token `sub`.
 * No browser-supplied issuer/subject or synthetic identity is accepted.
 */
export async function readOidcUserinfoForClient({ login, client, inspect, discovery, userinfo }) {
  const claims = login?.claims;
  const aud = typeof claims?.aud === 'string' ? [claims.aud] : claims?.aud;
  if (!login?.verified || typeof login.accessToken !== 'string' || !login.accessToken ||
      !client?.issuer || !client?.clientId || !client?.brand ||
      claims?.iss !== client.issuer ||
      typeof claims?.sub !== 'string' || !claims.sub || claims.sub.length > 1024 ||
      !Array.isArray(aud) || !aud.includes(client.clientId) ||
      (claims.azp !== undefined && claims.azp !== client.clientId) ||
      !Number.isSafeInteger(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000))
    return { status: 401, body: { allowed: false, error: 'authentication_required' } };
  let current;
  try { current = await inspect(login, client); }
  catch { return { status: 503, body: { allowed: false, error: 'wso2_authority_unavailable' } }; }
  if (current?.active !== true)
    return { status: 401, body: { allowed: false, error: 'access_token_inactive' } };
  if (!Array.isArray(current.scopes) || !current.scopes.includes('openid'))
    return { status: 403, body: { allowed: false, error: 'wso2_openid_scope_denied' } };
  try {
    const md = await discovery(client.issuer);
    const attributes = await userinfo({ discovery: md, issuer: client.issuer,
      accessToken: login.accessToken, subject: claims.sub });
    // The production UserInfo reader enforces the exact `sub` binding and
    // returns an allowlisted set of attributes; never emit raw `sub` or bearer.
    if (!attributes || typeof attributes !== 'object' || Array.isArray(attributes))
      throw new Error('userinfo_invalid_attributes');
    return { status: 200, body: { allowed: true,
      identitySource: 'WSO2_USERINFO', authorizedBy: 'WSO2_LIVE_OPENID_ACCESS_TOKEN',
      brand: client.brand, issuer: client.issuer, attributes } };
  } catch {
    return { status: 502, body: { allowed: false, error: 'wso2_userinfo_not_verified' } };
  }
}
