// Verified WSO2 UserInfo read. No local persona/role reconstruction.
export function userinfoEndpoint(discovery, issuer) {
  const source = new URL(issuer);
  const endpoint = new URL(discovery?.userinfo_endpoint || '');
  if (source.protocol !== 'https:' || endpoint.protocol !== 'https:' ||
      endpoint.origin !== source.origin || !endpoint.pathname.endsWith('/oauth2/userinfo') ||
      endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error('untrusted_wso2_userinfo_endpoint');
  }
  return endpoint.toString();
}
export function verifiedUserinfoClaims(result, expectedSubject) {
  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      typeof result.sub !== 'string' || result.sub !== expectedSubject)
    throw new Error('userinfo_subject_mismatch');
  const allowed = ['name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified', 'phone_number', 'phone_number_verified'];
  return Object.fromEntries(allowed.filter(k =>
    (typeof result[k] === 'string' && result[k].length <= 256) ||
    (['email_verified','phone_number_verified'].includes(k) && typeof result[k] === 'boolean'))
    .map(k => [k, result[k]]));
}
export async function readVerifiedUserinfo({ discovery, issuer, accessToken, subject, request = fetch }) {
  const url = userinfoEndpoint(discovery, issuer);
  const response = await request(url, { method: 'GET',
    headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
    redirect: 'error', signal: AbortSignal.timeout(6000) });
  if (!response.ok) throw new Error(`userinfo_http_${response.status}`);
  if (Number(response.headers?.get?.('content-length') || 0) > 16384)
    throw new Error('userinfo_response_too_large');
  const body = await response.text();
  if (body.length > 16384) throw new Error('userinfo_response_too_large');
  return verifiedUserinfoClaims(JSON.parse(body), subject);
}
