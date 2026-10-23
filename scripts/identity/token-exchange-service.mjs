/** RFC 8693 request builder; returns server-only response, never log secrets. */
export async function performTokenExchange({ tokenEndpoint, clientId, clientSecret, subjectToken, actorToken, scope, audience, fetchFn = fetch }) {
  if (!tokenEndpoint || !clientId || !clientSecret || !subjectToken || !actorToken || !scope) throw new Error('missing_token_exchange_input');
  const endpoint = new URL(tokenEndpoint);
  if (endpoint.username || endpoint.password || endpoint.hash || endpoint.protocol !== 'https:' &&
    !(process.env.ALLOW_INSECURE_LOCAL === 'true' && ['localhost', '127.0.0.1'].includes(endpoint.hostname) && endpoint.protocol === 'http:'))
    throw new Error('untrusted_token_endpoint');
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: subjectToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    actor_token: actorToken,
    actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token', scope
  });
  if (audience) body.set('audience', audience);
  const response = await fetchFn(endpoint.toString(), {
    method: 'POST', headers: {
      authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded', 'accept': 'application/json'
    },
    body, redirect: 'error', signal: AbortSignal.timeout(12000)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) throw new Error(`token_exchange_rejected: ${String(result.error || response.status).slice(0, 80)}`);
  return result;
}
