/** Pure, fail-closed parser for authorization-code callback parameters. */
export function readAuthorizationResponse(url) {
  const p = url?.searchParams;
  if (!p || p.getAll('state').length !== 1 || p.getAll('code').length > 1 ||
      p.getAll('error').length > 1 || (p.has('error') && p.has('code')))
    return { valid: false };
  const state = p.get('state');
  const code = p.get('code');
  if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(state))
    return { valid: false };
  if (p.has('code') && (typeof code !== 'string' || code.length < 1 ||
      code.length > 4096 || /[\x00-\x1f\x7f]/.test(code)))
    return { valid: false };
  return { valid: true, state, code };
}
