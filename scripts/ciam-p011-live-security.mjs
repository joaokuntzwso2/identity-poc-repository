/** Additional real BFF security probes. No tokens, cookies, URLs or bodies in evidence.
 * Every probe is opt-in through an operator-approved P010 live browser run.
 */
export function observedCallbackIsLocal(raw, base, key = 'aurora-web') {
  try {
    const target = new URL(raw);
    const host = new URL(base);
    return target.origin === host.origin &&
      target.pathname === `/auth/${key}/callback` &&
      target.searchParams.has('state') && target.searchParams.has('code') &&
      target.searchParams.get('state').length > 0 && target.searchParams.get('code').length > 0 &&
      target.username === '' && target.password === '' && target.hash === '';
  } catch { return false; }
}

export async function replayConsumedCallback(context, raw, base) {
  // Retain a real previously consumed authorization response in memory only.
  // Replay is performed against the SAME authenticated cookie context.
  if (!observedCallbackIsLocal(raw, base)) return null;
  try {
    const response = await context.request.get(raw, {maxRedirects: 0, timeout: 10000});
    return response.status();
  } catch { return null; }
}

export async function denyUnsolicitedCallback(context, base) {
  try {
    // This tests a live BFF denial for an unissued state, NOT live MFA cancellation.
    const response = await context.request.get(
      new URL('/auth/aurora-web/callback?state=unissued-probe&code=unissued-probe',base).href,
      {maxRedirects:0,timeout:10000});
    return response.status();
  } catch { return null; }
}

export async function observeBffLogout(customerPage, sellerPage) {
  // The BFF endpoint explicitly does not terminate the global WSO2 session.
  // Do not report this check as OIDC RP-initiated/global SSO logout.
  try {
    const customer = await customerPage.evaluate(async () => {
      const current = await fetch('/api/identity/me',{credentials:'same-origin',cache:'no-store'});
      if (current.status!==200) return {logoutHttp:null,customerSessionDestroyed:false,wso2GlobalLogoutClaimed:null};
      const state = await current.json();
      if (typeof state.csrf !== 'string' || !state.csrf)
        return {logoutHttp:null,customerSessionDestroyed:false,wso2GlobalLogoutClaimed:null};
      const response = await fetch('/api/logout', {method:'POST', credentials:'same-origin',
        cache:'no-store', headers:{'x-csrf-token':state.csrf}});
      const result = await response.json().catch(()=>null);
      const after = await fetch('/api/identity/me',{credentials:'same-origin',cache:'no-store'});
      const afterState = await after.json().catch(()=>null);
      return {logoutHttp:response.status,
        customerSessionDestroyed:after.status===200 && !!afterState?.clients?.['aurora-web'] && afterState.clients['aurora-web'].authenticated === false,
        wso2GlobalLogoutClaimed:result?.wso2Session !== 'NOT_TERMINATED'};
    });
    const still = await sellerPage.evaluate(async () => {
      const r = await fetch('/api/identity/me',{credentials:'same-origin',cache:'no-store'});
      const result = await r.json().catch(()=>null);
      return r.status===200 && result?.clients?.['aurora-web']?.authenticated === true;
    });
    return {logoutHttp:customer.logoutHttp,customerSessionDestroyed:customer.customerSessionDestroyed,
      sellerSessionIndependent:still,wso2GlobalLogoutClaimed:customer.wso2GlobalLogoutClaimed};
  } catch {
    return {logoutHttp:null,customerSessionDestroyed:null,sellerSessionIndependent:null,
      wso2GlobalLogoutClaimed:null};
  }
}
