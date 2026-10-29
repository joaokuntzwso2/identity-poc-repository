/**
 * Local BFF channel logout, not WSO2 RP-initiated logout.
 * The browser's single BFF session may contain four independent OIDC logins.
 * Clear only the requested registered channel, including unfinished auth/MFA.
 * Access-token revocation and provider-wide logout are NOT claimed.
 */
export function endChannelSession(session, key, clients) {
  if (!session || typeof key !== 'string' || !clients ||
      !Object.hasOwn(clients, key) || !session.logins || !session.pending) {
    return false;
  }
  delete session.logins[key];
  for (const [state, transaction] of Object.entries(session.pending)) {
    if (transaction?.key === key) delete session.pending[state];
  }
  return true;
}
