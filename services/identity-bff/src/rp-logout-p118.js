/** Optional OIDC RP-initiated logout; local logout remains separate. */
import {discover,assertTrustedEndpoint} from './oidc.js';
export async function rpLogoutUrl({client,login,postLogoutUri,origin,discoverer=discover}) {
 if(!login?.verified || login.claims?.iss!==client?.issuer || !login.idToken ||
    typeof login.idToken!=='string' || login.idToken.length>30000)
   throw new Error('RP_LOGOUT_REQUIRES_VERIFIED_LOGIN_AND_ID_TOKEN');
 if(!postLogoutUri)throw new Error('RP_LOGOUT_REDIRECT_NOT_REGISTERED');
 const redirect=new URL(postLogoutUri);
 if(redirect.origin!==origin || redirect.username || redirect.password || redirect.hash || redirect.search)
   throw new Error('RP_LOGOUT_REDIRECT_NOT_TRUSTED');
 const discovery=await discoverer(client.issuer);
 if(!discovery.end_session_endpoint)throw new Error('RP_LOGOUT_NOT_ADVERTISED');
 const endpoint=assertTrustedEndpoint(discovery.end_session_endpoint,client.issuer);
 const result=new URL(endpoint);
 result.searchParams.set('id_token_hint',login.idToken);
 result.searchParams.set('post_logout_redirect_uri',postLogoutUri);
 result.searchParams.set('client_id',client.clientId);
 return result.toString();
}
