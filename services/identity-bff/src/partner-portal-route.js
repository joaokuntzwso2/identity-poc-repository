/** P2.24 V16.3: isolated Aurora partner callback, NEVER a business permission.
 * V16.3 registers an OAuth client but intentionally leaves login DISABLED.
 * A future independently approved selected-organization share and a verified
 * confidential client secret are mandatory before this route can authenticate.
 */
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { random, discover, makeAuthorizationUrl, exchangeAuthorizationCode,
  verifyIdToken } from './oidc.js';
import { readAuthorizationResponse } from './auth-callback-guards.js';
import { inspectAccessToken } from './wso2-authority.js';

export const PARTNER_LOGIN_PATH = '/auth/aurora-partner-web/login';
export const PARTNER_CALLBACK_PATH = '/auth/aurora-partner-web/callback';
const J='p2-aurora-partner-business-portal-v16.private.json';
const C='p2-aurora-partner-portal-client-v16-3.private.json';
const S='p2-aurora-partner-portal-sharing-v17.private.json';
const TENANT='aurora.identity.test';
const PARTNER='a9c40a10acabab52';
const NAME='P2 Aurora Returns Partner Business Portal';
const CLIENT_SCHEMA='p2.24.aurora.partner-portal.client.v16.3';
const MAX_JSON=128*1024;

function secureFile(root, filename) {
  const path=join(root,filename);
  const base=lstatSync(root), st=lstatSync(path);
  if (!base.isDirectory() || base.isSymbolicLink() || (base.mode & 0o077) ||
      !st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) ||
      st.size<2 || st.size>MAX_JSON || st.nlink!==1 ||
      (typeof process.getuid==='function' &&
       (base.uid!==process.getuid() || st.uid!==process.getuid())) ||
      realpathSync(path)!==join(realpathSync(root),filename))
    throw new Error('PARTNER_PRIVATE_STATE_UNSAFE');
  return JSON.parse(readFileSync(path,'utf8'));
}

/** Private, runtime-only config. Never derives an OAuth client from a source
 * Aurora Web credential and never enables the client based on a local flag.
 * The V17 sharing journal does not exist in V16.3, so login is OFF by design. */
export function loadPartnerPortalClient({ origin, clients, privateDir } = {}) {
  try {
    const root=privateDir ?? process.env.P2_PRIVATE_DIR ?? join(homedir(),'wso2-ciam-v10/private');
    const journal=secureFile(root,J), secret=secureFile(root,C), sharing=secureFile(root,S);
    const expected=new URL(PARTNER_CALLBACK_PATH,origin).href;
    const source=clients?.['aurora-web'];
    if (journal?.schema!=='p2.24.aurora.partner-portal.v16.3' ||
        journal?.state!=='VERIFIED' || journal.tenant!==TENANT || journal.name!==NAME ||
        journal.partnerFingerprint!==PARTNER ||
        secret?.schema!==CLIENT_SCHEMA || secret?.tenant!==TENANT ||
        secret.applicationId!==journal.applicationId ||
        secret.callbackURL!==expected ||
        !/^[A-Za-z0-9_.~+\/-]{4,256}$/.test(secret.clientId||'') ||
        typeof secret.clientSecret!=='string' || secret.clientSecret.length<10 || secret.clientSecret.length>4096 ||
        !source?.issuer || !source.issuer.includes(`/t/${TENANT}/`) ||
        Object.values(clients).some(c=>c.clientId===secret.clientId) ||
        sharing?.schema!=='p2.24.aurora.partner-portal.share.v17' ||
        sharing?.verified!==true || sharing?.tenant!==TENANT ||
        sharing.applicationId!==journal.applicationId ||
        sharing.partnerFingerprint!==PARTNER ||
        sharing.mode!=='SELECTED_ORG_ONLY' || sharing.excludeFutureChildren!==true ||
        sharing.globalSharing===true || sharing.businessAuthorizationVerified===true ||
        sharing.targetOrganizationFingerprint!==PARTNER || sharing.targetCount!==1)
      return null;
    return Object.freeze({clientId:secret.clientId,clientSecret:secret.clientSecret,
      issuer:source.issuer,redirectUri:expected});
  } catch {return null;}
}

function writeJSON(res,status,data) {
  res.writeHead(status,{'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store','x-content-type-options':'nosniff',
    'referrer-policy':'no-referrer','x-frame-options':'DENY'});
  res.end(JSON.stringify(data));
}
function redirect(res,url) {
  res.writeHead(302,{location:url,'cache-control':'no-store',
    'referrer-policy':'no-referrer','x-content-type-options':'nosniff'});res.end();
}

/** Injectable dependencies are used only by offline tests; production below
 * always uses actual OIDC signature verification and live introspection. */
export function makePartnerPortalHandler({
  load=loadPartnerPortalClient,discoverIssuer=discover,authorize=makeAuthorizationUrl,
  exchange=exchangeAuthorizationCode,verify=verifyIdToken,inspect=inspectAccessToken,
  newRandom=random,now=()=>Date.now()
}={}) {
  return async function handlePartnerPortalAuth({req,res,u,s,origin,clients,rotate}) {
    if (u.pathname!==PARTNER_LOGIN_PATH && u.pathname!==PARTNER_CALLBACK_PATH) return false;
    if (req.method!=='GET') {writeJSON(res,405,{error:'method_not_allowed'});return true;}
    const c=load({origin,clients});
    if (!c) {writeJSON(res,503,{error:'partner_portal_access_not_yet_verified',allowed:false});return true;}
    if (c.redirectUri!==new URL(PARTNER_CALLBACK_PATH,origin).href ||
        c.clientId===clients?.['aurora-web']?.clientId ||
        !c.issuer.includes(`/t/${TENANT}/`)) {
      writeJSON(res,503,{error:'partner_portal_client_binding_failed',allowed:false});return true;
    }
    if (u.pathname===PARTNER_LOGIN_PATH) {
      if (u.search || !s?.pending) {writeJSON(res,400,{error:'invalid_partner_login_request'});return true;}
      const pending=Object.entries(s.pending);
      for (const [key,p] of pending) if (!p || now()-p.at>300000) delete s.pending[key];
      if (Object.keys(s.pending).length>=8) {
        writeJSON(res,429,{error:'too_many_pending_authorizations'});return true;
      }
      const state=newRandom(32),nonce=newRandom(24),verifier=newRandom(32);
      s.pending[state]={key:'aurora-partner-web',nonce,verifier,at:now(),
        clientId:c.clientId,redirectUri:c.redirectUri};
      try {
        const doc=await discoverIssuer(c.issuer);
        redirect(res,authorize(doc,{clientId:c.clientId,redirectUri:c.redirectUri,
          state,nonce,verifier,scope:'openid'}));
      } catch {
        delete s.pending[state];writeJSON(res,503,{error:'wso2_authority_unavailable'});
      }
      return true;
    }
    const parsed=readAuthorizationResponse(u);
    if (!parsed.valid || !s?.pending) {
      writeJSON(res,400,{error:'invalid_partner_oidc_callback'});return true;
    }
    const p=s.pending[parsed.state];
    if (!p || p.key!=='aurora-partner-web' || p.clientId!==c.clientId ||
        p.redirectUri!==c.redirectUri || !Number.isSafeInteger(p.at) ||
        now()-p.at<0 || now()-p.at>300000) {
      writeJSON(res,400,{error:'invalid_or_expired_partner_state'});return true;
    }
    delete s.pending[parsed.state]; // One use, including error and exchange failure.
    if (u.searchParams.has('error') || !parsed.code) {
      writeJSON(res,400,{error:'partner_oidc_provider_denied'});return true;
    }
    try {
      const doc=await discoverIssuer(c.issuer);
      const tokens=await exchange(doc,{clientId:c.clientId,clientSecret:c.clientSecret,
        redirectUri:c.redirectUri,code:parsed.code,verifier:p.verifier});
      const claims=await verify(tokens.id_token,{issuer:c.issuer,
        clientId:c.clientId,nonce:p.nonce});
      if (typeof tokens.access_token!=='string' || !tokens.access_token) throw Error('missing_token');
      const outcome=await inspect({verified:true,claims,accessToken:tokens.access_token},c);
      if (!outcome?.active) throw Error('inactive_token');
      // Deliberately NOT in s.logins or any business-authorized channel.
      s.partnerPortalLogin={claims,verified:true,verifiedAt:new Date(now()).toISOString(),
        accessToken:tokens.access_token};
      rotate(s,res);
      redirect(res,'/portal/aurora?partnerOidc=1');
    } catch {
      writeJSON(res,403,{error:'partner_oidc_proof_not_verified',allowed:false});
    }
    return true;
  };
}

export const handlePartnerPortalAuth=makePartnerPortalHandler();
