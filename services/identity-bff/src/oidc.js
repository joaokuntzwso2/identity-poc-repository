import {randomBytes, createHash, createPublicKey, verify as cryptoVerify, timingSafeEqual} from 'node:crypto';

const ALGORITHMS = Object.freeze({RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512', ES256: 'sha256', PS256: 'RSA-SHA256'});
const MAX_RESPONSE_BYTES = 256 * 1024;
export const base64url = buf => Buffer.from(buf).toString('base64url');
export const challenge = verifier => base64url(createHash('sha256').update(verifier).digest());
export const random = (size = 32) => base64url(randomBytes(size));
export const fingerprint = text => base64url(createHash('sha256').update(text).digest()).slice(0, 20);

export function safeEqual(a, b) {
  const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}
function readPart(part) { try { return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')); } catch { throw new Error('Invalid JWT encoding'); } }
export function parseJwt(jwt) {
  if (typeof jwt !== 'string' || jwt.length > 30000) throw new Error('JWT missing or oversized');
  const p = jwt.split('.'); if (p.length !== 3) throw new Error('Expected signed JWT');
  return {header: readPart(p[0]), payload: readPart(p[1]), signingInput: `${p[0]}.${p[1]}`, signature: Buffer.from(p[2], 'base64url')};
}

/** Keep all discovery-supplied endpoints within explicitly trusted origins.
 * Cross-host endpoints must be approved by deployment configuration; never
 * trust a new host merely because discovery returned it. */
export function assertTrustedEndpoint(url, issuer) {
  const u = new URL(url); const parent=new URL(issuer);
  if (u.username || u.password || u.hash) throw new Error('OIDC endpoint includes forbidden URL components');
  const local = process.env.ALLOW_INSECURE_LOCAL==='true' &&
    ['localhost','127.0.0.1'].includes(u.hostname) &&
    ['localhost','127.0.0.1'].includes(parent.hostname);
  if (u.protocol!=='https:' && !(local&&u.protocol==='http:'))throw new Error('Untrusted OIDC endpoint protocol');
  const additional=(process.env.OIDC_TRUSTED_ENDPOINT_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean);
  const approved = new Set([parent.origin,...additional]);
  if(!approved.has(u.origin))throw new Error(`OIDC endpoint origin not trusted: ${u.origin}`);
  return u.toString();
}

export async function getJson(url) {
  const u = new URL(url);
  if (u.protocol !== 'https:' && !(process.env.ALLOW_INSECURE_LOCAL === 'true' && ['localhost','127.0.0.1'].includes(u.hostname))) throw new Error('TLS required for remote OIDC endpoint');
  const res=await fetch(url,{headers:{accept:'application/json'},signal:AbortSignal.timeout(8000),redirect:'error'});
  if(!res.ok)throw new Error(`OIDC endpoint returned HTTP ${res.status}`);
  if(Number(res.headers.get('content-length'))>MAX_RESPONSE_BYTES)throw new Error('OIDC response too large');
  if(!res.body)throw new Error('OIDC endpoint has no response body');
  const reader=res.body.getReader();let size=0;const chunks=[];
  try {while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;
    if(size>MAX_RESPONSE_BYTES)throw new Error('OIDC response too large');chunks.push(value);}}
  finally {reader.releaseLock();}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const discoveryCache=new Map();
export async function discover(issuer) {
  if(!issuer || !new URL(issuer).pathname)throw new Error('Invalid issuer');
  const overrides=process.env.OIDC_DISCOVERY_URLS_JSON?JSON.parse(process.env.OIDC_DISCOVERY_URLS_JSON):{};
  const explicit=overrides[issuer]||process.env.OIDC_DISCOVERY_URL||'';
  const cacheKey=`${issuer}|${explicit}`;
  const cached=discoveryCache.get(cacheKey);
  if(cached&&cached.until>Date.now())return cached.doc;
  const normalized=issuer.replace(/\/$/,'');const parent=new URL(issuer);
  // WSO2 path varies across installation and tenant context. Use the explicit
  // override when necessary; discovery's reported issuer is ALWAYS verified.
  const candidates=explicit?[explicit]:[
    `${normalized}/.well-known/openid-configuration`,
    `${parent.origin}${parent.pathname.split('/oauth2/')[0]}/oauth2/oidcdiscovery/.well-known/openid-configuration`
  ];
  let doc,lastError;
  for(const location of [...new Set(candidates)]){
    try {doc=await getJson(assertTrustedEndpoint(location,issuer));break;}
    catch(e){lastError=e;}
  }
  if(!doc)throw lastError;
  if(doc.issuer!==issuer)throw new Error(`Issuer mismatch in Discovery: expected ${issuer}, got ${doc.issuer}`);
  for(const key of ['authorization_endpoint','token_endpoint','jwks_uri']){
    if(typeof doc[key]!=='string')throw new Error(`Discovery missing ${key}`);
    assertTrustedEndpoint(doc[key],issuer);
  }
  discoveryCache.set(cacheKey,{doc,until:Date.now()+30_000});return doc;
}

export function validateJwtClaims(claims, {issuer, clientId, nonce, maxAge=3600, now=Math.floor(Date.now()/1000)}={}) {
  if (claims.iss !== issuer) throw new Error('Invalid token issuer');
  const aud = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  if (!Array.isArray(aud) || !aud.includes(clientId)) throw new Error('Invalid token audience');
  if (aud.length > 1 && claims.azp !== clientId) throw new Error('Authorized party mismatch');
  if (claims.azp && claims.azp !== clientId) throw new Error('Authorized party mismatch');
  if (!claims.sub || typeof claims.sub !== 'string') throw new Error('Missing subject');
  if (typeof claims.exp !== 'number' || now >= claims.exp) throw new Error('Expired token');
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf > now + 60)) throw new Error('Token not yet valid');
  if (typeof claims.iat !== 'number' || claims.iat > now + 60 || now - claims.iat > maxAge + 60) throw new Error('Invalid token issued-at');
  if (nonce !== undefined && (!claims.nonce || !safeEqual(claims.nonce, nonce))) throw new Error('OIDC nonce mismatch');
  return true;
}

export async function verifyIdToken(token, {issuer, clientId, nonce}) {
  const {header, payload, signingInput, signature} = parseJwt(token);
  if (!['RS256','RS384','RS512'].includes(header.alg)) throw new Error('Unsupported JWT signature algorithm');
  if (typeof header.kid !== 'string' || !header.kid || header.kid.length > 256 || (header.typ && !['JWT','application/jwt'].includes(header.typ)) || header.crit || header.b64 === false) throw new Error('Invalid JWT header');
  const disc = await discover(issuer);
  const jwks = await getJson(assertTrustedEndpoint(disc.jwks_uri,issuer));
  if (!Array.isArray(jwks.keys)) throw new Error('Invalid JWKS');
  const key = jwks.keys.find(k => k.kid === header.kid && k.kty === 'RSA' && (!k.use || k.use === 'sig') && (!k.alg || k.alg === header.alg));
  if (!key) throw new Error('Signing key not found in JWKS');
  const pub = createPublicKey({key, format:'jwk'});
  if (!cryptoVerify(ALGORITHMS[header.alg], Buffer.from(signingInput), pub, signature)) throw new Error('Invalid JWT signature');
  validateJwtClaims(payload, {issuer, clientId, nonce});
  return payload;
}

export function makeAuthorizationUrl(disc, {clientId, redirectUri, state, nonce, verifier, scope='openid', acrValues}) {
  const url = new URL(disc.authorization_endpoint);
  for (const [k,v] of Object.entries({client_id:clientId, response_type:'code', redirect_uri:redirectUri, scope, code_challenge:challenge(verifier), code_challenge_method:'S256', state, nonce})) url.searchParams.set(k,v);
  if (acrValues) url.searchParams.set('acr_values', acrValues);
  return url.toString();
}
export async function exchangeAuthorizationCode(disc, {clientId, clientSecret='', redirectUri, code, verifier}) {
  const params = new URLSearchParams({grant_type:'authorization_code', client_id:clientId, redirect_uri:redirectUri, code, code_verifier:verifier});
  const headers = {'content-type':'application/x-www-form-urlencoded','accept':'application/json'};
  if (clientSecret) { headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`; params.delete('client_id'); }
  const res = await fetch(disc.token_endpoint, {method:'POST',headers,body:params.toString(),redirect:'error',signal:AbortSignal.timeout(8000)});
  const data = await res.json().catch(()=>({error:'invalid_response'}));
  if (!res.ok || data.error) throw new Error(`Code exchange failed: ${data.error || res.status}`);
  if (!data.id_token) throw new Error('ID token not returned');
  return data;
}
export function sanitizedClaims(claims) {
  const allow = ['iss','aud','sub','azp','iat','exp','acr','amr','auth_time'];
  return Object.fromEntries(allow.filter(k=>claims[k] !== undefined).map(k=>[k,claims[k]]));
}
