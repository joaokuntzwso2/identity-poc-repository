import {createPublicKey,verify as verifySignature} from 'node:crypto';
import {parseJwt} from '../../services/identity-bff/src/oidc.js';

export function verifyRs256Jwt(token,{issuer,jwks,audience,now=Math.floor(Date.now()/1000)}){
  const {header,payload,signingInput,signature}=parseJwt(token);
  if(header.alg!=='RS256' || !header.kid || header.crit || header.b64===false)throw new Error('unapproved_jws_header');
  if(!Array.isArray(jwks?.keys))throw new Error('invalid_jwks');
  const key=jwks.keys.find(k=>k.kid===header.kid&&k.kty==='RSA'&&(!k.use||k.use==='sig')&&(!k.alg||k.alg==='RS256'));
  if(!key)throw new Error('jwks_signing_key_missing');
  if(!verifySignature('RSA-SHA256',Buffer.from(signingInput),createPublicKey({key,format:'jwk'}),signature))throw new Error('invalid_jwt_signature');
  if(payload.iss!==issuer)throw new Error('jwt_issuer_mismatch');
  if(!payload.sub || typeof payload.sub!=='string' || !Number.isFinite(payload.exp) || payload.exp<=now ||
    (payload.nbf!==undefined && payload.nbf>now+30))throw new Error('invalid_jwt_lifetime_or_subject');
  if(audience){const aud=Array.isArray(payload.aud)?payload.aud:[payload.aud];if(!aud.includes(audience))throw new Error('jwt_audience_mismatch');}
  return payload;
}
export const asScopes = v => new Set((Array.isArray(v)?v:typeof v==='string'?v.split(' '):[]).filter(Boolean));
export function assertDelegation({subject,actor,issued,response,requestedScope,expectedAudience}){
  if(response.issued_token_type!=='urn:ietf:params:oauth:token-type:access_token')throw new Error('incorrect_issued_token_type');
  if(issued.sub!==subject.sub)throw new Error('delegated_subject_changed');
  if(issued.act?.sub!==actor.sub)throw new Error('actor_chain_missing_or_changed');
  const base=asScopes(subject.scope??subject.scp);
  const asked=asScopes(requestedScope);
  const granted=asScopes(issued.scope??issued.scp);
  if(!base.size || !asked.size || !granted.size)throw new Error('cannot_verify_scope_attenuation');
  for(const s of granted)if(!base.has(s)||!asked.has(s))throw new Error('scope_escalation_detected');
  if(response.scope){for(const s of asScopes(response.scope))if(!granted.has(s))throw new Error('response_token_scope_inconsistent');}
  if(expectedAudience){const aud=Array.isArray(issued.aud)?issued.aud:[issued.aud];if(!aud.includes(expectedAudience))throw new Error('delegated_audience_mismatch');}
  return {status:'DELEGATION_ASSERTIONS_PASSED',verifiedActor:true,verifiedScopeAttenuation:true,
    verifiedIssuedTokenType:true,scopes:[...granted].sort()};
}
