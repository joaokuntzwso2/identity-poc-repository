/** Operator CLI, never a browser endpoint. Uses genuine WSO2-issued JWTs from owner-only files. */
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {discover,getJson,assertTrustedEndpoint} from '../../services/identity-bff/src/oidc.js';
import {verifyRs256Jwt,assertDelegation} from './token-exchange-core.mjs';
import {performTokenExchange} from './token-exchange-service.mjs';
const e=process.env;
if(e.CONFIRM_REAL_WSO2!=='yes')throw new Error('Set CONFIRM_REAL_WSO2=yes only for actual installed WSO2');
const names=['M2M_ISSUER','M2M_CLIENT_ID','M2M_CLIENT_SECRET','IDENTITY_SUBJECT_TOKEN_FILE','IDENTITY_ACTOR_TOKEN_FILE','IDENTITY_EXCHANGE_SCOPE'];
for(const name of names)if(!e[name])throw new Error(`Missing ${name}`);
const issuer=e.M2M_ISSUER;
const doc=await discover(issuer);
const jwks=await getJson(assertTrustedEndpoint(doc.jwks_uri,issuer));
async function tokenFromFile(name){const s=(await readFile(e[name],'utf8')).trim();if(s.length<50 || s.length>20000)throw new Error(`Invalid ${name}`);return s;}
const subjectToken=await tokenFromFile('IDENTITY_SUBJECT_TOKEN_FILE');
const actorToken=await tokenFromFile('IDENTITY_ACTOR_TOKEN_FILE');
const subject=verifyRs256Jwt(subjectToken,{issuer,jwks});
const actor=verifyRs256Jwt(actorToken,{issuer,jwks});
const started=performance.now();
const result=await performTokenExchange({tokenEndpoint:assertTrustedEndpoint(doc.token_endpoint,issuer),
  clientId:e.M2M_CLIENT_ID,clientSecret:e.M2M_CLIENT_SECRET,subjectToken,actorToken,
  scope:e.IDENTITY_EXCHANGE_SCOPE,audience:e.IDENTITY_EXCHANGE_AUDIENCE||undefined});
const issued=verifyRs256Jwt(result.access_token,{issuer,jwks,audience:e.IDENTITY_EXCHANGE_AUDIENCE||undefined});
const assertions=assertDelegation({subject,actor,issued,response:result,requestedScope:e.IDENTITY_EXCHANGE_SCOPE,expectedAudience:e.IDENTITY_EXCHANGE_AUDIENCE});
const evidence={type:'RFC8693_REAL_WSO2',checkedAt:new Date().toISOString(),issuer,
  elapsedMs:Math.round(performance.now()-started),updateLevel:'MUST_ATTEST_FROM_RUNNING_WSO2',
  tokenFingerprint:createHash('sha256').update(result.access_token).digest('hex').slice(0,20),...assertions,
  warnings:['A signed JWT is not evidence of enforcement at a protected downstream API.',
  'WSO2 build/update level and client trust policy require independent attestation.']};
await mkdir('evidence/identity',{recursive:true});
await writeFile('evidence/identity/actor-delegation-live.json',JSON.stringify(evidence,null,2)+'\n',{mode:0o600});
console.log(JSON.stringify(evidence,null,2));
