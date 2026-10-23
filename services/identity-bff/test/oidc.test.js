import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {challenge, parseJwt, validateJwtClaims, sanitizedClaims} from '../src/oidc.js';
import {evaluatePairwise} from '../src/pairwise.js';
import {ConsentLedger} from '../src/audit.js';
const now=Math.floor(Date.now()/1000);
const payload={iss:'https://issuer.example.invalid',aud:'test-client',sub:'pairwise-991',iat:now,exp:now+300,nonce:'unique-nonce'};
test('PKCE S256 is deterministic and verifier-dependent',()=>{assert.equal(challenge('abc'),'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');assert.notEqual(challenge('abc'),challenge('def'));});
test('token temporal, audience and nonce safeguards',()=>{
  assert.equal(validateJwtClaims(payload,{issuer:payload.iss,clientId:payload.aud,nonce:payload.nonce}),true);
  assert.throws(()=>validateJwtClaims(payload,{issuer:payload.iss,clientId:'other',nonce:payload.nonce}),/audience/);
  assert.throws(()=>validateJwtClaims(payload,{issuer:payload.iss,clientId:payload.aud,nonce:'wrong'}),/nonce/);
  assert.throws(()=>validateJwtClaims({...payload,exp:now-1},{issuer:payload.iss,clientId:payload.aud,nonce:payload.nonce}),/Expired/);
});
test('signed JWT parser and claim allowlist',()=>{
  const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const a=Buffer.from(JSON.stringify({alg:'RS256',kid:'test'})).toString('base64url');
  const b=Buffer.from(JSON.stringify({...payload,email:'should-not-display@example.invalid'})).toString('base64url');
  const signature=sign('RSA-SHA256',Buffer.from(`${a}.${b}`),privateKey).toString('base64url');
  const parsed=parseJwt(`${a}.${b}.${signature}`);
  assert.equal(parsed.payload.sub,payload.sub);assert.equal(sanitizedClaims(parsed.payload).email,undefined);
  assert.throws(()=>parseJwt('header.payload'),/signed JWT/);
});
test('four client predicate refuses partial and cross-brand shared subjects',()=>{
  const v=(sub)=>({verified:true,claims:{sub,iss:'https://issuer'}});
  assert.equal(evaluatePairwise({}).status,'INCOMPLETE');
  const entries={'aurora-web':v('A'),'aurora-app':v('A'),'brisa-web':v('B'),'brisa-app':v('B')};
  assert.equal(evaluatePairwise(entries).status,'IDENTIFIER_PREDICATE_MET');
  assert.equal(evaluatePairwise(entries).canonicalPerson,'NOT_VERIFIED');
  entries['brisa-app']=v('A');assert.equal(evaluatePairwise(entries).status,'FAIL');
});
test('consent defaults to denial, scoped to directional origin/target, chained and revocable',()=>{
 const ledger=new ConsentLedger();const d={subject:'issuer|subject',origin:'aurora',target:'brisa',purpose:'delivery',client:'aurora-web'};
 assert.equal(ledger.decision(d).allow,false);
 ledger.write({...d,action:'GRANTED'});assert.equal(ledger.decision(d).allow,true);
 assert.equal(ledger.decision({...d,target:'aurora'}).allow,false);
 assert.equal(ledger.decision({...d,purpose:'customer-support'}).allow,false);
 ledger.write({...d,action:'REVOKED'});assert.equal(ledger.decision(d).allow,false);
 assert.equal(ledger.verifyChain(),true);
 assert.equal(ledger.history(d.subject).length,2);
});

test('pairwise predicate refuses equal subject strings from unrelated issuers',()=>{
  const v=(sub,iss)=>({verified:true,claims:{sub,iss}});
  const e={'aurora-web':v('a','https://issuer1'),'aurora-app':v('a','https://issuer2'),'brisa-web':v('b','https://issuer3'),'brisa-app':v('b','https://issuer3')};
  assert.equal(evaluatePairwise(e).status,'FAIL');
  assert.equal(evaluatePairwise(e).checks.auroraSameIssuer,false);
});
