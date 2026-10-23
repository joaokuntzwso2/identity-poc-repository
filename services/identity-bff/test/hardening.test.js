import test from 'node:test';
import assert from 'node:assert/strict';
import {assertTrustedEndpoint} from '../src/oidc.js';
import {DemoSessionStore} from '../src/session-store.js';

const issuer='https://id.poc-poc.example/oauth2/token';
test('discovery URLs and JWKS must remain on explicitly trusted HTTPS origins',()=>{
  assert.equal(assertTrustedEndpoint('https://id.poc-poc.example/jwks',issuer),'https://id.poc-poc.example/jwks');
  assert.throws(()=>assertTrustedEndpoint('http://id.poc-poc.example/jwks',issuer),/protocol/);
  assert.throws(()=>assertTrustedEndpoint('https://169.254.169.254/latest/meta-data',issuer),/not trusted/);
  assert.throws(()=>assertTrustedEndpoint('https://attacker.example/jwks',issuer),/not trusted/);
  assert.throws(()=>assertTrustedEndpoint('https://bob:id.poc-poc.example@attacker.example/jwks',issuer),/forbidden/);
  assert.throws(()=>assertTrustedEndpoint('https://id.poc-poc.example/jwks#token',issuer),/forbidden/);
});
test('local HTTP exception is loopback only',()=>{
  const before=process.env.ALLOW_INSECURE_LOCAL;
  process.env.ALLOW_INSECURE_LOCAL='true';
  try {
    assert.equal(assertTrustedEndpoint('http://127.0.0.1:9443/jwks','http://127.0.0.1:9443/oauth2/token'),'http://127.0.0.1:9443/jwks');
    assert.throws(()=>assertTrustedEndpoint('http://192.168.1.2/jwks','http://192.168.1.2/oauth2/token'),/protocol/);
  }finally{if(before===undefined)delete process.env.ALLOW_INSECURE_LOCAL;else process.env.ALLOW_INSECURE_LOCAL=before;}
});
test('sessions rotate on login and are destroyed on logout',()=>{
  const store=new DemoSessionStore({maxSessions:3});
  const headers={};const res={setHeader(k,v){headers[k]=v;}};
  const anon=store.ensure({headers:{}},res);
  const first=anon.id,csrf=anon.csrf;
  const session=store.rotate(anon,res);
  assert.notEqual(session.id,first);assert.notEqual(session.csrf,csrf);
  assert.equal(store.sessions.has(first),false);
  assert.ok(headers['Set-Cookie'].includes(session.id));
  store.destroy(session,res);
  assert.equal(store.sessions.size,0);
  assert.ok(headers['Set-Cookie'].includes('Max-Age=0'));
});
test('a full session store rejects new sessions, rather than evicting logged-in sessions',()=>{
  const store=new DemoSessionStore({maxSessions:1});
  const res={setHeader(){}};
  const established=store.ensure({headers:{}},res);
  established.logins['aurora-web']={verified:true};
  assert.equal(store.ensure({headers:{}},res),null);
  assert.equal(store.sessions.has(established.id),true);
});
test('secure sessions use __Host cookie with Secure flag',()=>{
  const s=new DemoSessionStore({secure:true});let header='';
  s.ensure({headers:{}},{setHeader(k,v){header=v;}});
  assert.match(header,/^__Host-poc_sid=/);
  assert.match(header,/; Secure/);
});
