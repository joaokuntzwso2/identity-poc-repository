import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectAccessToken, requireAuthorityForClient, AuthorityUnavailable } from '../src/wso2-authority.js';
const issuer='https://localhost:9444/t/aurora.identity.test/oauth2/token';
const a={clientId:'aurora-rp',clientSecret:'only-in-server',issuer};
const b={clientId:'brisa-rp',clientSecret:'only-in-server',issuer:'https://localhost:9444/t/brisa.identity.test/oauth2/token'};
const login={verified:true,accessToken:'actual-token'};
const response = v => async () => ({status:200,headers:{get:()=>null},text:async()=>JSON.stringify(v)});
test('anonymous, fixture, wrong-tenant sessions fail without fetching WSO2',async()=>{
  const clients={'aurora-web':a,'brisa-web':b};
  for (const s of [{logins:{}},{logins:{'aurora-web':{verified:false,accessToken:'fixture'}}},{logins:{'brisa-web':login}}]) {
    assert.equal((await requireAuthorityForClient(s,'aurora-web',clients,'ciam:profile:read','https://api.ciam-v10.test/profile')).http,401);
  }
});
test('introspection timeout or API 401 cannot fall back to a synthetic permission',async()=>{
  const session={logins:{'aurora-web':login}},clients={'aurora-web':a};
  assert.equal((await requireAuthorityForClient(session,'aurora-web',clients,'ciam:profile:read','https://api.ciam-v10.test/profile',
    async()=>{throw new AuthorityUnavailable();})).http,503);
  await assert.rejects(inspectAccessToken(login,a,{fetcher:async()=>{throw Error('ECONNREFUSED');}}),AuthorityUnavailable);
  await assert.rejects(inspectAccessToken(login,a,{fetcher:async()=>({status:401,headers:{get:()=>null},text:async()=>''})}),AuthorityUnavailable);
});
test('wrong issuer, wrong audience, expired and revoked access tokens are denied',async()=>{
  const base={active:true,client_id:a.clientId,scope:'ciam:profile:read',exp:4102444800,aud:'https://api.ciam-v10.test/profile'};
  for (const change of [{iss:b.issuer},{aud:'different'},{exp:42},{active:false},{client_id:b.clientId}]) {
    const result=await inspectAccessToken(login,a,{fetcher:response({...base,...change}),audience:'https://api.ciam-v10.test/profile'});
    assert.equal(result.active,false);
  }
});
test('a valid ID token without WSO2 business API scope is always 403',async()=>{
  const result=await requireAuthorityForClient({logins:{'aurora-web':login}},'aurora-web',{'aurora-web':a},
    'ciam:profile:read','https://api.ciam-v10.test/profile',async()=>({active:true,scopes:['openid']}));
  assert.equal(result.http,403);
});
