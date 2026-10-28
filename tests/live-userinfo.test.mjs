import test from 'node:test';
import assert from 'node:assert/strict';
import { userinfoEndpoint, verifiedUserinfoClaims, readVerifiedUserinfo } from '../services/identity-bff/src/live-userinfo.js';
const issuer='https://localhost:9444/t/aurora.identity.test/oauth2/token';
const endpoint='https://localhost:9444/t/aurora.identity.test/oauth2/userinfo';
test('accepts only same-origin trusted UserInfo', () => {
  assert.equal(userinfoEndpoint({userinfo_endpoint:endpoint},issuer),endpoint);
  for (const url of ['http://localhost:9444/oauth2/userinfo',
    'https://evil.example/oauth2/userinfo', 'https://localhost:9444/t/a/scim2/Users',
    'https://localhost:9444/oauth2/userinfo?exfil=yes'])
    assert.throws(() => userinfoEndpoint({userinfo_endpoint:url},issuer));
});
test('requires subject equality before returning attributes', () => {
  assert.deepEqual(verifiedUserinfoClaims({sub:'one',name:'Real Name',roles:['admin'],foo:'bar'},'one'), {name:'Real Name'});
  assert.throws(() => verifiedUserinfoClaims({sub:'two',name:'Not Real'},'one'), /mismatch/);
  assert.throws(() => verifiedUserinfoClaims({name:'No Subject'},'one'), /mismatch/);
});
test('binds the bearer request to the expected ID token subject', async () => {
  const result=await readVerifiedUserinfo({issuer,discovery:{userinfo_endpoint:endpoint},subject:'pairwise-1',accessToken:'OPAQUE',
    request:async(url,opts)=> {
      assert.equal(url,endpoint);
      assert.equal(opts.headers.authorization,'Bearer OPAQUE');
      assert.equal(opts.redirect,'error');
      return {ok:true,headers:{get:()=>null},text:async()=>JSON.stringify({sub:'pairwise-1',email:'real@example.test'})};
    }});
  assert.deepEqual(result,{email:'real@example.test'});
});
