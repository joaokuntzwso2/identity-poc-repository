/** OIDC fixture exists ONLY inside the test suite. The demo has no mock IdP. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';

const keys=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk=keys.publicKey.export({format:'jwk'});
Object.assign(jwk,{kid:'fixture',use:'sig',alg:'RS256'});
let issuer, provider, bff, origin, verifierChallenge, expectedNonce;
const minted=[];
function token(nonce){const now=Math.floor(Date.now()/1000);
 const header=Buffer.from(JSON.stringify({kid:'fixture',alg:'RS256',typ:'JWT'})).toString('base64url');
 const payload=Buffer.from(JSON.stringify({iss:issuer,aud:'aurora-test-client',sub:'pairwise-sub-fixture',nonce,iat:now,exp:now+300})).toString('base64url');
 const signature=sign('RSA-SHA256',Buffer.from(`${header}.${payload}`),keys.privateKey).toString('base64url');
 return `${header}.${payload}.${signature}`;
}
async function waitHealth(){for(let i=0;i<100;i++){try{const response=await fetch(origin+'/api/health');if(response.ok)return;}catch{}await new Promise(r=>setTimeout(r,40));}throw new Error('BFF unavailable');}

test.before(async()=>{
 provider=createServer(async(req,res)=>{
  const url=new URL(req.url,issuer);
  if(url.pathname==='/jwks') {res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({keys:[jwk]}));}
  if(url.pathname==='/oauth2/token'&&req.method==='POST') {
    let body='';for await(const part of req)body+=part;
    const fields=new URLSearchParams(body);
    const challenge=createHash('sha256').update(fields.get('code_verifier')||'').digest('base64url');
    if(fields.get('code')!=='test-code'||fields.get('client_id')!=='aurora-test-client'||challenge!==verifierChallenge){res.writeHead(400);return res.end('{}');}
    minted.push(true);
    res.writeHead(200,{'content-type':'application/json'});
    return res.end(JSON.stringify({id_token:token(expectedNonce),access_token:'secret-only-for-test',token_type:'Bearer',expires_in:300}));
  }
  const doc={issuer,authorization_endpoint:new URL('/authorize',issuer).toString(),token_endpoint:new URL('/oauth2/token',issuer).toString(),jwks_uri:new URL('/jwks',issuer).toString(),subject_types_supported:['pairwise']};
  res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(doc));
 });
 await new Promise(resolve=>provider.listen(0,'127.0.0.1',resolve));
 issuer=`http://127.0.0.1:${provider.address().port}/oauth2/token`;
 // Use a free port: acquire with temporary listener, then release before BFF starts.
 const temp=createServer();await new Promise(resolve=>temp.listen(0,'127.0.0.1',resolve));
 const port=temp.address().port;await new Promise(resolve=>temp.close(resolve));
 origin=`http://127.0.0.1:${port}`;
 bff=spawn(process.execPath,['services/identity-bff/src/server.js'],{
  cwd:process.cwd(),env:{...process.env,PORT:String(port),BIND_HOST:'127.0.0.1',PUBLIC_ORIGIN:origin,ALLOW_INSECURE_LOCAL:'true',NODE_ENV:'development',OIDC_ISSUER:issuer,OIDC_AURORA_WEB_CLIENT_ID:'aurora-test-client',OIDC_DISCOVERY_URL:`http://127.0.0.1:${provider.address().port}/test-discovery`,ENABLE_EPHEMERAL_CONSENT:'true'},stdio:['ignore','pipe','pipe']
 });
 await waitHealth();
});
test.after(async()=>{bff?.kill('SIGTERM');await new Promise(resolve=>provider?.close(resolve));});

test('actual BFF login + signed JWT fixture rotates cookie and requires origin-client consent',async()=>{
 const authorization=await fetch(origin+'/auth/aurora-web/login',{redirect:'manual'});
 assert.equal(authorization.status,302);
 const originalCookie=authorization.headers.get('set-cookie').split(';')[0];
 const authorUrl=new URL(authorization.headers.get('location'));
 assert.equal(authorUrl.searchParams.get('code_challenge_method'),'S256');
 verifierChallenge=authorUrl.searchParams.get('code_challenge');
 expectedNonce=authorUrl.searchParams.get('nonce');
 const state=authorUrl.searchParams.get('state');
 const callback=await fetch(`${origin}/auth/aurora-web/callback?code=test-code&state=${encodeURIComponent(state)}`,{headers:{cookie:originalCookie},redirect:'manual'});
 assert.equal(callback.status,302);
 const freshCookie=callback.headers.get('set-cookie').split(';')[0];
 assert.notEqual(freshCookie,originalCookie,'Session ID not rotated after verified login');
 assert.equal(callback.headers.get('referrer-policy'),'no-referrer');
 assert.equal(minted.length,1);
 const old=await fetch(origin+'/api/session',{headers:{cookie:originalCookie}}).then(x=>x.json());
 assert.equal(old.authenticated,false,'Old pre-auth SID retained identity');
 const actual=await fetch(origin+'/api/session',{headers:{cookie:freshCookie}}).then(x=>x.json());
 assert.equal(actual.authenticated,true);
 assert.equal(actual.logins['aurora-web'].verified,true);
 assert.equal(actual.pairwise.status,'INCOMPLETE');
 assert.ok(!JSON.stringify(actual).includes('secret-only-for-test'));
 // Having Aurora Web auth must not authorize Brisa Web consent management.
 const args={origin:'brisa',target:'aurora',client:'brisa-web',purpose:'delivery',action:'GRANTED'};
 const response=await fetch(origin+'/api/consent',{method:'POST',headers:{cookie:freshCookie,origin,'x-csrf-token':actual.csrf,'content-type':'application/json'},body:JSON.stringify(args)});
 assert.equal(response.status,403);
 assert.equal((await response.json()).error,'origin_client_authentication_required');
 const valid={...args,origin:'aurora',target:'brisa',client:'aurora-web'};
 const post=await fetch(origin+'/api/consent',{method:'POST',headers:{cookie:freshCookie,origin,'x-csrf-token':actual.csrf,'content-type':'application/json'},body:JSON.stringify(valid)});
 assert.equal(post.status,201);
 const history=await fetch(origin+'/api/consent',{headers:{cookie:freshCookie}}).then(x=>x.json());
 assert.equal(history.events.length,1);
 assert.equal(history.mode,'EPHEMERAL_EXTENSION_PILOT');
});
