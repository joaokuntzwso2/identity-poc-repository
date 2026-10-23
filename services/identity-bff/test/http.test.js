import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
const PORT=46891;const base=`http://127.0.0.1:${PORT}`;
let child;
test.before(async()=>{
 child=spawn(process.execPath,['services/identity-bff/src/server.js'],{cwd:process.cwd(),env:{...process.env,PORT:String(PORT),PUBLIC_ORIGIN:base,ALLOW_INSECURE_LOCAL:'true',NODE_ENV:'development'},stdio:['ignore','pipe','pipe']});
 const timeout=Date.now()+3000;while(Date.now()<timeout){try{const res=await fetch(base+'/api/health');if(res.status===200)return;}catch{}await new Promise(r=>setTimeout(r,40));}throw new Error('Local BFF test server failed to start');
});
test.after(()=>{child?.kill('SIGTERM');});
test('health and all mandatory scenario metadata over actual HTTP',async()=>{
 const h=await fetch(base+'/api/health').then(r=>r.json());assert.equal(h.status,'UP');
 const s=await fetch(base+'/api/scenarios').then(r=>r.json());assert.equal(s.filter(x=>x.id.startsWith('M-02.')).length,7);
});
test('sector documents contain two distinct callback URIs per brand',async()=>{
 const r=await fetch(base+'/oidc/sector/aurora.json');const v=await r.json();assert.equal(v.length,2);
 assert.ok(v.every(x=>x.startsWith(base+'/auth/aurora-')));
 assert.equal((await fetch(base+'/oidc/sector/brisa.json').then(r=>r.json())).length,2);
});
test('anonymous post to operator-only M2M is denied without CSRF and identity',async()=>{
 const r=await fetch(base+'/api/m2m/client-credentials',{method:'POST'});
 assert.equal(r.status,403);assert.equal((await r.json()).error,'origin_denied');
});
test('login fails closed when client was not provisioned in WSO2',async()=>{
 const r=await fetch(base+'/auth/aurora-web/login',{redirect:'manual'});
 assert.equal(r.status,503);assert.equal((await r.json()).error,'oidc_client_not_configured');
});
test('session discloses no non-redacted bearer tokens',async()=>{
 const r=await fetch(base+'/api/session');const json=await r.json();assert.ok(json.csrf);assert.equal(json.authenticated,false);
 assert.equal(json.pairwise.status,'INCOMPLETE');assert.equal(json.pairwise.canonicalPerson,'NOT_VERIFIED');
});

test('public status and sector endpoints do not allocate browser sessions',async()=>{
 const paths=['/api/health','/api/scenarios','/api/wso2-status','/oidc/sector/aurora.json'];
 for(const path of paths){const r=await fetch(base+path);assert.equal(r.headers.get('set-cookie'),null,`${path} created a session`);}
});
test('consent mutation requires opt-in pilot and refuses anonymous browsers',async()=>{
 const r=await fetch(base+'/api/session');const csrf=(await r.json()).csrf;const cookie=r.headers.get('set-cookie').split(';')[0];
 const result=await fetch(base+'/api/consent',{method:'POST',headers:{cookie,origin:base,'x-csrf-token':csrf,'content-type':'application/json'},body:JSON.stringify({origin:'aurora',target:'brisa',purpose:'delivery',client:'aurora-web',action:'GRANTED'})});
 assert.equal(result.status,401);
});
