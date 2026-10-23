import {test} from 'node:test';
import {strict as assert} from 'node:assert';
import {handleDurableConsent} from '../src/identity/consent-api.js';
const originSession={logins:{'aurora-web':{verified:true,claims:{iss:'https://idp.example',sub:'synthetic-1'}}}};
const clients={'aurora-web':{brand:'aurora'},'brisa-web':{brand:'brisa'}};
async function request(body,{login=originSession,route='record',repo}={}){
 let output;const reply=(_res,status,value)=>{output={status,value};};
 const originalRepo=repo||{record:async d=>({mode:'AE_POSTGRES_LEDGER',decision:d.decision}),evaluate:async()=>({decision:'DENY'})};
 await handleDurableConsent({req:{method:'POST'},res:{},u:{pathname:`/api/identity/consent/${route}`},s:login,reply,
  requirePost:()=>true,bodyJson:async()=>body,subjectOf:(s,key)=>s?.logins[key]?.verified?'principal':null,clients,repoOverride:originalRepo});
 return output;
}
const input={client:'aurora-web',origin:'aurora',target:'brisa',purpose:'delivery',scope:'profile.read',action:'GRANTED'};
test('consent endpoint refuses client-origin mismatch, even if authenticated',async()=>{
 const output=await request({...input,origin:'brisa'});
 assert.equal(output.status,403);
});
test('consent requires actual WSO2-authenticated source client',async()=>{
 const output=await request(input,{login:{logins:{}}});assert.equal(output.status,403);
});
test('consent grant and deny check are backed by repository, not synthetic PASS',async()=>{
 const grant=await request(input);assert.equal(grant.status,201);
 const check=await request(input,{route:'check'});assert.equal(check.status,403);assert.equal(check.value.decision,'DENY');
});
