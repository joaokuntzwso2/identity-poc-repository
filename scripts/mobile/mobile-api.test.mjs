import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createPreviewServer} from '../../services/experience-api/server.mjs';
const json=async(response)=>{const data=await response.json();return {status:response.status,data}};

test('web and mobile share persisted brand-scoped preferences without inter-brand inheritance',async()=>{
 const dir=mkdtempSync(path.join(os.tmpdir(),'identity-mobile-v05-'));
 const server=createPreviewServer({dbFile:path.join(dir,'preview.sqlite'),serveDist:false});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const port=server.address().port;
 const base=`http://127.0.0.1:${port}/api/retail`;
 const get=(brand)=>fetch(`${base}/${brand}/bootstrap?persona=customer-ana`).then(json);
 const post=(brand,data)=>fetch(`${base}/${brand}/preferences`,{method:'POST',headers:{'Content-Type':'application/json','X-Experience-Preview':'yes'},body:JSON.stringify({persona:'customer-ana',changes:data})}).then(json);
 try{
  const aurora=await get('aurora'),brisa=await get('brisa');
  assert.equal(aurora.status,200);assert.equal(brisa.status,200);
  assert.equal(aurora.data.identityVerified,false);
  const beforeBrisa=brisa.data.preferences;
  const changes={email:true,sms:true,orderAlerts:false,personalization:true};
  const changed=await post('aurora',changes);
  assert.equal(changed.status,200);
  assert.deepEqual((await get('aurora')).data.preferences,changes);
  assert.deepEqual((await get('brisa')).data.preferences,beforeBrisa);
 }finally{await new Promise(resolve=>server.close(resolve));rmSync(dir,{recursive:true,force:true})}
});

test('API refuses unauthenticated-meaningful mutations without preview intent marker',async()=>{
 const dir=mkdtempSync(path.join(os.tmpdir(),'identity-mobile-v05-'));
 const server=createPreviewServer({dbFile:path.join(dir,'preview.sqlite'),serveDist:false});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const port=server.address().port;
 try{
  const response=await fetch(`http://127.0.0.1:${port}/api/retail/aurora/security`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({persona:'customer-ana',action:'preview-passkey-add'})});
  assert.equal(response.status,403);
  assert.equal((await response.json()).error,'PREVIEW_INTENT_REQUIRED');
 }finally{await new Promise(resolve=>server.close(resolve));rmSync(dir,{recursive:true,force:true})}
});
