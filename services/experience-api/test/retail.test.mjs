import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {RetailStore} from '../retail-store.mjs';
import {createPreviewServer} from '../server.mjs';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

function store(){const db=new DatabaseSync(':memory:');return{db,retail:new RetailStore(db)}}
test('two brands keep independent preferences, profile and order history',()=>{
 const {db,retail}=store();retail.preferences('customer-ana','aurora',{email:true,sms:false,orderAlerts:true,personalization:false});
 const a=retail.snapshot('customer-ana','aurora'),b=retail.snapshot('customer-ana','brisa');
 assert.equal(a.preferences.email,true);assert.equal(b.preferences.email,false);
 retail.profile('customer-ana','aurora',{displayName:'Ana Preview',city:'Cidade Exemplo',phone:'00000000'});
 assert.equal(retail.snapshot('customer-ana','aurora').profile.displayName,'Ana Preview');assert.equal(retail.snapshot('customer-ana','brisa').profile.displayName,'Ana Costa');
 assert.ok(a.orders.every(x=>x.id.startsWith('AUR')));assert.ok(b.orders.every(x=>x.id.startsWith('BRI')));
 db.close();
});
test('unrelated persona cannot access another brand and mutations fail closed',()=>{
 const {db,retail}=store();assert.throws(()=>retail.snapshot('customer-rafael','brisa'),/PERSONA_NOT_IN_BRAND/);
 assert.throws(()=>retail.snapshot('seller-marcos','aurora'),/UNKNOWN_PERSONA/);
 assert.throws(()=>retail.security('customer-ana','aurora','set-real-password'),/UNSUPPORTED_SECURITY_ACTION/);
 db.close();
});
test('credentials are NEVER accepted, stored, or used as authentication',()=>{
 const {db,retail}=store();retail.security('customer-ana','aurora','preview-password-rotate');
 const s=retail.snapshot('customer-ana','aurora');assert.ok(s.security.passwordRotationPreviewAt);
 assert.equal(Object.hasOwn(s.security,'password'),false);
 const columns=db.prepare('PRAGMA table_info(retail_credentials)').all().map(x=>x.name);
 assert.ok(!columns.some(x=>/password_hash|password_secret|otp_secret|private_key/.test(x)));
 retail.security('customer-ana','aurora','preview-passkey-add');assert.equal(retail.snapshot('customer-ana','aurora').security.passkeyPreview,true);
 db.close();
});
test('sessions are synthetic and revocation scoped by brand',()=>{
 const {db,retail}=store();retail.security('customer-ana','aurora','revoke-preview-device','phone-demo');
 assert.equal(retail.snapshot('customer-ana','aurora').devices.find(x=>x.id==='phone-demo').active,false);
 assert.equal(retail.snapshot('customer-ana','brisa').devices.find(x=>x.id==='phone-demo').active,true);
 assert.throws(()=>retail.security('customer-ana','aurora','revoke-preview-device','phone-demo'),/SESSION_ALREADY_REVOKED/);
 db.close();
});
test('checkout ignores client-supplied prices, requires explicit approval, prevents double approval',()=>{
 const {db,retail}=store();const pending=retail.order('customer-ana','aurora','request',{items:[{id:'a1',qty:2,price:1}]});
 assert.equal(pending.total,1598);assert.equal(pending.status,'aguardando_confirmacao');
 assert.throws(()=>retail.order('customer-ana','aurora','approve',{orderId:pending.id}),/EXPLICIT_PREVIEW_ACK_REQUIRED/);
 assert.throws(()=>retail.order('customer-ana','brisa','approve',{orderId:pending.id,previewAcknowledged:true}),/ORDER_NOT_FOUND/);
 assert.equal(retail.order('customer-ana','aurora','approve',{orderId:pending.id,previewAcknowledged:true}).status,'confirmado_no_preview');
 assert.throws(()=>retail.order('customer-ana','aurora','approve',{orderId:pending.id,previewAcknowledged:true}),/ORDER_ALREADY_RESOLVED/);
 assert.throws(()=>retail.order('customer-ana','aurora','request',{items:[{id:'b1',qty:1}]}),/INVALID_CART_LINE/);
 db.close();
});
test('order denial and activity history survive DB restart',()=>{
 const dir=mkdtempSync(join(tmpdir(),'identity-retail-'));const f=join(dir,'retail.sqlite');
 try{const a=new DatabaseSync(f),x=new RetailStore(a);const p=x.order('customer-ana','brisa','request',{items:[{id:'b1',qty:1}]});x.order('customer-ana','brisa','deny',{orderId:p.id});a.close();
 const b=new DatabaseSync(f),y=new RetailStore(b),s=y.snapshot('customer-ana','brisa');assert.equal(s.orders.find(v=>v.id===p.id).status,'recusado_no_preview');assert.ok(s.activity.some(v=>v.kind==='order'));assert.throws(()=>b.exec('DELETE FROM retail_activity'),/append only/);b.close();
 }finally{rmSync(dir,{recursive:true,force:true})}
});
test('wishlists, addresses, and communication preferences persist per brand',()=>{
 const {db,retail}=store();assert.equal(retail.wishlist('customer-ana','aurora','a1').saved,true);
 assert.equal(retail.snapshot('customer-ana','aurora').wishlist.includes('a1'),true);
 assert.equal(retail.snapshot('customer-ana','brisa').wishlist.length,0);
 const a=retail.address('customer-ana','aurora','add',{label:'Trabalho',street:'Rua Fictícia 23',city:'Cidade Teste'});assert.ok(a.id.startsWith('preview-'));
 assert.ok(retail.snapshot('customer-ana','aurora').addresses.some(x=>x.id===a.id));
 retail.address('customer-ana','aurora','remove',{id:a.id});assert.equal(retail.snapshot('customer-ana','aurora').addresses.some(x=>x.id===a.id),false);
 assert.throws(()=>retail.preferences('customer-ana','aurora',{email:'true',sms:false,orderAlerts:true,personalization:false}),/BOOLEAN_REQUIRED/);
 db.close();
});
test('HTTP API needs explicit preview intent; can never claim verified identity',async()=>{
 const server=createPreviewServer({dbFile:':memory:',serveDist:false});await new Promise(done=>server.listen(0,'127.0.0.1',done));const base=`http://127.0.0.1:${server.address().port}`;
 try{const s=await(await fetch(`${base}/api/retail/aurora/bootstrap?persona=customer-ana`)).json();assert.equal(s.identityVerified,false);
 const payload={persona:'customer-ana',action:'preview-passkey-add'};
 const denied=await fetch(`${base}/api/retail/aurora/security`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});assert.equal(denied.status,403);
 const allowed=await fetch(`${base}/api/retail/aurora/security`,{method:'POST',headers:{'Content-Type':'application/json','X-Experience-Preview':'yes'},body:JSON.stringify(payload)});assert.equal(allowed.status,200);assert.equal((await allowed.json()).identityVerified,false);
 const b=await fetch(`${base}/api/retail/brisa/bootstrap?persona=customer-rafael`);assert.equal(b.status,403);
 const crossOrigin=await fetch(`${base}/api/retail/aurora/bootstrap?persona=customer-ana`,{headers:{Origin:'https://external.example'}});assert.equal(crossOrigin.status,403);
 }finally{await new Promise(done=>server.close(done))}
});
