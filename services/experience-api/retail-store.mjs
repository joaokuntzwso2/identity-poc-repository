/** Synthetic retail experience. NEVER use as authentication or credential storage. */
import {readFileSync} from 'node:fs';
const catalogue=JSON.parse(readFileSync(new URL('../../apps/experience-center/src/data/retail-products.json',import.meta.url),'utf8'));
const deny=(message,status=400)=>{throw Object.assign(new Error(message),{status})};
const time=()=>new Date().toISOString();
const people={'customer-ana':{name:'Ana Costa',city:'Campinas, SP',email:'ana@identidade.example',brands:['aurora','brisa']},'customer-rafael':{name:'Rafael Nunes',city:'Curitiba, PR',email:'rafael@identidade.example',brands:['aurora']}};
function plain(value,max=140){if(typeof value!=='string'||!value.trim()||value.length>max||/[<>\x00-\x1f]/.test(value))deny('INVALID_PREVIEW_FIELD');return value.trim()}
function pair(persona,brand){if(!['aurora','brisa'].includes(brand))deny('UNKNOWN_BRAND',404);if(!people[persona])deny('UNKNOWN_PERSONA',404);if(!people[persona].brands.includes(brand))deny('PERSONA_NOT_IN_BRAND',403)}
function yesNo(v){if(typeof v!=='boolean')deny('BOOLEAN_REQUIRED');return v?1:0}
export class RetailStore {
 constructor(db){this.db=db; db.exec(`
  CREATE TABLE IF NOT EXISTS retail_profiles(persona TEXT NOT NULL,brand TEXT NOT NULL,display_name TEXT NOT NULL,city TEXT NOT NULL,phone TEXT NOT NULL,PRIMARY KEY(persona,brand));
  CREATE TABLE IF NOT EXISTS retail_preferences(persona TEXT NOT NULL,brand TEXT NOT NULL,email INTEGER NOT NULL DEFAULT 0,sms INTEGER NOT NULL DEFAULT 0,order_alerts INTEGER NOT NULL DEFAULT 1,personalization INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(persona,brand));
  CREATE TABLE IF NOT EXISTS retail_credentials(persona TEXT NOT NULL,brand TEXT NOT NULL,passkey_demo INTEGER NOT NULL DEFAULT 0,totp_demo INTEGER NOT NULL DEFAULT 0,password_rotation_demo TEXT,PRIMARY KEY(persona,brand));
  CREATE TABLE IF NOT EXISTS retail_devices(persona TEXT NOT NULL,brand TEXT NOT NULL,id TEXT NOT NULL,label TEXT NOT NULL,last_seen TEXT NOT NULL,active INTEGER NOT NULL,PRIMARY KEY(persona,brand,id));
  CREATE TABLE IF NOT EXISTS retail_addresses(persona TEXT NOT NULL,brand TEXT NOT NULL,id TEXT NOT NULL,label TEXT NOT NULL,street TEXT NOT NULL,city TEXT NOT NULL,PRIMARY KEY(persona,brand,id));
  CREATE TABLE IF NOT EXISTS retail_wishlist(persona TEXT NOT NULL,brand TEXT NOT NULL,product_id TEXT NOT NULL,PRIMARY KEY(persona,brand,product_id));
  CREATE TABLE IF NOT EXISTS retail_orders(id TEXT PRIMARY KEY,persona TEXT NOT NULL,brand TEXT NOT NULL,lines_json TEXT NOT NULL,total INTEGER NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS retail_activity(id INTEGER PRIMARY KEY AUTOINCREMENT,persona TEXT NOT NULL,brand TEXT NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL,created_at TEXT NOT NULL);
  CREATE TRIGGER IF NOT EXISTS retail_activity_no_update BEFORE UPDATE ON retail_activity BEGIN SELECT RAISE(ABORT,'append only'); END;
  CREATE TRIGGER IF NOT EXISTS retail_activity_no_delete BEFORE DELETE ON retail_activity BEGIN SELECT RAISE(ABORT,'append only'); END;`);
 }
 tx(fn){this.db.exec('BEGIN IMMEDIATE');try{const v=fn();this.db.exec('COMMIT');return v}catch(e){this.db.exec('ROLLBACK');throw e}}
 log(persona,brand,kind,detail){this.db.prepare('INSERT INTO retail_activity(persona,brand,kind,detail,created_at) VALUES (?,?,?,?,?)').run(persona,brand,kind,detail,time())}
 seed(persona,brand){pair(persona,brand);const p=people[persona];this.tx(()=>{
  this.db.prepare('INSERT OR IGNORE INTO retail_profiles VALUES (?,?,?,?,?)').run(persona,brand,p.name,p.city,'+55 (11) 90000-0000');
  this.db.prepare('INSERT OR IGNORE INTO retail_preferences(persona,brand) VALUES (?,?)').run(persona,brand);
  this.db.prepare('INSERT OR IGNORE INTO retail_credentials(persona,brand) VALUES (?,?)').run(persona,brand);
  this.db.prepare('INSERT OR IGNORE INTO retail_devices VALUES (?,?,?,?,?,?)').run(persona,brand,'browser-demo','Navegador de demonstração',time(),1);
  this.db.prepare('INSERT OR IGNORE INTO retail_devices VALUES (?,?,?,?,?,?)').run(persona,brand,'phone-demo','Dispositivo móvel fictício','2026-10-18T12:00:00Z',1);
  this.db.prepare('INSERT OR IGNORE INTO retail_addresses VALUES (?,?,?,?,?,?)').run(persona,brand,'home','Casa','Rua da Amostra, 100',p.city);
  const existing=this.db.prepare('SELECT COUNT(*) as count FROM retail_orders WHERE persona=? AND brand=?').get(persona,brand).count;
  if(!existing){const x=catalogue[brand];for(let i=0;i<2;i++){
   const id=`${brand.toUpperCase().slice(0,3)}-${persona.endsWith('ana')?'ANA':'RAF'}-DEMO-${i+1}`;
   this.db.prepare('INSERT OR IGNORE INTO retail_orders VALUES (?,?,?,?,?,?,?)').run(id,persona,brand,JSON.stringify([{id:x[i].id,name:x[i].name,qty:1,price:x[i].price}]),x[i].price,i===0?'entregue':'a_caminho',i===0?'2026-09-20T10:00:00Z':'2026-10-11T10:00:00Z');
  }}
 });}
 snapshot(persona,brand){this.seed(persona,brand);const args=[persona,brand],get=(table)=>this.db.prepare(`SELECT * FROM ${table} WHERE persona=? AND brand=?`).get(...args);
  const profile=get('retail_profiles'),prefs=get('retail_preferences'),cred=get('retail_credentials');return {mode:'synthetic-preview',identityVerified:false,profile:{displayName:profile.display_name,city:profile.city,phone:profile.phone,email:people[persona].email},preferences:{email:!!prefs.email,sms:!!prefs.sms,orderAlerts:!!prefs.order_alerts,personalization:!!prefs.personalization},security:{passkeyPreview:!!cred.passkey_demo,totpPreview:!!cred.totp_demo,passwordRotationPreviewAt:cred.password_rotation_demo},devices:this.db.prepare('SELECT id,label,last_seen as lastSeen,active FROM retail_devices WHERE persona=? AND brand=? ORDER BY id').all(...args).map(x=>({...x,active:!!x.active})),addresses:this.db.prepare('SELECT id,label,street,city FROM retail_addresses WHERE persona=? AND brand=? ORDER BY id').all(...args),wishlist:this.db.prepare('SELECT product_id FROM retail_wishlist WHERE persona=? AND brand=?').all(...args).map(x=>x.product_id),orders:this.orders(persona,brand),activity:this.db.prepare('SELECT kind,detail,created_at as createdAt FROM retail_activity WHERE persona=? AND brand=? ORDER BY id DESC LIMIT 25').all(...args)};
 }
 orders(persona,brand){pair(persona,brand);return this.db.prepare('SELECT id,lines_json,total,status,created_at FROM retail_orders WHERE persona=? AND brand=? ORDER BY created_at DESC').all(persona,brand).map(x=>({id:x.id,lines:JSON.parse(x.lines_json),total:x.total,status:x.status,createdAt:x.created_at}));}
 profile(persona,brand,changes){this.seed(persona,brand);const displayName=plain(changes.displayName,70),city=plain(changes.city,80),phone=plain(changes.phone,30);
  return this.tx(()=>{this.db.prepare('UPDATE retail_profiles SET display_name=?,city=?,phone=? WHERE persona=? AND brand=?').run(displayName,city,phone,persona,brand);this.log(persona,brand,'profile','Dados de perfil fictícios atualizados');return this.snapshotWithoutSeeding(persona,brand)});
 }
 snapshotWithoutSeeding(persona,brand){const row=this.db.prepare('SELECT display_name as displayName,city,phone FROM retail_profiles WHERE persona=? AND brand=?').get(persona,brand);return {...row,email:people[persona].email}}
 preferences(persona,brand,changes){this.seed(persona,brand);const fields=['email','sms','orderAlerts','personalization'];if(Object.keys(changes).sort().join(',')!==fields.sort().join(','))deny('UNKNOWN_PREFERENCE_FIELD');const v=[yesNo(changes.email),yesNo(changes.sms),yesNo(changes.orderAlerts),yesNo(changes.personalization)];return this.tx(()=>{this.db.prepare('UPDATE retail_preferences SET email=?,sms=?,order_alerts=?,personalization=? WHERE persona=? AND brand=?').run(...v,persona,brand);this.log(persona,brand,'preferences','Preferências de comunicação atualizadas');return {email:!!v[0],sms:!!v[1],orderAlerts:!!v[2],personalization:!!v[3]}})}
 security(persona,brand,action,id){this.seed(persona,brand);const actions=['preview-passkey-add','preview-passkey-remove','preview-totp-on','preview-totp-off','preview-password-rotate','revoke-preview-device'];if(!actions.includes(action))deny('UNSUPPORTED_SECURITY_ACTION');return this.tx(()=>{
  if(action==='revoke-preview-device'){if(!['browser-demo','phone-demo'].includes(id))deny('UNKNOWN_DEVICE',404);const result=this.db.prepare('UPDATE retail_devices SET active=0 WHERE persona=? AND brand=? AND id=? AND active=1').run(persona,brand,id);if(!result.changes)deny('SESSION_ALREADY_REVOKED',409)}
  else if(action==='preview-password-rotate')this.db.prepare('UPDATE retail_credentials SET password_rotation_demo=? WHERE persona=? AND brand=?').run(time(),persona,brand);
  else {const field=action.startsWith('preview-passkey')?'passkey_demo':'totp_demo',enabled=action.endsWith('add')||action.endsWith('on');this.db.prepare(`UPDATE retail_credentials SET ${field}=? WHERE persona=? AND brand=?`).run(enabled?1:0,persona,brand)}
  this.log(persona,brand,'security',`Ação fictícia: ${action}`);return {applied:true,mode:'synthetic-preview',identityVerified:false};
 })}
 address(persona,brand,action,payload){this.seed(persona,brand);if(!['add','remove'].includes(action))deny('INVALID_ADDRESS_ACTION');return this.tx(()=>{if(action==='add'){const label=plain(payload.label,40),street=plain(payload.street,100),city=plain(payload.city,80),id=`preview-${crypto.randomUUID().slice(0,12)}`;this.db.prepare('INSERT INTO retail_addresses VALUES (?,?,?,?,?,?)').run(persona,brand,id,label,street,city);this.log(persona,brand,'address','Endereço fictício adicionado');return{id,label,street,city}}
  const result=this.db.prepare('DELETE FROM retail_addresses WHERE persona=? AND brand=? AND id=?').run(persona,brand,plain(payload.id,60));if(!result.changes)deny('ADDRESS_NOT_FOUND',404);this.log(persona,brand,'address','Endereço fictício excluído');return{deleted:true};})}
 wishlist(persona,brand,productId){this.seed(persona,brand);if(!catalogue[brand].some(x=>x.id===productId))deny('PRODUCT_NOT_FOUND',404);return this.tx(()=>{const before=this.db.prepare('SELECT 1 FROM retail_wishlist WHERE persona=? AND brand=? AND product_id=?').get(persona,brand,productId);if(before)this.db.prepare('DELETE FROM retail_wishlist WHERE persona=? AND brand=? AND product_id=?').run(persona,brand,productId);else this.db.prepare('INSERT INTO retail_wishlist VALUES (?,?,?)').run(persona,brand,productId);this.log(persona,brand,'wishlist',before?'Produto removido dos favoritos':'Produto adicionado aos favoritos');return{saved:!before};})}
 order(persona,brand,action,payload){this.seed(persona,brand);if(action==='request'){
  if(!Array.isArray(payload.items)||payload.items.length===0||payload.items.length>16)deny('INVALID_CART');let sum=0;
  const lines=payload.items.map(line=>{const product=catalogue[brand].find(p=>p.id===line.id);if(!product||!Number.isInteger(line.qty)||line.qty<1||line.qty>10)deny('INVALID_CART_LINE');sum+=product.price*line.qty;return{id:product.id,name:product.name,price:product.price,qty:line.qty}});
  if(sum<=0||sum>50000)deny('LIMIT_EXCEEDED');return this.tx(()=>{const id=`${brand.toUpperCase().slice(0,3)}-PREV-${crypto.randomUUID().slice(0,8).toUpperCase()}`;this.db.prepare('INSERT INTO retail_orders VALUES (?,?,?,?,?,?,?)').run(id,persona,brand,JSON.stringify(lines),sum,'aguardando_confirmacao',time());this.log(persona,brand,'order',`Pedido de preview ${id} aguardando confirmação`);return{id,total:sum,status:'aguardando_confirmacao',lines};});
 }
 if(!['approve','deny'].includes(action))deny('UNSUPPORTED_ORDER_ACTION');if(typeof payload.orderId!=='string')deny('ORDER_ID_REQUIRED');if(action==='approve'&&payload.previewAcknowledged!==true)deny('EXPLICIT_PREVIEW_ACK_REQUIRED',403);
 return this.tx(()=>{const row=this.db.prepare('SELECT * FROM retail_orders WHERE id=? AND persona=? AND brand=?').get(payload.orderId,persona,brand);if(!row)deny('ORDER_NOT_FOUND',404);if(row.status!=='aguardando_confirmacao')deny('ORDER_ALREADY_RESOLVED',409);const status=action==='approve'?'confirmado_no_preview':'recusado_no_preview';this.db.prepare('UPDATE retail_orders SET status=? WHERE id=?').run(status,payload.orderId);this.log(persona,brand,'order',`Pedido ${payload.orderId}: ${status}`);return{id:payload.orderId,total:row.total,status};});
 }
}
