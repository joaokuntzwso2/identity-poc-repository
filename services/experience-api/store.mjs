import {DatabaseSync} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {dirname} from 'node:path';
import {DEMO_CONSENTS,DEMO_ATTRIBUTES,isPerson,assertTransition,mask,validateAttributeChange} from './domain.mjs';
export class PreviewStore {
 constructor(dbFile){
  if(dbFile!==':memory:')mkdirSync(dirname(dbFile),{recursive:true,mode:0o700});
  this.db = new DatabaseSync(dbFile);
  this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
  CREATE TABLE IF NOT EXISTS decisions (persona TEXT NOT NULL,consent_id TEXT NOT NULL, state TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL,expires_at TEXT,PRIMARY KEY(persona,consent_id));
  CREATE TABLE IF NOT EXISTS consent_events (id INTEGER PRIMARY KEY AUTOINCREMENT, persona TEXT NOT NULL,consent_id TEXT NOT NULL,from_state TEXT,to_state TEXT NOT NULL,version INTEGER NOT NULL,occurred_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS attributes (persona TEXT NOT NULL, attribute TEXT NOT NULL,value TEXT NOT NULL,source TEXT NOT NULL,level TEXT NOT NULL,verified_at TEXT,expires_at TEXT,version INTEGER NOT NULL DEFAULT 1,updated_at TEXT NOT NULL,PRIMARY KEY(persona,attribute));
  CREATE TABLE IF NOT EXISTS attribute_events (id INTEGER PRIMARY KEY AUTOINCREMENT,persona TEXT NOT NULL,attribute TEXT NOT NULL,old_level TEXT,new_level TEXT NOT NULL,source TEXT NOT NULL,version INTEGER NOT NULL,occurred_at TEXT NOT NULL);
  CREATE TRIGGER IF NOT EXISTS consent_events_no_update BEFORE UPDATE ON consent_events BEGIN SELECT RAISE(ABORT,'append only'); END;
  CREATE TRIGGER IF NOT EXISTS consent_events_no_delete BEFORE DELETE ON consent_events BEGIN SELECT RAISE(ABORT,'append only'); END;
  CREATE TRIGGER IF NOT EXISTS attribute_events_no_update BEFORE UPDATE ON attribute_events BEGIN SELECT RAISE(ABORT,'append only'); END;
  CREATE TRIGGER IF NOT EXISTS attribute_events_no_delete BEFORE DELETE ON attribute_events BEGIN SELECT RAISE(ABORT,'append only'); END;`);
 }
 assertPersona(persona){if(!isPerson(persona))throw Object.assign(new Error('UNKNOWN_SYNTHETIC_PERSONA'),{status:404})}
 tx(fn){this.db.exec('BEGIN IMMEDIATE');try{const result=fn();this.db.exec('COMMIT');return result}catch(e){this.db.exec('ROLLBACK');throw e}}
 seed(persona){
  this.assertPersona(persona);
  this.tx(()=>{
   for(const c of DEMO_CONSENTS){
    this.db.prepare('INSERT OR IGNORE INTO decisions (persona,consent_id,state,version,updated_at) VALUES (?,?,?,0,?)').run(persona,c.id,'pending',new Date().toISOString());
   }
   for(const a of DEMO_ATTRIBUTES){
    this.db.prepare('INSERT OR IGNORE INTO attributes (persona,attribute,value,source,level,verified_at,expires_at,updated_at) VALUES (?,?,?,?,?,?,?,?)').run(persona,a.attribute,(persona==='customer-rafael'&&a.attribute==='email')?'rafael@identidade.example':a.value,a.source,a.level,a.verifiedAt,a.expiresAt,new Date().toISOString());
   }
  });
 }
 listConsents(persona){
  this.seed(persona);
  this.expireConsents(persona);
  const byId=new Map(this.db.prepare('SELECT * FROM decisions WHERE persona=?').all(persona).map(v=>[v.consent_id,v]));
  return DEMO_CONSENTS.filter(c=>persona!=='customer-rafael'||(c.origin==='aurora'&&c.target==='aurora')).map(c=>({...c,state:byId.get(c.id)?.state||'pending',version:byId.get(c.id)?.version||0,updatedAt:byId.get(c.id)?.updated_at,expiresAt:byId.get(c.id)?.expires_at}));
 }
 expireConsents(persona){
  // A read should reflect expired decisions and record a durable transition.
  const now=new Date().toISOString();
  for(const row of this.db.prepare("SELECT consent_id FROM decisions WHERE persona=? AND state='granted' AND expires_at IS NOT NULL AND expires_at <= ?").all(persona,now))this.transition(persona,row.consent_id,'expired');
 }
 transition(persona,id,to){
  this.seed(persona);
  const consent=DEMO_CONSENTS.find(v=>v.id===id);
  if(!consent)throw Object.assign(new Error('UNKNOWN_CONSENT'),{status:404});
  if(persona==='customer-rafael'&&(consent.origin!=='aurora'||consent.target!=='aurora'))throw Object.assign(new Error('PERSONA_BRAND_NOT_ASSOCIATED'),{status:403});
  return this.tx(()=>{
   const prior=this.db.prepare('SELECT * FROM decisions WHERE persona=? AND consent_id=?').get(persona,id);
   assertTransition(prior.state,to);
   const version=prior.version+1, now=new Date().toISOString();
   const expires=to==='granted'?new Date(Date.now()+7*24*60*60*1000).toISOString():null;
   const result=this.db.prepare('UPDATE decisions SET state=?,version=?,updated_at=?,expires_at=? WHERE persona=? AND consent_id=? AND version=?').run(to,version,now,expires,persona,id,prior.version);
   if(result.changes!==1)throw Object.assign(new Error('CONCURRENT_MODIFICATION'),{status:409});
   this.db.prepare('INSERT INTO consent_events (persona,consent_id,from_state,to_state,version,occurred_at) VALUES (?,?,?,?,?,?)').run(persona,id,prior.state,to,version,now);
   return {...DEMO_CONSENTS.find(v=>v.id===id),state:to,version,updatedAt:now,expiresAt:expires};
  });
 }
 listAttributes(persona){
  this.seed(persona);
  return this.db.prepare('SELECT * FROM attributes WHERE persona=? ORDER BY attribute ASC').all(persona).map(a=>({attribute:a.attribute,display:DEMO_ATTRIBUTES.find(v=>v.attribute===a.attribute)?.display,maskedValue:mask(a.value),source:a.source,level:(a.level==='verified'&&a.expires_at&&a.expires_at<=new Date().toISOString())?'expired':a.level,verifiedAt:a.verified_at,expiresAt:a.expires_at,version:a.version,updatedAt:a.updated_at}));
 }
 updateAttribute(persona,attribute,value){
  this.seed(persona);
  const cleaned=validateAttributeChange(attribute,value);
  return this.tx(()=>{
   const old=this.db.prepare('SELECT * FROM attributes WHERE persona=? AND attribute=?').get(persona,attribute);
   if(!old)throw Object.assign(new Error('UNKNOWN_ATTRIBUTE'),{status:404});
   const newVersion=old.version+1, now=new Date().toISOString();
   this.db.prepare('UPDATE attributes SET value=?,source=?,level=?,verified_at=NULL,expires_at=NULL,version=?,updated_at=? WHERE persona=? AND attribute=?').run(cleaned,'self-declared','self_asserted',newVersion,now,persona,attribute);
   this.db.prepare('INSERT INTO attribute_events (persona,attribute,old_level,new_level,source,version,occurred_at) VALUES (?,?,?,?,?,?,?)').run(persona,attribute,old.level,'self_asserted','self-declared',newVersion,now);
   return {attribute,maskedValue:mask(cleaned),level:'self_asserted',source:'self-declared',version:newVersion,updatedAt:now};
  });
 }
 events(persona){
  this.seed(persona);
  const consent=this.db.prepare('SELECT id, consent_id as subject,from_state as previous,to_state as current,version,occurred_at as time FROM consent_events WHERE persona=? ORDER BY id DESC LIMIT 40').all(persona).map(v=>({...v,kind:'consent'}));
  const attr=this.db.prepare('SELECT id,attribute as subject,old_level as previous,new_level as current,version,occurred_at as time FROM attribute_events WHERE persona=? ORDER BY id DESC LIMIT 40').all(persona).map(v=>({...v,kind:'attribute'}));
  return [...consent,...attr].sort((a,b)=>b.time.localeCompare(a.time)).slice(0,50);
 }
 close(){this.db.close()}
}
