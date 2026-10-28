/** P0.10 single-process ledger integration; existing JSONL schema remains intact. */
import { readFileSync, openSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import { resolve, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const locks = new Set();
export class CasePolicyError extends Error {
  constructor(code,status){super(code);this.code=code;this.status=status;}
}
function ensure(yes,code,status){if(!yes)throw new CasePolicyError(code,status);}
const actor=(iss,sub)=>createHash('sha256').update(JSON.stringify([iss,sub])).digest('hex');
function file(brand){
 ensure(brand==='aurora'||brand==='brisa','invalid_brand',400);
 const root=process.env.CIAM_BUSINESS_DATA_DIR;
 ensure(root&&isAbsolute(root),'business_storage_not_configured',503);
 return resolve(root,`requests-${brand}.jsonl`);
}
function recordFor(brand,id){
 let text;
 try{text=readFileSync(file(brand),'utf8');}
 catch(e){if(e.code==='ENOENT')return null;throw e;}
 ensure(Buffer.byteLength(text)<=10*1024*1024,'business_storage_limit',503);
 let found;
 for(const line of text.split('\n').filter(Boolean)){
   const e=JSON.parse(line);
   ensure(e.brand===brand&&['created','approved'].includes(e.action),'business_record_corrupt',503);
   if(e.id!==id)continue;
   if(e.action==='created'){
     ensure(!found,'business_record_corrupt',503);
     found={owner:e.actor,status:'OPEN'};
   }else{
     ensure(found&&found.status==='OPEN','business_record_corrupt',503);
     found.status='APPROVED';
   }
 }
 return found||null;
}
export function precheckApproval({brand,caseId,issuer,subject}){
 ensure(UUID.test(caseId),'invalid_case_id',400);
 ensure(typeof issuer==='string'&&issuer.length>0&&typeof subject==='string'&&subject.length>0,'identity_not_verified',401);
 const row=recordFor(brand,caseId);
 ensure(row,'case_not_found',404);
 ensure(row.owner!==actor(issuer,subject),'self_approval_denied',403);
 ensure(row.status==='OPEN','case_not_open',409);
 return true;
}
/** Only call after signed OIDC assurance AND fresh WSO2 introspection scope check. */
export function commitApprovedCase({brand,caseId,issuer,subject,authTime}){
 ensure(Number.isSafeInteger(authTime),'assurance_time_invalid',403);
 const lock=brand+':'+caseId;
 ensure(!locks.has(lock),'case_approval_busy',409);
 locks.add(lock);
 try{
   precheckApproval({brand,caseId,issuer,subject});
   const event={brand,id:caseId,action:'approved',actor:actor(issuer,subject),
     at:new Date().toISOString(),assurance:'WSO2_SIGNED_TOTP_STEP_UP',authTime};
   const fd=openSync(file(brand),'a',0o600);
   try{writeSync(fd,JSON.stringify(event)+'\n');fsyncSync(fd);}
   finally{closeSync(fd);}
   return {id:caseId,status:'APPROVED',persistent:true};
 }finally{locks.delete(lock);}
}
