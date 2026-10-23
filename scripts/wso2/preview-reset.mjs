/** Reset synthetic preview state in-process while retaining append-only history by archive rotation. */
import {existsSync,mkdirSync,renameSync} from 'node:fs';
import {dirname,resolve,basename} from 'node:path';
import {randomUUID,timingSafeEqual} from 'node:crypto';
export function authenticatedInternalReset(req,key){
 if(req.method!=='POST'||req.headers.origin||req.headers['x-internal-operator']!=='local-reset-v1')return false;
 const ip=req.socket?.remoteAddress||'';
 if(!['127.0.0.1','::1','::ffff:127.0.0.1'].includes(ip))return false;
 const given=req.headers['x-demo-operator-key'];
 if(typeof key!=='string'||key.length<48||typeof given!=='string'||given.length<48)return false;
 const a=Buffer.from(given),b=Buffer.from(key);return a.length===b.length&&timingSafeEqual(a,b);
}
export function rotatePreviewDatabase(dbFile,store,{archiveRoot}={}){
 if(!store||!store.db||typeof store.close!=='function')throw Error('NO_PREVIEW_STORE');
 if(dbFile===':memory:'){store.close();return {archived:false};}
 const target=resolve(dbFile);if(!archiveRoot)archiveRoot=resolve(dirname(target),'wso2/preview-archive');
 const dest=resolve(archiveRoot,`${new Date().toISOString().replace(/[:.]/g,'-')}-${randomUUID()}`);
 // SQLite close() must checkpoint/disconnect WAL before moving DB and sidecars.
 store.close();mkdirSync(dest,{recursive:true,mode:0o700});
 for(const suffix of ['', '-wal','-shm']){const p=target+suffix;if(existsSync(p))renameSync(p,resolve(dest,basename(p)))}
 return {archived:true,archiveDir:dest};
}
