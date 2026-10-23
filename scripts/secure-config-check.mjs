import {readFile, readdir} from 'node:fs/promises';
import {join} from 'node:path';
const root=process.cwd();const files=[];
async function scan(dir){for(const ent of await readdir(join(root,dir),{withFileTypes:true})){const path=join(dir,ent.name);if(['node_modules','dist','.git'].includes(ent.name))continue;if(ent.isDirectory())await scan(path);else if(/\.(js|mjs|ts|tsx|yaml|yml|json|md)$/.test(ent.name))files.push(path);}}
await scan('services');await scan('apps');await scan('config');
let found=[];for(const file of files){const body=await readFile(file,'utf8');if(/rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|__dangerouslyDisableAuthorization/i.test(body))found.push(file);}
if(found.length){console.error('Unsafe TLS/authorization bypass:',found);process.exit(1)}
console.log(`Security source scan passed for ${files.length} files (not a replacement for SAST).`);
