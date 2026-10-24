/** OIDC Core §8.1: the SECTOR is the HOST of sector_identifier_uri.
 * Different brand paths on one host are NOT separate sectors. */
import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {root} from './domain.mjs';
const BRANDS=['aurora','brisa'];
export function documents(plan){
 const out={};for(const app of plan.apps.filter(x=>x.brand!=='workload'))(out[app.brand]??=[]).push(app.callback);
 return Object.fromEntries(Object.entries(out).map(([key,urls])=>[key,urls.sort()]));
}
export function writeSectorDocuments(plan){
 const dir=resolve(root,'apps/experience-center/public/sectors');mkdirSync(dir,{recursive:true});
 const docs=documents(plan);for(const [brand,callbacks] of Object.entries(docs))writeFileSync(resolve(dir,`${brand}.json`),JSON.stringify(callbacks,null,2)+'\n');return docs;
}
export function sectorUris(env=process.env){
 const urls={};
 for(const brand of BRANDS){
  const key=`DEMO_${brand.toUpperCase()}_SECTOR_BASE_URL`;
  if(!env[key])throw Error(`${key}_REQUIRED_TWO_DISTINCT_HTTPS_HOSTS`);
  let base;try{base=new URL(env[key])}catch{throw Error(`${key}_INVALID_URL`)}
  if(base.protocol!=='https:'||base.username||base.password||base.hash||base.search||base.pathname!=='/')throw Error(`${key}_INVALID_HTTPS_BASE`);
  if(!base.hostname||base.hostname==='localhost'||base.hostname==='127.0.0.1')throw Error(`${key}_PUBLICLY_REACHABLE_HOST_REQUIRED`);
  urls[brand]=new URL(`/sector.json`,base).href;
 }
 if(new URL(urls.aurora).hostname.toLowerCase()===new URL(urls.brisa).hostname.toLowerCase())throw Error('SECTOR_HOSTS_MUST_DIFFER_NOT_ONLY_PATHS');
 return urls;
}
export async function assertSectorDocuments(plan,env=process.env,fetchImpl=fetch){
 const docs=documents(plan);const urls=sectorUris(env);
 for(const [brand,want] of Object.entries(docs)){
  const r=await fetchImpl(urls[brand],{redirect:'error',signal:AbortSignal.timeout(7000)});
  if(!r.ok)throw Error(`SECTOR_DOCUMENT_HTTP_${brand}_${r.status}`);
  const text=await r.text();if(text.length>8192)throw Error('SECTOR_DOCUMENT_TOO_LARGE');
  let list;try{list=JSON.parse(text)}catch{throw Error('SECTOR_DOCUMENT_NOT_JSON')}
  if(!Array.isArray(list)||JSON.stringify([...list].sort())!==JSON.stringify(want))throw Error(`SECTOR_REDIRECT_MISMATCH_${brand}`);
 }
 return true;
}
