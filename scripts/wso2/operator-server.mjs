/** Optional local-only operator command; never put an operator key in a public bundle. */
import http from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import {spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {readFileSync,existsSync} from 'node:fs';
import {root} from './domain.mjs';
const PORT=4391,HOST='127.0.0.1';
const key=process.env.DEMO_RESET_OPERATOR_KEY||'';
let busy=false,failures=0;
const allowed=new Set(['http://127.0.0.1:5173','http://localhost:5173','http://127.0.0.1:4317']);
function reply(res,code,data){res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data))}
function equal(given){if(key.length<48||typeof given!=='string'||given.length<48)return false;const a=Buffer.from(given),b=Buffer.from(key);return a.length===b.length&&timingSafeEqual(a,b)}
export function createOperatorServer({run=execReset}={}){
 return http.createServer(async(req,res)=>{
  const origin=req.headers.origin;if(origin&&!allowed.has(origin)){reply(res,403,{error:'ORIGIN_DENIED'});return}
  if(origin){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Headers','Content-Type,X-Demo-Operator-Key');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS')}
  if(req.method==='OPTIONS'){res.writeHead(204);res.end();return}
  if(req.url==='/api/operator/status'&&req.method==='GET'){reply(res,200,{enabled:true,mode:'LOCAL_OPERATOR_ONLY',running:busy,acceptance:'NOT_VERIFIED'});return}
  if(req.url!=='/api/operator/reset'||req.method!=='POST'){reply(res,404,{error:'NOT_FOUND'});return}
  if(!origin||!allowed.has(origin)||failures>=10||!equal(req.headers['x-demo-operator-key'])){failures++;reply(res,403,{error:'OPERATOR_AUTH_REQUIRED'});return}
  if(busy){reply(res,409,{error:'RESET_IN_PROGRESS'});return}
  let body='';try{for await(const chunk of req){body+=chunk;if(body.length>256)throw Error('OVERSIZED')}
   const payload=JSON.parse(body);
   if(payload.confirm!=='RESET DEMO'||payload.scope!=='lab-owned-demo')throw Error('INVALID_CONFIRMATION');
  }catch{reply(res,400,{error:'CONFIRMATION_REQUIRED'});return}
  busy=true;try{const result=await run();reply(res,result.ok?200:502,{status:result.ok?'RESET_COMMAND_COMPLETED':'RESET_COMMAND_FAILED',
   note:'Wso2-owned resources cleared and preview DB rotated to private immutable archive only if both operations completed. Verify local inventory.',acceptance:'NOT_VERIFIED'});
  }catch{reply(res,502,{error:'RESET_EXECUTION_FAILED'})}finally{busy=false}
 });
}
async function execReset(){
 const inventory=resolve(root,'var/wso2/inventory.private.json');
 let hasWso2=false;try{if(existsSync(inventory))hasWso2=JSON.parse(readFileSync(inventory,'utf8')).resources?.length>0}catch{return {ok:false}}
 if(hasWso2){const remote=await runWso2Reset();if(!remote.ok)return remote;}
 try{const r=await fetch('http://127.0.0.1:4317/api/experience/maintenance/reset',{method:'POST',headers:{'X-Internal-Operator':'local-reset-v1','X-Demo-Operator-Key':key},redirect:'error',signal:AbortSignal.timeout(10000)});
 return {ok:r.ok};
 }catch{return {ok:false}}
}
function runWso2Reset(){return new Promise(resolvePromise=>{
 const child=spawn(process.execPath,[resolve(root,'scripts/wso2/cli.mjs'),'reset'],{cwd:root,env:{...process.env,WSO2_LAB_CONFIRM:'DELETE_LAB_OWNED_RESOURCES'},stdio:'ignore'});
 child.on('error',()=>resolvePromise({ok:false}));child.on('close',code=>resolvePromise({ok:code===0}));
 });}
if(process.argv[1]&&resolve(process.argv[1])===import.meta.filename){
 if(process.env.DEMO_RESET_OPERATOR_ENABLE!=='YES_LOCAL_ONLY'||key.length<48)throw Error('OPERATOR_SERVER_REQUIRES_LOCAL_OPT_IN_AND_LONG_SECRET');
 createOperatorServer().listen(PORT,HOST,()=>console.log(`Local-only reset operator at http://${HOST}:${PORT}`));
}
