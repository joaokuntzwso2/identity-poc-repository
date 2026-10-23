/** Disposable localhost-only sector JSON origins, exported through TWO distinct
 * HTTPS Quick Tunnels for a throwaway local lab. Never expose the BFF or WSO2.
 * AWS/long-lived identities require stable, separately named HTTPS hosts.
 */
import {createServer} from 'node:http';
import {spawn,spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {readFileSync,writeFileSync,existsSync,mkdirSync,chmodSync,renameSync,unlinkSync} from 'node:fs';
import {root,config,deploymentPlan} from './domain.mjs';
import {documents,sectorUris,assertSectorDocuments} from './sector.mjs';
import {execute} from './cli.mjs';

const RESERVED_TUNNEL_HOSTS=new Set(['api','www']);
export function extractTunnelHost(output){
 // IMPORTANT: cloudflared may print https://api.trycloudflare.com/tunnel
 // BEFORE it prints the actual random public hostname. That is NOT a tunnel.
 for(const match of String(output).matchAll(/https:\/\/([a-z0-9-]+)\.trycloudflare\.com(?=\b|\/)/gi)){
  const label=match[1].toLowerCase();
  if(!RESERVED_TUNNEL_HOSTS.has(label))return `https://${label}.trycloudflare.com`;
 }
 return null;
}
export function describeNetworkError(error){
 const parts=[];let e=error;
 for(let i=0;e&&i<4;i++,e=e.cause){
  if(e.code)parts.push(String(e.code));
  if(e.message)parts.push(String(e.message).replace(/\s+/g,' ').slice(0,180));
 }
 return [...new Set(parts)].join(' | ') || 'unknown network failure';
}
export function makeSectorHandler(brand,callbackUris){
 const route=`/sectors/${brand}.json`,data=JSON.stringify(callbackUris,null,2)+'\n';
 return (req,res)=>{
  if((req.method==='GET'||req.method==='HEAD')&&req.url===route){
   res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Length':Buffer.byteLength(data)});
   res.end(req.method==='HEAD'?undefined:data);
  }else{res.writeHead(404,{'Content-Type':'text/plain','Cache-Control':'no-store'});res.end('Not Found');}
 };
}
function serverListen(server){return new Promise((ok,fail)=>{server.once('error',fail);server.listen(0,'127.0.0.1',()=>ok(server.address().port));});}
async function verifyLocalOrigin(port,brand,expected){
 const response=await fetch(`http://127.0.0.1:${port}/sectors/${brand}.json`,{redirect:'error',signal:AbortSignal.timeout(3000)});
 if(!response.ok||JSON.stringify((await response.json()).sort())!==JSON.stringify([...expected].sort()))throw Error(`LOCAL_SECTOR_ORIGIN_INVALID_${brand}`);
}
function startTunnel(port,brand){
 return new Promise((ok,fail)=>{
  const args=['tunnel','--url',`http://127.0.0.1:${port}`];
  // Useful when UDP/QUIC is blocked on a corporate network; no TLS downgrade.
  if(process.env.WSO2_LAB_TUNNEL_PROTOCOL==='http2')args.push('--protocol','http2');
  const child=spawn('cloudflared',args,{stdio:['ignore','pipe','pipe'],env:process.env});
  let finished=false,log='';
  const timer=setTimeout(()=>finish(new Error(`TUNNEL_URL_TIMEOUT_${brand}: ${filteredLog()}`)),90000);
  const filteredLog=()=>log.split('\n').filter(x=>/ERR|WARN|error|fail|connected|registered|trycloudflare/i.test(x)).slice(-6).join(' | ').slice(-1400);
  function finish(error,url){
   if(finished)return;finished=true;clearTimeout(timer);
   if(error){child.kill('SIGTERM');fail(error);}else ok({child,url,diagnostics:filteredLog});
  }
  for(const stream of [child.stdout,child.stderr])stream.on('data',data=>{
   log=(log+data.toString()).slice(-20000);
   const url=extractTunnelHost(log);
   if(url)finish(null,url);
  });
  child.once('error',error=>finish(new Error(`CLOUDFLARED_UNAVAILABLE_${brand}_${error.code||error.message}`)));
  child.once('exit',code=>finish(new Error(`TUNNEL_EXIT_${brand}_${code}: ${filteredLog()}`)));
 });
}
export async function waitForSectorPublication(plan,env,{
 checker=assertSectorDocuments,
 attempts=12,
 sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),
 onRetry=()=>{},
 tunnels=[]
}={}){
 let last;
 for(let attempt=1;attempt<=attempts;attempt++){
  for(const tunnel of tunnels){
   if(tunnel.child.exitCode!==null||tunnel.child.signalCode!==null)
    throw Error(`TUNNEL_EXITED_${tunnel.brand}: ${tunnel.diagnostics()}`);
  }
  try{await checker(plan,env);return true}
  catch(error){
   last=error;
   onRetry(attempt,attempts,describeNetworkError(error));
   if(attempt<attempts)await sleep(3000);
  }
 }
 throw Error(`SECTOR_PUBLICATION_NOT_READY: ${describeNetworkError(last)}`);
}
export async function main(mode=process.argv[2]||'serve'){
 if(!['serve','bootstrap'].includes(mode))throw Error('SECTOR_MODE_MUST_BE_serve_OR_bootstrap');
 if(mode==='bootstrap'&&process.env.WSO2_LAB_CONFIRM!=='CREATE_SYNTHETIC_RESOURCES')throw Error('EXPLICIT_APPLY_ACK_REQUIRED');
 const check=spawnSync('cloudflared',['--version'],{encoding:'utf8'});
 if(check.error||check.status!==0)throw Error('CLOUDFLARED_REQUIRED_install_with_brew_install_cloudflared');
 const plan=deploymentPlan(config(),process.env),docs=documents(plan);
 const file=resolve(root,'var/wso2/local-sector-tunnels.env');
 const servers=[],tunnels=[];
 let written=null,closed=false;
 const cleanup=()=>{
  if(closed)return;closed=true;
  for(const t of tunnels)t.child.kill('SIGTERM');
  for(const s of servers)s.close();
  if(written&&existsSync(file)&&readFileSync(file,'utf8')===written)unlinkSync(file);
 };
 for(const sig of ['SIGINT','SIGTERM'])process.on(sig,()=>{cleanup();process.exit(0)});
 try{
  const urls={};
  for(const brand of ['aurora','brisa']){
   const server=createServer(makeSectorHandler(brand,docs[brand]));servers.push(server);
   const port=await serverListen(server);
   await verifyLocalOrigin(port,brand,docs[brand]);
   const tunnel=await startTunnel(port,brand);
   tunnel.brand=brand;
   tunnels.push(tunnel);urls[brand]=tunnel.url;
   console.log(`${brand.toUpperCase()}_TUNNEL_DISCOVERED: ${tunnel.url}/sectors/${brand}.json`);
  }
  const env={...process.env,DEMO_AURORA_SECTOR_BASE_URL:urls.aurora,DEMO_BRISA_SECTOR_BASE_URL:urls.brisa};
  sectorUris(env); // security: two different HTTPS sector HOSTNAMES are required.
  await waitForSectorPublication(plan,env,{
   tunnels,
   onRetry:(attempt,max,reason)=>console.error(`SECTOR_HTTPS_WAIT ${attempt}/${max}: ${reason}`)
  });
  const content=`# Private, temporary. Created by local-sector-tunnels.mjs; do not commit.\nDEMO_AURORA_SECTOR_BASE_URL=${urls.aurora}\nDEMO_BRISA_SECTOR_BASE_URL=${urls.brisa}\n`;
  mkdirSync(resolve(root,'var/wso2'),{recursive:true,mode:0o700});
  const temp=`${file}.${process.pid}.tmp`;
  writeFileSync(temp,content,{flag:'wx',mode:0o600});chmodSync(temp,0o600);renameSync(temp,file);written=content;
  console.log('SECTOR_HTTPS_READY: Two isolated, temporary HTTPS hostnames');
  console.log('AURORA_SECTOR_URI:',`${urls.aurora}/sectors/aurora.json`);
  console.log('BRISA_SECTOR_URI:',`${urls.brisa}/sectors/brisa.json`);
  console.log('WARNING: Quick Tunnel hosts change on restart; NOT for persistent pairwise identifiers or AWS.');
  console.log('Keep this terminal running. Stop with Ctrl+C only after testing.');
  if(mode==='bootstrap'){
   try{await execute('apply',{env});console.log('BOOTSTRAP_RETURNED — verify actual WSO2 login and subject claims separately.');}
   catch(e){console.error('LAB_ERROR:',e instanceof Error?e.message:'UNKNOWN_ERROR');console.error('Tunnels remain up for retries in another terminal. Preserve private inventory.');}
  }else console.log('In a second terminal: WSO2_LAB_CONFIRM=CREATE_SYNTHETIC_RESOURCES ./wso2-lab.sh apply');
  // Two child tunnels remain alive until interrupted by operator.
 }catch(e){
  // These are public static JSON URLs only. Showing them is safe and useful for diagnostics.
  for(const t of tunnels)console.error(`CLOUDFLARED_${t.brand.toUpperCase()}_LOG:`,t.diagnostics());
  console.error('SECTOR_TROUBLESHOOT: The tunnel URL alone does not prove DNS/TLS/edge connectivity.');
  console.error('SECTOR_TROUBLESHOOT: Check VPN/firewall/DNS and try WSO2_LAB_TUNNEL_PROTOCOL=http2 if QUIC is blocked.');
  console.error('SECTOR_TROUBLESHOOT: Quick Tunnel hosts are disposable; do not reuse them after restarting.');
  cleanup();throw e;
 }
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(import.meta.filename||'')){
 main().catch(e=>{console.error('LAB_ERROR:',e.message);process.exitCode=1});
}
