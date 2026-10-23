import http from 'node:http';
import {authenticatedInternalReset,rotatePreviewDatabase} from '../../scripts/wso2/preview-reset.mjs';
import {readFileSync,existsSync,statSync} from 'node:fs';
import {resolve,join,extname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PreviewStore} from './store.mjs';
import {RetailStore} from './retail-store.mjs';
import {createOperationsRoutes} from './p1-routes.mjs';
import {createProviderHttpRoute} from '../identity-bff/src/provider/http-route.mjs';
import {getMode} from '../identity-bff/src/provider/core.mjs';
const base=resolve(fileURLToPath(new URL('../../',import.meta.url)));
const distDir=resolve(base,'apps/experience-center/dist');
const defaults=['http://127.0.0.1:5173','http://localhost:5173','http://127.0.0.1:4173','http://localhost:4173'];
const PORT=Number(process.env.EXPERIENCE_PORT||4317);
const HOST='127.0.0.1';
const contentTypes={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.json':'application/json; charset=utf-8','.png':'image/png','.ico':'image/x-icon'};
function send(res,status,data,extra={}){const json=JSON.stringify(data);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...extra});res.end(json)}
function fail(res,err){send(res,err?.status||500,{error:err?.status?err.message:'SERVER_ERROR',mode:'synthetic-preview'})}
async function body(req){let raw='';for await(const part of req){raw+=part;if(raw.length>4096)throw Object.assign(new Error('BODY_TOO_LARGE'),{status:413})}let obj;try{obj=JSON.parse(raw||'{}')}catch{throw Object.assign(new Error('INVALID_JSON'),{status:400})}if(!obj||typeof obj!=='object'||Array.isArray(obj))throw Object.assign(new Error('INVALID_JSON'),{status:400});return obj}
export function createPreviewServer({dbFile=resolve(base,'var/identity-preview.sqlite'),allowedOrigins=defaults,serveDist=true}={}){
 let store=new PreviewStore(dbFile);
 let retail=new RetailStore(store.db);
 let operationsRoute=createOperationsRoutes(store.db);
 const providerRoute=createProviderHttpRoute();
 const server=http.createServer(async(req,res)=>{
  res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');
  const origin=req.headers.origin;
  if(origin){if(!allowedOrigins.includes(origin)){send(res,403,{error:'ORIGIN_NOT_ALLOWED'});return}res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type,X-Experience-Preview')}
  if(req.method==='OPTIONS'){res.writeHead(204);res.end();return}
  const url=new URL(req.url||'/',`http://${HOST}:${PORT}`);const path=url.pathname;
  try{
   if(path==='/api/experience/maintenance/reset'){
    if(!authenticatedInternalReset(req,process.env.DEMO_RESET_OPERATOR_KEY)){send(res,403,{error:'OPERATOR_AUTH_REQUIRED'});return}
    const archived=rotatePreviewDatabase(dbFile,store);
    store=new PreviewStore(dbFile);retail=new RetailStore(store.db);operationsRoute=createOperationsRoutes(store.db);
    send(res,200,{status:'PREVIEW_RESET',evidence:'ARCHIVED_NOT_DELETED',archived:archived.archived,acceptance:'NOT_VERIFIED'});return;
   }
   if(await providerRoute({req,res,path,send}))return;
   if(await operationsRoute({req,res,path,send,body}))return;
   if(path==='/api/experience/meta'&&req.method==='GET'){send(res,200,{mode:'synthetic-preview',identityProvider:'not_configured',identityVerified:false,liveAcceptance:false,store:'local-sqlite',personas:'fictional'});return}
   if(path==='/api/experience/consents'&&req.method==='GET'){send(res,200,{mode:'synthetic-preview',items:store.listConsents(url.searchParams.get('persona')||'')});return}
   if(path==='/api/experience/assurance'&&req.method==='GET'){send(res,200,{mode:'synthetic-preview',items:store.listAttributes(url.searchParams.get('persona')||'')});return}
   if(path==='/api/experience/events'&&req.method==='GET'){send(res,200,{mode:'synthetic-preview',items:store.events(url.searchParams.get('persona')||'')});return}
   const change=path.match(/^\/api\/experience\/(consents|assurance)\/([a-z0-9_-]+)$/);
   if(change&&req.method==='POST'){
    if(req.headers['x-experience-preview']!=='yes')throw Object.assign(new Error('PREVIEW_INTENT_REQUIRED'),{status:403});
    if(req.headers['content-type']?.split(';')[0]!=='application/json')throw Object.assign(new Error('JSON_REQUIRED'),{status:415});
    const data=await body(req), persona=data.persona;
    if(change[1]==='consents')send(res,200,{mode:'synthetic-preview',item:store.transition(persona,change[2],data.action)});
    else send(res,200,{mode:'synthetic-preview',item:store.updateAttribute(persona,change[2],data.value)});
    return;
   }
   // Synthetic storefront API. Persona selection is not user authentication.
   const retailRoute=path.match(/^\/api\/retail\/(aurora|brisa)\/(bootstrap|profile|preferences|security|addresses|wishlist|checkout)$/);
   if(retailRoute){
    const [,brand,endpoint]=retailRoute;
    if(endpoint==='bootstrap'&&req.method==='GET'){send(res,200,retail.snapshot(url.searchParams.get('persona')||'',brand));return;}
    if(req.method!=='POST')throw Object.assign(new Error('METHOD_NOT_ALLOWED'),{status:405});
    if(req.headers['x-experience-preview']!=='yes')throw Object.assign(new Error('PREVIEW_INTENT_REQUIRED'),{status:403});
    if(req.headers['content-type']?.split(';')[0]!=='application/json')throw Object.assign(new Error('JSON_REQUIRED'),{status:415});
    const data=await body(req),persona=data.persona;
    let item;
    if(endpoint==='profile')item=retail.profile(persona,brand,data.changes||{});
    if(endpoint==='preferences')item=retail.preferences(persona,brand,data.changes||{});
    if(endpoint==='security')item=retail.security(persona,brand,data.action,data.id);
    if(endpoint==='addresses')item=retail.address(persona,brand,data.action,data.values||{});
    if(endpoint==='wishlist')item=retail.wishlist(persona,brand,data.productId);
    if(endpoint==='checkout')item=retail.order(persona,brand,data.action,data);
    send(res,200,{mode:'synthetic-preview',identityVerified:false,item});return;
   }
   if(path.startsWith('/api/')){send(res,404,{error:'NOT_FOUND'});return}
   if(!serveDist||req.method!=='GET'&&req.method!=='HEAD'){send(res,404,{error:'NOT_FOUND'});return}
   const requested=path==='/'?'index.html':decodeURIComponent(path.slice(1));
   const target=resolve(distDir,requested);
   if(!(target===distDir||target.startsWith(distDir+sep))){send(res,403,{error:'FORBIDDEN'});return}
   let actual=target;
   if(!existsSync(actual)||!statSync(actual).isFile()){
    if(extname(requested)){send(res,404,{error:'NOT_FOUND'});return}
    actual=join(distDir,'index.html');
   }
   if(!existsSync(actual)){send(res,404,{error:'FRONTEND_NOT_BUILT',hint:'Run ./experience.sh build'});return}
   const bytes=readFileSync(actual);res.writeHead(200,{'Content-Type':contentTypes[extname(actual)]||'application/octet-stream','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; connect-src 'self' http://127.0.0.1:4317; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"});res.end(req.method==='HEAD'?undefined:bytes);
  }catch(err){fail(res,err)}
 });
 server.on('close',()=>store.close());
 return server;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(getMode(process.env)!=='story-preview'){console.error('Synthetic Experience API is not a live BFF; use real BFF integration for live mode.');process.exit(2)}
 if(process.env.EXPERIENCE_PREVIEW_ACK!=='YES_LOCAL_SYNTHETIC_ONLY'){console.error('Set EXPERIENCE_PREVIEW_ACK=YES_LOCAL_SYNTHETIC_ONLY to run synthetic-only loopback preview.');process.exit(1)}
 const server=createPreviewServer();server.listen(PORT,HOST,()=>console.log(`Synthetic-only Identity Experience preview at http://${HOST}:${PORT} (no WSO2 auth)`));
}
