import {OperationsStore} from './p1-store.mjs';
import {problem,validPlan} from './p1-domain.mjs';
import {existsSync,readFileSync,statSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
export function createOperationsRoutes(db){
 const lab=new OperationsStore(db);
 const releasePath=resolve(fileURLToPath(new URL('../../',import.meta.url)),'evidence/identity/release-gates.json');
 function privateGateSummary(){
  // Read only aggregate metadata, never leak private requirement rows or promote offline evidence.
  if(!existsSync(releasePath)||statSync(releasePath).size>1024*1024)return {available:false};
  try{const r=JSON.parse(readFileSync(releasePath,'utf8'));
   return {available:true,reportedOverall:String(r.overall||'UNKNOWN').slice(0,64),reportedVerified:Number.isInteger(r.verified)?r.verified:0,reportedOpenGates:Array.isArray(r.eliminatoryOpen)?r.eliminatoryOpen.length:null,generatedAt:r.generatedAt||null,independentlyReviewed:false};
  }catch{return {available:false,parseFailed:true}}
 }
 const routes={
 '/api/lab/meta':()=>lab.staticData(),
 '/api/lab/b2b':()=>lab.b2b(),
 '/api/lab/onboarding/plans':()=>({items:lab.plans(),mode:'synthetic-preview',provisioned:false}),
 '/api/lab/evidence':()=>({...lab.evidence(),privateGate:privateGateSummary()})
 };
 return async function route({req,res,path,send,body}){
  if(!path.startsWith('/api/lab/'))return false;
  // Fixture-only protected resource endpoints. These enforce server-side preview policies,
  // but NEVER claim that selecting a fixture authenticates the caller.
  const resourceMatch=path.match(/^\/api\/lab\/resources\/(catalog|orders|preferences|transfers)$/);
  if(resourceMatch){
   if(req.headers['x-experience-preview']!=='yes')throw problem('PREVIEW_INTENT_REQUIRED',403);
   const resourceMap={catalog:{GET:'catalog.read'},orders:{GET:'orders.read',POST:'orders.write'},preferences:{GET:'preferences.read'},transfers:{POST:'finance.transfer'}};
   const resourceId=resourceMap[resourceMatch[1]][req.method];
   if(!resourceId)throw problem('RESOURCE_METHOD_NOT_ALLOWED',405);
   let fixtureId,requestedScopes;
   if(req.method==='GET'){
    const u=new URL(req.url,'http://127.0.0.1');
    fixtureId=u.searchParams.get('fixtureId');requestedScopes=u.searchParams.getAll('scope');
   }else{
    if(req.headers['content-type']?.split(';')[0]!=='application/json')throw problem('JSON_REQUIRED',415);
    const input=await body(req);fixtureId=input.fixtureId;requestedScopes=input.requestedScopes;
   }
   const decision=lab.authorize({fixtureId,resourceId,requestedScopes});
   if(!decision.allowed){send(res,403,{error:'RESOURCE_DENIED',mode:'synthetic-preview',decision,identityVerified:false});return true}
   const payload={
    'catalog.read':{products:[{id:'item-01',label:'Produto de exemplo'},{id:'item-02',label:'Outro produto de exemplo'}]},
    'orders.read':{orders:[{id:'SYNTH-ORDER-01',status:'fictitious',owner:decision.fixture.subject}]},
    'orders.write':{orderId:'PREVIEW-NO-ORDER-CREATED',state:'approved_fixture_only'},
    'preferences.read':{preferences:{style:'minimalist',purpose:'preview_only'}},
    'finance.transfer':null
   }[resourceId];
   send(res,req.method==='POST'?201:200,{mode:'synthetic-preview',identityVerified:false,decision,payload,liveAcceptance:false});return true;
  }
  if(req.method==='GET'){
   if(!routes[path])throw problem('NOT_FOUND',404);
   send(res,200,routes[path]());return true;
  }
  if(req.method!=='POST')throw problem('METHOD_NOT_ALLOWED',405);
  if(req.headers['x-experience-preview']!=='yes')throw problem('PREVIEW_INTENT_REQUIRED',403);
  if(req.headers['content-type']?.split(';')[0]!=='application/json')throw problem('JSON_REQUIRED',415);
  const payload=await body(req);let item;
  switch(path){
   case '/api/lab/b2b/create-org':item=lab.createChild(payload);break;
   case '/api/lab/b2b/invite':item=lab.invite(payload);break;
   case '/api/lab/b2b/role':item=lab.role(payload);break;
   case '/api/lab/onboarding/validate':item=validPlan(payload,lab.plans());break;
   case '/api/lab/onboarding/plan':item=lab.plan(payload);break;
   case '/api/lab/authorization/evaluate':item=lab.authorize(payload);break;
   case '/api/lab/evidence/run-offline':item={items:lab.runSelfChecks(),acceptanceStatus:'NOT_VERIFIED'};break;
   default:throw problem('NOT_FOUND',404);
  }
  send(res,200,{mode:'synthetic-preview',identityVerified:false,liveAcceptance:false,item});return true;
 }
}
