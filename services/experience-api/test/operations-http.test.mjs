import {test} from 'node:test';import assert from 'node:assert/strict';import {mkdtempSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {createPreviewServer} from '../server.mjs';
test('HTTP endpoints enforce preview intent, persist B2B/plan/authorization evidence and never verify live',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'identity-p1-http-'));
 const server=createPreviewServer({dbFile:join(dir,'preview.sqlite'),serveDist:false});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const url=`http://127.0.0.1:${server.address().port}`;
 const send=async(path,data,headers={})=>fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(data)});
 try{
  let res=await fetch(url+'/api/lab/meta');assert.equal(res.status,200);let json=await res.json();assert.equal(json.idpConfigured,false);
  res=await send('/api/lab/b2b/role',{actor:'seller-marcos',orgId:'horizonte',persona:'customer-ana',role:'viewer'});assert.equal(res.status,403);
  res=await send('/api/lab/b2b/role',{actor:'admin-luiza',orgId:'horizonte',persona:'customer-ana',role:'editor'},{'X-Experience-Preview':'yes'});assert.equal(res.status,403);
  res=await send('/api/lab/b2b/invite',{actor:'seller-marcos',orgId:'horizonte',email:'staff@organization.example',role:'viewer'},{'X-Experience-Preview':'yes'});assert.equal(res.status,200);json=await res.json();assert.equal(json.item.delivery,'none');
  res=await send('/api/lab/onboarding/plan',{code:'solis',name:'Solis Marketplace',sectorUri:'https://login.solis.example/sector.json',webRedirect:'https://shop.solis.example/callback',mobileRedirect:'https://mobile.solis.example/callback',stepUp:true,independentConsent:true},{'X-Experience-Preview':'yes'});assert.equal(res.status,200);json=await res.json();assert.equal(json.item.provisioned,false);
  res=await send('/api/lab/authorization/evaluate',{fixtureId:'agent-unapproved',resourceId:'orders.write',requestedScopes:['orders.write']},{'X-Experience-Preview':'yes'});assert.equal(res.status,200);json=await res.json();assert.equal(json.item.allowed,false);assert(json.item.reasons.includes('APPROVAL_REQUIRED'));assert.equal(json.item.acceptanceStatus,'NOT_VERIFIED');assert.equal(json.item.accessToken,null);
  // Real preview-resource HTTP endpoints: no bearer token and no accepted external identity.
  res=await fetch(url+'/api/lab/resources/catalog?fixtureId=client-credentials&scope=catalog.read',{headers:{'X-Experience-Preview':'yes'}});assert.equal(res.status,200);json=await res.json();assert(json.payload.products.length>0);
  res=await fetch(url+'/api/lab/resources/orders?fixtureId=client-credentials&scope=orders.read',{headers:{'X-Experience-Preview':'yes'}});assert.equal(res.status,403);json=await res.json();assert(json.decision.reasons.includes('HUMAN_SUBJECT_REQUIRED'));
  res=await fetch(url+'/api/lab/resources/orders?fixtureId=token-exchange&scope=orders.read',{headers:{'X-Experience-Preview':'yes'}});assert.equal(res.status,200);
  res=await send('/api/lab/resources/orders',{fixtureId:'agent-unapproved',requestedScopes:['orders.write']},{'X-Experience-Preview':'yes'});assert.equal(res.status,403);
  res=await send('/api/lab/resources/orders',{fixtureId:'agent-approved',requestedScopes:['orders.write']},{'X-Experience-Preview':'yes'});assert.equal(res.status,201);json=await res.json();assert.equal(json.payload.orderId,'PREVIEW-NO-ORDER-CREATED');
  res=await fetch(url+'/api/lab/evidence');json=await res.json();assert.equal(json.counts.liveVerified,0);assert(json.events.length>=4);assert(json.events.every(x=>x.acceptanceStatus==='NOT_VERIFIED'));
  res=await send('/api/lab/evidence/run-offline',{}, {'X-Experience-Preview':'yes'});assert.equal(res.status,200);json=await res.json();assert.equal(json.item.items.length,5);
  res=await fetch(url+'/api/lab/evidence');json=await res.json();assert(json.counts.total>=9);
 }finally{await new Promise(resolve=>server.close(resolve));rmSync(dir,{recursive:true,force:true})}
});
