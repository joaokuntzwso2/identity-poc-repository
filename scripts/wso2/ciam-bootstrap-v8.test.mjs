import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,existsSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {apply,labOrigin,newPassword,privateRead,userPayload,parseScimList} from './ciam-bootstrap-v8.mjs';
const domain={aurora:'aurora.identity.test',brisa:'brisa.identity.test'};
const base='https://localhost:9443';
const env={WSO2_BASE_URL:base+'/',WSO2_LAB_CONFIRM:'CREATE_SYNTHETIC_RESOURCES',WSO2_CIAM_V8_CONFIRM:'ROTATE_LAB_OWNERS_AND_PROVISION_USERS',WSO2_ADMIN_USER:'admin',WSO2_ADMIN_PASSWORD:'secret',NODE_EXTRA_CA_CERTS:'/dev/null'};
function fixture(){
 const dir=mkdtempSync(join(tmpdir(),'ciam-v8-test-'));
 const paths={root:join(dir,'tenant-brand.private.json'),management:join(dir,'tenant-management.private.json'),state:join(dir,'ciam-bootstrap-v8.private.json'),lock:join(dir,'ciam-bootstrap-v8.lock')};
 const root={tenants:{},clients:{}};const mgmt={management:{}};
 for(const b of ['aurora','brisa']){
   root.tenants[b]={state:'created',owned:true,domain:domain[b],tenantId:'tenant-'+b,ownerId:'owner-'+b,owner:{username:'labtenantadmin',email:'lab-admin@example.invalid',firstname:'Identity',lastname:'Lab'}};
   mgmt.management[b]={state:'verified',domain:domain[b],id:'manager-'+b,clientId:'client-'+b,clientSecret:'secret-'+b};
   for(const c of ['WEB','MOBILE'])root.clients[b.toUpperCase()+'_'+c]={state:'verified',tenant:domain[b],id:b+'-app-'+c,clientId:b+'client'+c,clientSecret:'not-shared'};
 }
 writeFileSync(paths.root,JSON.stringify(root),{mode:0o600});writeFileSync(paths.management,JSON.stringify(mgmt),{mode:0o600});
 return {paths,root,mgmt};
}
function mock(){
 const calls=[],authz={aurora:[],brisa:[]},users={aurora:null,brisa:null};
 function fail(status=400){return new Response(JSON.stringify({error:'test'}),{status,headers:{'content-type':'application/json'}})}
 const fetchImpl=async (url,init)=>{
   const u=new URL(url),parts=u.pathname.split('/').filter(Boolean),method=init.method;
   calls.push({method,path:u.pathname});
   const respond=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json'}});
   if(parts[0]==='api'&&parts[3]==='tenants'&&parts[5]==='owners'){
      const b=parts[4].replace('tenant-','');
      const item={id:'owner-'+b,username:'labtenantadmin',firstname:'Identity',lastname:'Lab',email:'lab-admin@example.invalid'};
      if(method==='PUT')return respond({},200);
      if(method==='GET')return respond(item);
   }
   if(parts[0]!=='t')return fail(404);
   const b=parts[1].replace('.identity.test','');
   if(!['brisa','aurora'].includes(b))return fail(404);
   const rest=parts.slice(2).join('/');
   if(rest==='api/server/v1/applications'&&method==='GET')return respond({applications:[]});
   if(rest==='api/server/v1/api-resources'&&method==='GET')return respond({APIResources:[{identifier:'/scim2/Users',id:'scim-resource-'+b}]});
   if(rest===`api/server/v1/applications/manager-${b}/authorized-apis`){
      if(method==='GET')return respond(authz[b].length?[{id:'scim-resource-'+b,authorizedScopes:authz[b].map(name=>({name}))}]:[]);
      if(method==='POST'){authz[b]=JSON.parse(init.body).scopes;return respond({},201)}
   }
   if(rest==='oauth2/token'&&method==='POST')return respond({access_token:'fake-bearer',token_type:'Bearer',scope:'internal_application_mgt_view internal_user_mgt_list internal_user_mgt_view internal_user_mgt_create'});
   if(rest.startsWith('api/server/v1/applications/')&&method==='GET')return respond({id:parts[6],applicationEnabled:true,authenticationSequence:{type:'DEFAULT'}});
   if(rest==='scim2/Users'&&method==='GET')return respond({totalResults:users[b]?1:0,Resources:users[b]?[users[b]]:[]});
   if(rest==='scim2/Users'&&method==='POST'){
     const v=JSON.parse(init.body);users[b]={id:'user-'+b,externalId:v.externalId,userName:v.userName,active:true};return respond(users[b],201);
   }
   if(rest==='scim2/Users/user-'+b&&method==='GET')return respond(users[b]);
   return fail(404);
 };
 return {fetchImpl,calls,users};
}
test('origin pinned; no accidental remote deployment',()=>{
 assert.equal(labOrigin(env),base);
 assert.throws(()=>labOrigin({...env,WSO2_BASE_URL:'https://example.com:9443/'}),/LOCAL_HTTPS/);
 assert.throws(()=>labOrigin({...env,WSO2_AURORA_ROOT_TENANT:'not-aurora.example'}),/DOMAIN_CHANGE/);
});
test('secrets generated and user payload follows SCIM',()=>{
 const a=newPassword(),b=newPassword();assert.notEqual(a,b);assert.ok(a.length>=36);
 const v=userPayload('brisa',a,'ciamv8_123456789abcdef012345');assert.equal(v.userName,'ciam_brisa');assert.equal(v.password,a);
 assert.ok(v.schemas[0].includes('core:2.0:User'));
});
test('SCIM user collisions and truncation fail closed',()=>{
 assert.equal(parseScimList({Resources:[],totalResults:0},'ciam_brisa'),null);
 assert.throws(()=>parseScimList({Resources:[],totalResults:10},'ciam_brisa'),/PAGINATION/);
 assert.throws(()=>parseScimList({Resources:[{userName:'ciam_brisa'},{userName:'PRIMARY\/ciam_brisa'}],totalResults:2},'ciam_brisa'),/DUPLICATE/);
});
test('end-to-end simulated existing: 2 owner updates, 2 SCIM grants, 2 customer users, 4 app reads; rerun no write',async()=>{
 const {paths}=fixture(),service=mock();
 const res=await apply('existing',{env,fetchImpl:service.fetchImpl,paths});
 assert.equal(res.oidcClients,'4_VERIFIED');assert.equal(res.users.aurora.browserAuthentication,'NOT_VERIFIED');
 assert.equal(service.calls.filter(x=>x.method==='PUT').length,2);
 assert.equal(service.calls.filter(x=>x.method==='POST'&&x.path.endsWith('/authorized-apis')).length,2);
 assert.equal(service.calls.filter(x=>x.method==='POST'&&x.path.endsWith('/scim2/Users')).length,2);
 assert.equal(service.calls.filter(x=>x.method==='GET'&&x.path.includes('-app-')).length,4);
 const local=privateRead(paths.state);
 assert.equal(local.tenants.aurora.owner.state,'tenant-api-authenticated');
 assert.equal(local.tenants.brisa.user.state,'verified-password-not-browser-tested');
 assert.equal(statSync(paths.state).mode&0o777,0o600);
 assert.ok(!existsSync(paths.lock));
 const writes=service.calls.filter(x=>['PUT','PATCH','POST'].includes(x.method)).length;
 await apply('existing',{env,fetchImpl:service.fetchImpl,paths});
 assert.equal(service.calls.filter(x=>['PUT','PATCH','POST'].includes(x.method)).length-writes,2); // token requests only
});
test('missing explicit confirmation refuses every remote call',async()=>{
 const {paths}=fixture(),service=mock();
 await assert.rejects(apply('existing',{env:{...env,WSO2_CIAM_V8_CONFIRM:''},fetchImpl:service.fetchImpl,paths}),/APPROVAL/);
 assert.equal(service.calls.length,0);
});
test('fresh refuses existing journals before writes',async()=>{
 const {paths}=fixture(),service=mock();
 await assert.rejects(apply('fresh',{env,fetchImpl:service.fetchImpl,paths,bootstrapFresh:async()=>{throw Error('SHOULD_NOT_BE_CALLED')}}),/FRESH_MODE_REQUIRES/);
 assert.equal(service.calls.length,0);
 assert.ok(!existsSync(paths.lock));
});
test('ambiguous previous owner update cannot blindly repeat write',async()=>{
 const {paths}=fixture(),service=mock();
 const s={schema:'identity.wso2.ciam.v8',base,tenants:{aurora:{owner:{state:'update-started',tenantId:'tenant-aurora',ownerId:'owner-aurora',password:newPassword()}}},acceptance:'NOT_VERIFIED'};
 writeFileSync(paths.state,JSON.stringify(s),{mode:0o600});
 await apply('existing',{env,fetchImpl:service.fetchImpl,paths});
 assert.equal(service.calls.filter(x=>x.method==='PUT'&&x.path.includes('tenant-aurora')).length,0);
 assert.equal(privateRead(paths.state).tenants.aurora.owner.state,'tenant-api-authenticated');
});
