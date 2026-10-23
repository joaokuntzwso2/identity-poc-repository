import test from 'node:test';
import assert from 'node:assert/strict';
import {authorizeOrgManagement,authorizedScopeNames,REQUIRED_ORG_SCOPES} from './management-token.mjs';
import {authorizeOrgLevel,ORG_LEVEL_SCOPES} from './org-context.mjs';

function fake(api,scopes,granted=scopes){
 const resource={id:'resource-012345',identifier:api,scopes:scopes.map(name=>({name}))};
 const calls=[];
 return {
  api:{
   listApiResources:async()=>({data:{apiResources:[resource]}}),
   getAuthorizedApis:async()=>({data:[{id:resource.id,identifier:api,authorizedScopes:granted.map(name=>({name}))}]}),
   authorizeApi:async(...params)=>{calls.push(params);throw Error('UNEXPECTED_WRITE');}
  },calls
 };
}

test('WSO2 documented GET authorizedScopes objects satisfy existing root API grant without writes',async()=>{
 const f=fake('/api/server/v1/organizations',REQUIRED_ORG_SCOPES);
 assert.equal(await authorizeOrgManagement(f.api,'owned-app'),'ALREADY_AUTHORIZED');
 assert.deepEqual(f.calls,[]);
});
test('WSO2 documented GET authorizedScopes objects satisfy existing organization-scoped grant without writes',async()=>{
 const f=fake('/o/api/server/v1/organizations',ORG_LEVEL_SCOPES);
 assert.equal(await authorizeOrgLevel(f.api,'scoped-app'),'VERIFIED');
 assert.deepEqual(f.calls,[]);
});
test('legacy string scopes still accepted when WSO2 returns that shape',()=>{
 assert.deepEqual([...authorizedScopeNames({scopes:REQUIRED_ORG_SCOPES})],REQUIRED_ORG_SCOPES);
});
test('missing root permission fails closed with no writes',async()=>{
 const f=fake('/api/server/v1/organizations',REQUIRED_ORG_SCOPES,REQUIRED_ORG_SCOPES.slice(0,2));
 await assert.rejects(authorizeOrgManagement(f.api,'owned-app'),/ORG_API_PARTIALLY_AUTHORIZED_MANUAL_REVIEW/);
 assert.deepEqual(f.calls,[]);
});
test('missing organization permission fails closed with no writes',async()=>{
 const f=fake('/o/api/server/v1/organizations',ORG_LEVEL_SCOPES,ORG_LEVEL_SCOPES.slice(0,2));
 await assert.rejects(authorizeOrgLevel(f.api,'scoped-app'),/ORG_LEVEL_SCOPES_PARTIALLY_AUTHORIZED/);
 assert.deepEqual(f.calls,[]);
});
test('missing/malformed read-back fails closed, never implicitly authorizes',()=>{
 for(const value of [null,{}, {authorizedScopes:null},{authorizedScopes:[{}]},{authorizedScopes:[{name:9}]}]){
  assert.throws(()=>authorizedScopeNames(value),/AUTHORIZED_API_SCOPES_FORMAT_UNRECOGNIZED/);
 }
});
