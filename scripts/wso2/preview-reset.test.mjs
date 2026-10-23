import test from 'node:test';import assert from 'node:assert/strict';
import{mkdtempSync,writeFileSync,existsSync,readFileSync}from'node:fs';import{tmpdir}from'node:os';import{join}from'node:path';
import{authenticatedInternalReset,rotatePreviewDatabase}from'./preview-reset.mjs';
const key='a'.repeat(64);
test('internal reset requires loopback, no browser Origin, and constant-time secret',()=>{
 const req={method:'POST',headers:{'x-internal-operator':'local-reset-v1','x-demo-operator-key':key},socket:{remoteAddress:'127.0.0.1'}};
 assert.equal(authenticatedInternalReset(req,key),true);
 assert.equal(authenticatedInternalReset({...req,headers:{...req.headers,origin:'http://127.0.0.1:5173'}},key),false);
 assert.equal(authenticatedInternalReset({...req,socket:{remoteAddress:'192.168.1.99'}},key),false);
 assert.equal(authenticatedInternalReset({...req,headers:{...req.headers,'x-demo-operator-key':'x'.repeat(64)}},key),false);
});
test('rotates synthetic DB to a separate private audit archive instead of erasing evidence',()=>{
 const dir=mkdtempSync(join(tmpdir(),'archive-preview-'));const path=join(dir,'preview.sqlite');writeFileSync(path,'fixture-ledger');let closed=false;
 const archive=rotatePreviewDatabase(path,{db:{},close:()=>{closed=true}},{archiveRoot:join(dir,'private')});
 assert.equal(closed,true);assert.equal(archive.archived,true);assert.equal(existsSync(path),false);assert.equal(readFileSync(join(archive.archiveDir,'preview.sqlite'),'utf8'),'fixture-ledger');
});
