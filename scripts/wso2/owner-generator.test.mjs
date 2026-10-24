import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';

const repo=join(dirname(fileURLToPath(import.meta.url)),'..','..');
const code=readFileSync(join(repo,'scripts/wso2/tenant-brand-bootstrap.mjs'),'utf8');
test('tenant owner generator has bounded, cryptographically secure password',()=>{
 const match=code.match(/function safeOwner\(\)\s*\{return\s*\{[\s\S]*?\}\s*;?\s*\}/);
 assert.ok(match,'safeOwner present');
 assert.match(match[0],/randomBytes\(21\)\.toString\('base64url'\)/);
 const context={randomBytes:()=>Buffer.alloc(21,0xaa)};
 const owner=runInNewContext(`${match[0]};safeOwner()`,context);
 assert.equal(owner.password.length,28);
 assert.ok(/^[A-Za-z0-9_-]{28}$/.test(owner.password));
 assert.equal(owner.username,'labtenantadmin');
});
