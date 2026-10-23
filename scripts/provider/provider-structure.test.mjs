import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
const read=p=>readFileSync(p,'utf8');
test('provider UI is a separate build entry with a launcher link',()=>{
 assert.ok(existsSync('apps/experience-center/provider.html'));
 assert.match(read('apps/experience-center/provider.vite.config.ts'),/provider\.html/);
 assert.match(read('experience.sh'),/provider\.vite\.config\.ts/);
 assert.match(read('apps/experience-center/src/main.tsx'),/href="\/provider\.html"/);
});
test('read-only adapter is exposed through the existing loopback API',()=>{
 const source=read('services/experience-api/server.mjs');
 assert.match(source,/createProviderHttpRoute/);
 assert.match(source,/await providerRoute\(/);
 assert.match(source,/getMode\(process\.env\)!=='story-preview'/);
});
test('public README tells the architecture story and does not mark live acceptance',()=>{
 const readme=read('README.md');
 for(const name of ['The challenge','WSO2 Identity Server 7.3','Run locally','Implementation status','Security and evidence','Roadmap'])assert.ok(readme.includes(name),name);
 assert.match(readme,/NOT|pending|not configured/i);
});
test('public-safe example has separate web/mobile clients per brand',()=>{
 const config=JSON.parse(read('config/provider-client-contract.json'));
 assert.equal(config.brands.length,2);
 for(const brand of config.brands){assert.equal(brand.clients.length,2);assert.ok(brand.sectorKey)}
 assert.notEqual(config.brands[0].sectorKey,config.brands[1].sectorKey);
});
