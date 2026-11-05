import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const js=await readFile(new URL('../src/live-experience-v5.js',import.meta.url),'utf8');
const css=await readFile(new URL('../src/live-experience-v5.css',import.meta.url),'utf8');
test('web routes use a first-party phone-stage wrapper, mobile channels remain unchanged',()=>{
  assert.match(js,/const frameOpen = mobile \? ''/);
  assert.match(js,/const frameClose = mobile \? ''/);
  assert.match(js,/data-testid="live-retail-device"/);
  assert.match(js,/data-testid="live-retail-screen"/);
  assert.match(css,/\.v5-retail-stage \.v5-case-form/);
});
test('existing WSO2 routes and controlled case form are unchanged',()=>{
  for(const route of ['/portal/aurora/web','/portal/brisa/web','/portal/aurora/mobile','/portal/brisa/mobile'])assert.ok(js.includes(route));
  for(const id of ['site-profile','site-login','v5-case-create','v5-case-list-btn'])assert.ok(js.includes(`id="${id}"`));
  assert.match(js,/const response = await fetch\(url, \{credentials:'same-origin'/);
});
