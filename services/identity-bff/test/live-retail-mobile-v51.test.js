import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const js = await readFile(new URL('../src/live-experience-v5.js', import.meta.url), 'utf8');
const css = await readFile(new URL('../src/live-experience-v5.css', import.meta.url), 'utf8');
const digest = text => createHash('sha256').update(text).digest('hex');
const webBaselineSha = '729adcbf49855a45048e389d5b3facf3a06ca650f1d7b05e9347632d08f874f0';
const cssBaselineSha = 'd5f48d1f77c27bb2decd301449560887b16f8f64ead2b889b6a61bc1fd41ecbd';

test('mobile-only shell: stripping conditional decoration restores original JS exactly', () => {
  const marker='    // Phone-style shell is ONLY for the separate MOBILE OIDC channel.';
  const start=js.indexOf(marker);
  assert.ok(start>0);
  const end=js.indexOf('    root.innerHTML=`${frameOpen}<div class="retail-site',start);
  assert.ok(end>start);
  const baseline=js.slice(0,start)+js.slice(end)
    .replace('    root.innerHTML=`${frameOpen}<div class="retail-site','    root.innerHTML=`<div class="retail-site')
    .replace('</footer></div>${frameClose}`;','</footer></div>`;');
  assert.equal(digest(baseline),webBaselineSha);
  assert.match(js,/const frameOpen = mobile \? `<div class="v5-retail-stage/);
  assert.match(js,/const frameClose = mobile \? `/);
  assert.match(js,/data-testid="live-retail-screen"/);
});
test('web CSS is untouched; responsive styles are appended and scoped to mobile wrapper', () => {
  const marker='/* P2_RETAIL_MOBILE_ONLY_V51:';
  const idx=css.indexOf(marker);
  assert.ok(idx>0);
  const original=css.slice(0,idx).replace(/\s+$/,'');
  // Original source ends with a trailing newline before appended decoration.
  assert.equal(digest(original+'\n'),cssBaselineSha);
  assert.match(css,/\.v5-retail-stage \.v5-case-form/);
  assert.match(css,/\.v5-retail-stage \.v5-identity-strip/);
});
test('all four WSO2 channels and protected operations are still in place', () => {
  for(const route of ['/portal/aurora/web','/portal/brisa/web','/portal/aurora/mobile','/portal/brisa/mobile'])
    assert.ok(js.includes(route));
  for(const id of ['site-profile','site-login','v5-case-create','v5-case-list-btn'])
    assert.ok(js.includes(`id="${id}"`));
  assert.match(js,/const response = await fetch\(url, \{credentials:'same-origin'/);
});
