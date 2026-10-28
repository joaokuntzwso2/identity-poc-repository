#!/usr/bin/env node
/** Installs only the Playwright Chromium browser binary declared by the installed npm package.
 * No running BFF or WSO2 configuration writes. No unpinned npx package downloads.
 */
import { chromium } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const mode=process.argv[2];
if (!['--check','--install'].includes(mode)) {
  console.error('USAGE: node scripts/ciam-p010-browser-ready.mjs --check|--install');process.exit(2);
}
function installed(){return existsSync(chromium.executablePath());}
const before=installed();
if(mode==='--install'&&!before){
  let cli;
  try {
    const manifest = require.resolve('playwright/package.json');
    const pkg = JSON.parse(readFileSync(manifest, 'utf8'));
    const entry = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.playwright;
    if (entry !== 'cli.js') throw Error('UNEXPECTED_PLAYWRIGHT_BINARY');
    cli = resolve(dirname(manifest), entry);
    if (!existsSync(cli)) throw Error('PLAYWRIGHT_CLI_MISSING');
  }catch{
    console.log(JSON.stringify({status:'PLAYWRIGHT_PACKAGE_CLI_UNAVAILABLE',browserInstalled:false,remoteWso2Writes:0}));
    process.exit(2);
  }
  const result=spawnSync(process.execPath,[cli,'install','chromium'],{
    stdio:'inherit',timeout:240000,env:process.env
  });
  if(result.error||result.status!==0){
    console.log(JSON.stringify({status:'CHROMIUM_INSTALL_FAILED',browserInstalled:false,remoteWso2Writes:0}));
    process.exit(2);
  }
}
const now=installed();
console.log(JSON.stringify({stage:'P010_PLAYWRIGHT_CHROMIUM_LOCAL_READY',
  status:now?'CHROMIUM_READY':'CHROMIUM_MISSING',
  browserInstalled:now,installedThisRun:!before&&now,remoteWso2Writes:0},null,2));
if(!now)process.exitCode=2;
