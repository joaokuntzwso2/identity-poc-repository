import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
// Snapshot captured once when the BFF process starts; never reads environment secrets.
const here = dirname(fileURLToPath(import.meta.url));
const paths = ['server.js','live-experience-v5.js','live-experience-v5.html',
  'live-premium-p120.js','live-premium-p120.css'];
const files = {};
for(const name of paths){
  try {files[name]=createHash('sha256').update(readFileSync(join(here,name))).digest('hex');}
  catch {files[name]=null;}
}
let commit = null;
try { commit=execFileSync('git',['rev-parse','HEAD'],{cwd:resolve(here,'../../..'),encoding:'utf8',timeout:3000}).trim(); }
catch { /* No Git metadata in an image: report absence, never assert a commit. */ }
export const demoProvenance = Object.freeze({commit, files, capturedAt:new Date().toISOString()});
