#!/usr/bin/env node
/**
 * Idempotent initialization of the two application-owned JSONL business ledgers.
 * No WSO2 calls, no PostgreSQL calls, and no writes to existing ledger files.
 * Running the repository's npm bootstrap triggers this via postbootstrap.
 */
import { constants, closeSync, existsSync, fsyncSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BRANDS, parseLedgerBuffer } from '../services/identity-bff/src/business-ledger.js';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fileNames = BRANDS.map(brand => ({brand, name:`requests-${brand}.jsonl`}));
const nofollow = constants.O_NOFOLLOW || 0;

function safeExistingFile(path, brand) {
  // O_NOFOLLOW prevents a symbolic link from redirecting a ledger read.
  const fd = openSync(path, constants.O_RDONLY | nofollow);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || (info.mode & 0o077) !== 0)
      throw new Error(`UNSAFE_LEDGER_FILE:${brand}`);
    if (typeof process.getuid === 'function' && info.uid !== process.getuid())
      throw new Error(`LEDGER_OWNER_MISMATCH:${brand}`);
    const decoded = parseLedgerBuffer(readFileSync(fd), brand);
    return {brand, result:'preserved', cases:decoded.records.length, events:decoded.events.length, sha256:decoded.sha256};
  } finally { closeSync(fd); }
}

export function bootstrapBusinessLedgers(env=process.env) {
  if ((env.CIAM_CASES_BACKEND || 'jsonl') !== 'jsonl')
    throw new Error('JSONL_BOOTSTRAP_REFUSED_IN_POSTGRES_MODE');
  const dir = env.CIAM_BUSINESS_DATA_DIR || join(repositoryRoot, 'var', 'ciam-business-data');
  if (!isAbsolute(dir)) throw new Error('ABSOLUTE_LEDGER_DIRECTORY_REQUIRED');
  const location = resolve(dir);
  const marker = join(location, 'business-postgres-cutover.json');
  // lstat detects even a dangling symlink at the cutover marker location.
  try { lstatSync(marker); throw new Error('JSONL_BOOTSTRAP_REFUSED_AFTER_CUTOVER'); }
  catch(error) { if (error?.code !== 'ENOENT') throw error; }

  // Existing files are checked BEFORE any missing file is created.
  if (existsSync(location)) {
    const info = lstatSync(location);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0)
      throw new Error('UNSAFE_BUSINESS_LEDGER_DIRECTORY');
    if (typeof process.getuid === 'function' && info.uid !== process.getuid())
      throw new Error('LEDGER_DIRECTORY_OWNER_MISMATCH');
  }
  const before = fileNames.map(({brand,name}) => {
    const path = join(location,name);
    try {
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`UNSAFE_LEDGER_FILE:${brand}`);
      return safeExistingFile(path,brand);
    } catch (error) {
      if (error?.code === 'ENOENT') return {brand, result:'missing'};
      throw error;
    }
  });
  if (!existsSync(location)) mkdirSync(location, {recursive:true, mode:0o700});
  const output = [];
  for (const item of before) {
    if (item.result === 'preserved') {output.push(item);continue;}
    const path = join(location,`requests-${item.brand}.jsonl`);
    let fd;
    try {
      fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | nofollow, 0o600);
      fsyncSync(fd);
      output.push({brand:item.brand,result:'created_empty',cases:0,events:0});
    } catch(error) {
      // Another bootstrap process could have created the file concurrently.
      // Never truncate it, never replace it, and validate its contents before proceeding.
      if (error?.code !== 'EEXIST') throw error;
      output.push(safeExistingFile(path,item.brand));
    } finally {if(fd !== undefined) closeSync(fd);}
  }
  return {directory:location, ledgers:output};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {console.log(JSON.stringify(bootstrapBusinessLedgers(),null,2));}
  catch(error) {console.error(`BUSINESS_LEDGER_BOOTSTRAP_FAILED: ${error.message}`);process.exitCode=1;}
}
