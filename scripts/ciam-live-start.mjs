#!/usr/bin/env node
/**
 * Canonical, fail-closed local v10 CIAM BFF launcher.
 * No WSO2 or PostgreSQL mutations; never touches client secrets or creates identities.
 * Run from npm run start:bff (or node scripts/ciam-live-start.mjs --check).
 */
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { homedir } from 'node:os';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validatePrivateClients } from '../services/identity-bff/src/wso2-private.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ORIGIN = 'http://127.0.0.1:4400';
const PORT = '4400';
const MANIFEST_REL = 'var/wso2/identity-bff-v10.private.json';
const MANIFEST = join(ROOT, MANIFEST_REL);
const CERT = join(homedir(), '.config/ciam/wso2-local.pem');
const DATA_DIR = join(ROOT, 'var/ciam-business-data');
const KEYS = ['aurora-web', 'aurora-app', 'brisa-web', 'brisa-app'];
const ISSUERS = Object.freeze({
  aurora: 'https://localhost:9444/t/aurora.identity.test/oauth2/token',
  brisa: 'https://localhost:9444/t/brisa.identity.test/oauth2/token'
});
const ACR = 'urn:ciampoc:assurance:totp:v1';
const AMR = 'totp';
const CASE_AUD = 'urn:ciampoc:service-requests:v1';

function requireSafeFile(path, name, mode600 = false) {
  if (!existsSync(path)) throw Error(`${name}_MISSING`);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw Error(`${name}_UNSAFE_FILE`);
  if (mode600 && ((stat.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && stat.uid !== process.getuid())))
    throw Error(`${name}_OWNER_OR_PERMISSIONS_INVALID`);
  return stat;
}

function requireSourceSignatures() {
  const sources = [
    ['services/identity-bff/src/server.js', "from './channel-logout.js'"],
    ['services/identity-bff/src/live-cases-v4.js', 'CIAM_BUSINESS_DATA_DIR'],
    ['services/identity-bff/src/approval-stepup-p010.js', 'WSO2_TOTP_STEPUP_ACR'],
    ['services/identity-bff/src/live-experience-v5.js', '/api/logout?client=']
  ];
  for (const [path, marker] of sources) {
    const absolute = join(ROOT, path);
    if (!existsSync(absolute) || !readFileSync(absolute, 'utf8').includes(marker))
      throw Error(`EXPECTED_P1_PATCH_NOT_PRESENT: ${path}`);
  }
}

function checkDataDir(create) {
  const varRoot = join(ROOT, 'var');
  if (!existsSync(varRoot)) {
    if (!create) { console.log('Data directory will be created on start (none currently exists).'); return; }
    mkdirSync(varRoot, { recursive: true, mode: 0o700 });
  }
  const varStat = lstatSync(varRoot);
  if (!varStat.isDirectory() || varStat.isSymbolicLink()) throw Error('VAR_DIRECTORY_NOT_SAFE');
  // Stop rather than silently relocate previous business records.
  const found = [];
  const traverse = (dir, depth) => {
    if (depth > 4) return;
    for (const item of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, item.name);
      if (item.isSymbolicLink()) continue;
      if (item.isDirectory()) { traverse(full, depth + 1); continue; }
      if (/^(requests-(aurora|brisa)|cases-(aurora|brisa))\.jsonl$/i.test(item.name)) found.push(full);
    }
  };
  traverse(varRoot, 0);
  const elsewhere = found.filter(p => dirname(p) !== DATA_DIR);
  if (elsewhere.length) throw Error(`OTHER_BUSINESS_LEDGERS_FOUND: ${elsewhere.map(p => p.slice(ROOT.length + 1)).join(', ')}`);
  if (!existsSync(DATA_DIR)) {
    if (!create) { console.log('Data directory will be created on start:', DATA_DIR); return; }
    mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
  const stat = lstatSync(DATA_DIR);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid()))
    throw Error('BUSINESS_DATA_DIR_MUST_BE_PRIVATE_0700');
  console.log('Durable ledger:', DATA_DIR, '(existing records preserved)');
}

function safeClientSummary() {
  requireSafeFile(MANIFEST, 'V10_PRIVATE_MANIFEST', true);
  const conf = validatePrivateClients(JSON.parse(readFileSync(MANIFEST, 'utf8')), { origin: ORIGIN });
  const unique = new Set();
  for (const key of KEYS) {
    const client = conf[key];
    const brand = key.split('-')[0];
    if (!client?.clientId || !client?.clientSecret || !client?.redirectUri || client.issuer !== ISSUERS[brand])
      throw Error(`V10_CLIENT_CONFIG_INVALID_${key}`);
    if (client.redirectUri !== `${ORIGIN}/auth/${key}/callback`)
      throw Error(`V10_CALLBACK_MISMATCH_${key}`);
    if (unique.has(client.clientId)) throw Error('DUPLICATE_OIDC_CLIENT_ID');
    unique.add(client.clientId);
    console.log(`${key}: verified manifest mapping, callback and tenant (no secrets printed)`);
  }
}

function checkCertificate() {
  requireSafeFile(CERT, 'TRUSTED_WSO2_CERT');
  const cert = new X509Certificate(readFileSync(CERT));
  if (!cert.checkHost('localhost')) throw Error('WSO2_CERT_HOST_MISMATCH');
  const now = Date.now();
  if (now < Date.parse(cert.validFrom) || now > Date.parse(cert.validTo)) throw Error('WSO2_CERT_EXPIRED_OR_NOT_YET_VALID');
  console.log('Local WSO2 certificate: localhost SAN and validity OK (trust is verified by Node at request time)');
}

function checkRegisteredClients(env) {
  const audit = spawnSync('python3', [join(ROOT, 'scripts/ciam-live-registrations.py')], {
    cwd: ROOT, env, encoding: 'utf8', timeout: 30000, maxBuffer: 256 * 1024
  });
  if (audit.error) throw Error('WSO2_REGISTRATION_AUDIT_UNAVAILABLE: ' + audit.error.message);
  if (audit.status !== 0) {
    // This program intentionally logs no secrets or complete client IDs.
    if (audit.stdout) process.stdout.write(audit.stdout);
    throw Error('WSO2_REGISTRATION_AUDIT_FAILED: verify original provisioning; no server started');
  }
  console.log('WSO2 OAuth client IDs/tenants/discovery: four registrations verified (SELECT only)');
}

async function checkPortFree() {
  const server = createServer();
  await new Promise((resolveFree, rejectFree) => {
    server.once('error', rejectFree);
    server.listen(Number(PORT), '127.0.0.1', () => resolveFree());
  }).catch(error => {
    throw Error(error.code === 'EADDRINUSE' ? 'PORT_4400_ALREADY_IN_USE: inspect existing BFF; do not kill an unidentified process' : `PORT_BIND_PROBE_FAILED_${error.code || 'unknown'}`);
  });
  await new Promise(done => server.close(done));
}

function getRuntimeEnv() {
  if (process.env.NODE_ENV === 'production') throw Error('LOCAL_HTTP_NOT_ALLOWED_IN_PRODUCTION');
  // Preserve unrelated private authority/introspection config already exported by the bootstrap.
  return {
    ...process.env,
    IDENTITY_MODE: 'live-wso2',
    ALLOW_INSECURE_LOCAL: 'true',
    PORT,
    PUBLIC_ORIGIN: ORIGIN,
    WSO2_BFF_PRIVATE_MANIFEST: MANIFEST_REL,
    NODE_EXTRA_CA_CERTS: CERT,
    WSO2_CASES_API_AUDIENCE: CASE_AUD,
    WSO2_CASES_SCOPES_ENABLED: '1',
    CIAM_BUSINESS_DATA_DIR: DATA_DIR,
    WSO2_TOTP_STEPUP_ACR: ACR,
    WSO2_TOTP_STEPUP_AMR: AMR,
  };
}

export { getRuntimeEnv }; // pure environment composition for regression testing

async function main() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 1 || args[0] !== '--check')) throw Error('USAGE: npm run start:bff OR npm run ciam:preflight');
  const check = args.includes('--check');
  const env = getRuntimeEnv();
  requireSourceSignatures();
  safeClientSummary();
  checkCertificate();
  checkDataDir(false);
  checkRegisteredClients(env);
  if (!check) { await checkPortFree(); checkDataDir(true); }
  console.log('Runtime: live-wso2; loopback 4400; cases audience and scopes; signed-TOTP ACR/AMR mapping');
  if (!env.WSO2_BUSINESS_API_AUDIENCE)
    console.warn('NOTE: WSO2_BUSINESS_API_AUDIENCE is not set; protected profile API requires its separately verified audience.');
  if (check) { console.log('Preflight PASS. No server started. No WSO2 changes.'); return; }
  const child = spawn(process.execPath, [join(ROOT, 'services/identity-bff/src/server.js')], {
    cwd: ROOT, env, stdio: 'inherit'
  });
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { if (!child.killed) child.kill(sig); });
  child.once('error', error => { console.error('BFF startup failed:', error.message); process.exitCode = 1; });
  child.once('exit', (code, signal) => { process.exitCode = code ?? (signal ? 128 + (signal === 'SIGINT' ? 2 : 15) : 1); });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error('CIAM_STARTUP_BLOCKED:', error.message); process.exitCode = 1; });
}
