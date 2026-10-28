/** Optional live callback proof. Never exports identity, JWTs or access tokens. */
import { constants, existsSync, lstatSync, mkdirSync, openSync, writeSync, closeSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { inspectAccessToken } from './wso2-authority.js';

const KEYS = new Set(['aurora-web', 'aurora-app', 'brisa-web', 'brisa-app']);
function privateReport(record) {
  const home = process.env.CIAM_V10_HOME || join(homedir(), 'wso2-ciam-v10');
  const dir = join(home, 'inspection');
  if (!existsSync(home) || lstatSync(home).isSymbolicLink()) throw new Error('UNSAFE_PRIVATE_HOME');
  if (existsSync(dir) && lstatSync(dir).isSymbolicLink()) throw new Error('UNSAFE_EVIDENCE_DIRECTORY');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = statSync(dir);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077))
    throw new Error('PRIVATE_EVIDENCE_DIRECTORY_PERMISSIONS');
  const target = join(dir, 'ciam-v10-binding-evidence.jsonl');
  const fd = openSync(target, constants.O_WRONLY | constants.O_APPEND |
    constants.O_CREAT | (constants.O_NOFOLLOW || 0), 0o600);
  try {
    const info = statSync(target);
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o077))
      throw new Error('PRIVATE_EVIDENCE_FILE_PERMISSIONS');
    writeSync(fd, JSON.stringify(record) + '\n');
  } finally { closeSync(fd); }
}
export async function verifyAndRecordBinding({ key, client, login, inspect = inspectAccessToken, record = privateReport }) {
  if (!KEYS.has(key) || !client || !login?.verified || !login?.claims?.sub || !login?.accessToken)
    throw new Error('BINDING_PROBE_CONTEXT_INVALID');
  let result = { active: false };
  try { result = await inspect(login, client); }
  catch { /* fail closed, never disclose upstream errors or credentials */ }
  const runId = process.env.WSO2_CIAM_BINDING_RUN_ID;
  if (!/^[A-Za-z0-9_-]{12,96}$/.test(runId || ''))
    throw new Error('BINDING_PROBE_RUN_ID_REQUIRED');
  const bound = result?.active === true;
  record({ runId, schema: 'ciam-v10.binding.v1', at: new Date().toISOString(),
    key, state: bound ? 'EXACT_SESSION_TOKEN_SUBJECT_BOUND' : 'NOT_VERIFIED',
    evidence: 'SIGNED_ID_TOKEN_PLUS_LIVE_INTROSPECTION',
    userOrTokenDataIncluded: false });
  return bound;
}
