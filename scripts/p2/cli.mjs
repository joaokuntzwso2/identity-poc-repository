#!/usr/bin/env node
/** P2 guarded operator CLI. Local operator execution only; never exposed by the BFF. */
import { readFile, lstat, open, rename } from 'node:fs/promises';
import { dirname, resolve, join, relative } from 'node:path';
import { homedir } from 'node:os';
import { GateError, insist, UUID, TENANT, PARTNER, makeTransport,
  planPartner, createPartner, inventoryChild, disableChildUser, inspectPartnerInventory } from './guarded-org.mjs';

const COMMANDS = ['inspect-partner-inventory', 'plan-partner', 'create-partner', 'child-users', 'disable-user'];
const APPROVAL = Object.freeze({
  'create-partner': 'CREATE_AURORA_RETURNS_PARTNER',
  'disable-user': 'DISABLE_AURORA_PARTNER_USER'
});
const help = `P2.24 + P2.29 operator kit (no automatic mutations).
Commands: inspect-partner-inventory | plan-partner | create-partner | child-users | disable-user
Required: P2_TOKEN_FILE=/absolute/path/mode0600 P2_ROOT_ORG_ID=uuid
  child-users/disable-user also need P2_CHILD_ORG_ID=uuid
  disable-user also needs P2_TARGET_USER_ID=uuid
Optional: P2_ORIGIN=https://localhost:9444
  P2_PRIVATE_DIR=~/wso2-ciam-v10/private
Mutations require exact --confirm=${APPROVAL['create-partner']} or
 --confirm=${APPROVAL['disable-user']} respectively.
Use NODE_EXTRA_CA_CERTS with a separately verified local WSO2 CA/cert chain.
No active server update, root tenant, business role, or browser API changes.
`;

function privateDir() {
  return resolve(process.env.P2_PRIVATE_DIR || join(homedir(), 'wso2-ciam-v10/private'));
}
async function requirePrivateDir(folder) {
  const s = await lstat(folder);
  insist(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() &&
    (s.mode & 0o077) === 0, 'PRIVATE_DIRECTORY_UNSAFE');
}
async function secureFile(file, base) {
  insist(typeof file === 'string' && file.startsWith('/'), 'TOKEN_FILE_ABSOLUTE_PATH_REQUIRED');
  const abs = resolve(file), rel = relative(base, abs);
  insist(rel && rel !== '..' && !rel.startsWith('../') && !rel.includes('/../'), 'TOKEN_OUTSIDE_PRIVATE_DIR');
  const s = await lstat(abs);
  insist(s.isFile() && !s.isSymbolicLink() && s.uid === process.getuid() && (s.mode & 0o777) === 0o600 &&
    s.size >= 25 && s.size <= 8192, 'TOKEN_FILE_PERMISSIONS_OR_SIZE_INVALID');
  const contents = await readFile(abs, 'utf8');
  insist(!contents.includes('\0') && contents.trim().split(/\s+/).length === 1,
    'TOKEN_FILE_CONTENT_INVALID');
  return contents.trim();
}
async function readJournal(path) {
  try {
    const s = await lstat(path);
    insist(s.isFile() && !s.isSymbolicLink() && s.uid === process.getuid() && (s.mode & 0o777) === 0o600,
      'JOURNAL_PERMISSIONS_INVALID');
    const obj = JSON.parse(await readFile(path, 'utf8'));
    insist(obj && ['INTENT','VERIFIED'].includes(obj.state), 'JOURNAL_INVALID');
    return obj;
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}
async function journalIntent(path, details) {
  // 'wx' is exclusive. No operation is sent after a failed or ambiguous journal write.
  const f = await open(path, 'wx', 0o600);
  try {
    await f.writeFile(JSON.stringify({state:'INTENT', at:new Date().toISOString(), details}) + '\n');
    await f.sync();
  } finally { await f.close(); }
  // Persist the directory entry before sending a write to WSO2; an intent
  // that can disappear after a crash is not a durable anti-replay guard.
  const folder = await open(dirname(path), 'r');
  try { await folder.sync(); } finally { await folder.close(); }
}
async function journalComplete(path, value) {
  const temp = `${path}.${process.pid}.tmp`;
  const f = await open(temp, 'wx', 0o600);
  try {
    await f.writeFile(JSON.stringify({state:'VERIFIED', at:new Date().toISOString(), details:value}) + '\n');
    await f.sync();
  } finally { await f.close(); }
  await rename(temp, path);
  // fsync parent directory so the rename is durable before displaying success.
  const folder = await open(dirname(path), 'r');
  try { await folder.sync(); } finally { await folder.close(); }
}
function requiredUUID(name) {
  const v = process.env[name];
  insist(typeof v === 'string' && UUID.test(v), `${name}_UUID_REQUIRED`);
  return v;
}
function approval(command, option) {
  insist(option === `--confirm=${APPROVAL[command]}`, 'EXPLICIT_MUTATION_APPROVAL_REQUIRED');
}
export async function main(args = process.argv.slice(2)) {
  const [command, confirmation, ...extra] = args;
  if (command === '--help' || command === 'help' || !command) { process.stdout.write(help); return; }
  insist(COMMANDS.includes(command) && extra.length === 0, 'UNKNOWN_COMMAND_OR_ARGUMENTS');
  if (APPROVAL[command]) approval(command, confirmation);
  else insist(!confirmation, 'UNEXPECTED_ARGUMENT');
  const folder = privateDir();
  await requirePrivateDir(folder);
  const token = await secureFile(process.env.P2_TOKEN_FILE, folder);
  const call = makeTransport({ origin: process.env.P2_ORIGIN || 'https://localhost:9444', bearer: token });
  const rootId = requiredUUID('P2_ROOT_ORG_ID');
  let result;
  if (command === 'inspect-partner-inventory') {
    result = await inspectPartnerInventory(call, rootId);
  } else if (command === 'plan-partner') {
    const r = await planPartner(call, rootId);
    result = { action:r.action, parentFingerprint:r.parentFingerprint,
      ...(r.organizationFingerprint ? {organizationFingerprint:r.organizationFingerprint} : {}) };
  } else if (command === 'create-partner') {
    const file = join(folder, 'p2-aurora-partner-create.private.json');
    const previous = await readJournal(file);
    insist(previous === null, previous?.state === 'INTENT' ? 'PRIOR_MUTATION_UNCERTAIN_MANUAL_RECONCILIATION' : 'PRIOR_MUTATION_JOURNALED_NO_REPLAY');
    const r = await createPartner(call, rootId, async intent => journalIntent(file, intent));
    if (r.created) await journalComplete(file, {organizationId: r.id, parentId:rootId,
      name:PARTNER.name, orgHandle:PARTNER.orgHandle});
    result = {action:r.action, organizationFingerprint:r.organizationFingerprint};
  } else {
    const childId = requiredUUID('P2_CHILD_ORG_ID');
    insist(childId !== rootId, 'CHILD_MUST_DIFFER_FROM_PARENT');
    if (command === 'child-users') {
      result = await inventoryChild(call, childId, rootId);
    } else {
      const userId = requiredUUID('P2_TARGET_USER_ID');
      const file = join(folder, `p2-disable-${userId}.private.json`);
      const previous = await readJournal(file);
      insist(previous === null, previous?.state === 'INTENT' ? 'PRIOR_MUTATION_UNCERTAIN_MANUAL_RECONCILIATION' : 'PRIOR_MUTATION_JOURNALED_NO_REPLAY');
      const r = await disableChildUser(call, childId, rootId, userId,
        async intent => journalIntent(file, intent));
      if (r.action === 'DISABLED_AND_VERIFIED') await journalComplete(file, {childId,userId,active:false});
      result = r;
    }
  }
  process.stdout.write(JSON.stringify({ phase:'P2.24-P2.29', source:'WSO2_API_RESPONSE',
    runtimeEvidence:'OPERATOR_EXECUTED', tenant:TENANT, result }, null, 2) + '\n');
}
if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  main().catch(e => {
    const code = e instanceof GateError ? e.code : 'STOP_UNEXPECTED_CHECK_PRIVATE_JOURNAL';
    // Error bodies, tokens, user claims and stack traces are never printed.
    process.stderr.write(JSON.stringify({ status:'BLOCKED', code }) + '\n');
    process.exitCode = 2;
  });
}
