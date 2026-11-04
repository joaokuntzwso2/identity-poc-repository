/** V13: isolated Aurora-only organization I/O. Bearer tokens enter by stdin only.
 * Never write tokens, claim authz, or fall back to non-Aurora paths.
 */
import { readFile, lstat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { PARTNER, TENANT, UUID, fingerprint, makeTransport, planPartner,
         createPartner, rootMetadata, insist, GateError } from './guarded-org.mjs';

const ORG = `/t/${TENANT}/o/api/server/v1/organizations`;
const EXPECTED_ROOT_FP = '4548812d1a94a3ff';
const APPROVAL = 'P2_V13_AURORA_RETURNS_ONE_CREATE_APPROVED';

function requireToken(t) {
  insist(typeof t === 'string' && t.length >= 25 && t.length <= 8192 &&
         t.trim() === t && !/\s/.test(t), 'V13_PRIVATE_TOKEN_INVALID');
  return t;
}
function requestGuard(input, expectedRootFp) {
  insist(input && typeof input === 'object' && !Array.isArray(input), 'V13_INPUT_INVALID');
  insist(UUID.test(input.rootId) && fingerprint(input.rootId) === expectedRootFp,
    'V13_ROOT_PIN_MISMATCH');
  requireToken(input.viewToken);
}
function exactPartner(item, child, parent) {
  insist(item && item.id === child && item.id !== parent && item.name === PARTNER.name &&
    item.orgHandle === PARTNER.orgHandle && item.parent?.id === parent &&
    item.status === 'ACTIVE', 'V13_CHILD_READBACK_MISMATCH');
  return { organizationFingerprint: fingerprint(child), parentFingerprint: fingerprint(parent) };
}
export async function run(input, { fetcher = globalThis.fetch, checkIntent = async () => {}, expectedRootFp = EXPECTED_ROOT_FP } = {}) {
  requestGuard(input, expectedRootFp);
  const origin = 'https://localhost:9444';
  const view = makeTransport({ origin, bearer: input.viewToken, fetcher });
  if (input.mode === 'plan' || input.mode === 'reconcile') {
    const result = await planPartner(view, input.rootId);
    return { action: result.action, ...(result.id ? { id: result.id } : {}),
             ...(result.organizationFingerprint ? { organizationFingerprint:result.organizationFingerprint } : {}),
             parentFingerprint: result.parentFingerprint };
  }
  if (input.mode === 'verify') {
    insist(UUID.test(input.partnerId), 'V13_PARTNER_ID_INVALID');
    const root = await view('GET', `${ORG}/metadata`);
    insist(root.status === 200, 'V13_ROOT_METADATA_UNAVAILABLE');
    rootMetadata(root.body, input.rootId);
    insist(root.body?.type === 'TENANT' &&
      (root.body?.orgHandle === TENANT || root.body?.domain === TENANT),
      'V13_ROOT_TENANT_CONTEXT_UNVERIFIED');
    const child = await view('GET', `${ORG}/${input.partnerId}`);
    insist(child.status === 200, 'V13_CHILD_GET_NOT_200');
    return { action:'EXACT_CHILD_VERIFIED', ...exactPartner(child.body, input.partnerId, input.rootId) };
  }
  insist(input.mode === 'create' && input.approval === APPROVAL,
    'V13_CREATE_REQUIRES_APPROVED_BOOTSTRAP');
  requireToken(input.creatorToken);
  // The creator token is strictly withheld from GET operations. Scope is independently
  // proven by the Python orchestrator through WSO2's OAuth token response.
  const creator = makeTransport({ origin, bearer:input.creatorToken, fetcher });
  const split = async (method, path, data = null) => {
    if (method === 'POST') {
      insist(path === ORG && data && data.name === PARTNER.name &&
        data.orgHandle === PARTNER.orgHandle && data.parentId === input.rootId &&
        data.description === PARTNER.description && Object.keys(data).length === 4,
        'V13_ORGANIZATION_POST_PAYLOAD_NOT_APPROVED');
      return creator(method, path, data);
    }
    insist(method === 'GET', 'V13_ONLY_ONE_ORGANIZATION_POST_ALLOWED');
    return view(method, path, data);
  };
  let intentChecked = false;
  const result = await createPartner(split, input.rootId, async details => {
    insist(details.expectedParentId === input.rootId &&
      details.name === PARTNER.name && details.orgHandle === PARTNER.orgHandle,
      'V13_INTENT_PAYLOAD_MISMATCH');
    await checkIntent(details);
    intentChecked = true;
  });
  insist(intentChecked && result.created === true && UUID.test(result.id),
    'V13_CREATE_NOT_PROVEN_OR_PARTNER_APPEARED_CONCURRENTLY');
  return { action:'CREATED_AND_VERIFIED', id:result.id,
           organizationFingerprint:result.organizationFingerprint,
           parentFingerprint:fingerprint(input.rootId) };
}

async function main() {
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (raw.length > 24576) throw new GateError('V13_STDIN_TOO_LARGE');
  }
  let input;
  try { input = JSON.parse(raw); } catch { throw new GateError('V13_INPUT_NOT_JSON'); }
  const checkIntent = async () => {
    insist(typeof input.intentPath === 'string' && input.intentPath.endsWith('/p2-aurora-partner-create.private.json'),
      'V13_INTENT_LOCATION_INVALID');
    const stat = await lstat(input.intentPath);
    insist(stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() &&
      (stat.mode & 0o777) === 0o600, 'V13_INTENT_FILE_UNSAFE');
    const doc = JSON.parse(await readFile(input.intentPath, 'utf8'));
    insist(doc.schema === 'p2.24.aurora.partner.v13' && doc.state === 'INTENT' &&
      doc.details?.parentId === input.rootId &&
      doc.details?.name === PARTNER.name && doc.details?.orgHandle === PARTNER.orgHandle &&
      doc.details?.remoteWritesAttempted === 1,
      'V13_DURABLE_CREATE_INTENT_UNVERIFIED');
  };
  const output = await run(input, { checkIntent });
  process.stdout.write(JSON.stringify(output) + '\n');
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(e => {
    const code = e instanceof GateError ? e.code : 'V13_ORGANIZATION_IO_UNCERTAIN_NO_RETRY';
    process.stderr.write(JSON.stringify({ status:'BLOCKED', code }) + '\n');
    process.exitCode = 2;
  });
}
