// Real, durable service-request operations. No fixture orders, personas, or local permissions.
// WSO2 is the authority for scopes; this module owns only application business records.
import { mkdirSync, openSync, readFileSync, writeSync, fsyncSync, closeSync } from 'node:fs';
import { resolve, isAbsolute } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { precheckApproval } from './case-approval-p010.js';

const SCOPES = Object.freeze({
  create: 'ciam:cases:create', read: 'ciam:cases:read',
  review: 'ciam:cases:review', approve: 'ciam:cases:approve'
});
function actor(issuer, subject) {
  return createHash('sha256').update(JSON.stringify([issuer, subject])).digest('hex');
}
function datastore() {
  const root = process.env.CIAM_BUSINESS_DATA_DIR;
  if (!root || !isAbsolute(root)) throw new Error('CIAM_BUSINESS_DATA_DIR_ABSOLUTE_REQUIRED');
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return root;
}
function fileFor(brand) { return resolve(datastore(), `requests-${brand}.jsonl`); }
function events(brand) {
  let text;
  try { text = readFileSync(fileFor(brand), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  if (Buffer.byteLength(text) > 10 * 1024 * 1024) throw new Error('CASE_LEDGER_LIMIT_REACHED');
  const entries = text.split('\n').filter(Boolean).map(line => JSON.parse(line));
  if (entries.some(e => e.brand !== brand || !['created', 'approved'].includes(e.action)))
    throw new Error('CASE_LEDGER_INVALID');
  return entries;
}
function persist(brand, event) {
  const line = JSON.stringify({ ...event, brand }) + '\n';
  const fd = openSync(fileFor(brand), 'a', 0o600);
  try { writeSync(fd, line); fsyncSync(fd); }
  finally { closeSync(fd); }
}
function materialize(brand) {
  const result = new Map();
  for (const e of events(brand)) {
    if (e.action === 'created') {
      if (result.has(e.id)) throw new Error('DUPLICATE_CASE_ID');
      result.set(e.id, { id: e.id, title: e.title, description: e.description,
        owner: e.actor, createdAt: e.at, status: 'OPEN', approvedAt: null });
    } else {
      const previous = result.get(e.id);
      if (!previous || previous.status !== 'OPEN') throw new Error('INVALID_APPROVAL_EVENT');
      previous.status = 'APPROVED'; previous.approvedAt = e.at;
      previous.approvedBy = e.actor;
    }
  }
  return result;
}
async function body(req) {
  if (!(req.headers['content-type'] || '').startsWith('application/json'))
    throw Object.assign(new Error('json_content_type_required'), { status: 415 });
  let text = '';
  for await (const chunk of req) {
    text += chunk.toString('utf8');
    if (Buffer.byteLength(text) > 2048) throw Object.assign(new Error('request_too_large'), { status: 413 });
  }
  try { return JSON.parse(text); }
  catch { throw Object.assign(new Error('invalid_json'), { status: 400 }); }
}
const send = (res, status, result) => {
  res.writeHead(status, {'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store', 'x-content-type-options':'nosniff'});
  res.end(JSON.stringify(result));
};
export async function handleCases(req, res, u, s, {clients, authorize, sameOrigin, safeCsrf, beginApproval}) {
  const match = /^\/api\/brands\/(aurora|brisa)\/cases(?:\/([0-9a-f-]{36})\/approve)?$/.exec(u.pathname);
  if (!match) return false;
  const [ , brand, caseId ] = match;
  const key = u.searchParams.get('client');
  if (!key || !Object.hasOwn(clients, key)) { send(res,400,{error:'invalid_client'});return true; }
  if (clients[key].brand !== brand) { send(res,403,{error:'tenant_brand_mismatch'});return true; }
  const desired = caseId ? SCOPES.approve : req.method === 'POST' ? SCOPES.create : SCOPES.read;
  if (!caseId && req.method !== 'POST' && req.method !== 'GET' || caseId && req.method !== 'POST') {
    send(res,405,{error:'method_not_allowed'});return true;
  }
  const decision = await authorize(s, key, desired);
  if (decision.http !== 200) { send(res,decision.http,{error:decision.reason,allowed:false});return true; }
  const login = s.logins[key];
  if (!login?.verified || login.claims?.iss !== clients[key].issuer || !login.claims?.sub) {
    send(res,401,{error:'authentication_required'});return true;
  }
  const who = actor(login.claims.iss,login.claims.sub);
  // A separate approval-bound WSO2 reauthentication follows authorization.
  // MFA in an ordinary login is NEVER sufficient for approval.
  if (req.method === 'POST' && (!sameOrigin(req) || !safeCsrf(req, s))) {
    send(res,403,{error:'csrf_or_origin_denied'});return true;
  }
  try {
    if (caseId) {
      precheckApproval({brand,caseId,issuer:login.claims.iss,subject:login.claims.sub});
      const launch = await beginApproval({session:s,key,brand,caseId});
      send(res,202,{status:'WSO2_TOTP_STEP_UP_REQUIRED',...launch});return true;
    }
    if (req.method === 'POST') {
      const input = await body(req);
      if (!input || typeof input.title !== 'string' || typeof input.description !== 'string' ||
          input.title.trim().length < 3 || input.title.length > 120 || input.description.length > 1000) {
        send(res,400,{error:'invalid_case_fields'});return true;
      }
      const id=randomUUID();
      persist(brand,{id,action:'created',actor:who,title:input.title.trim(),
        description:input.description,at:new Date().toISOString()});
      send(res,201,{id,status:'OPEN',persistent:true});return true;
    }
    // Read-all is only allowed if the *token* has ciam:cases:review.
    const review = await authorize(s,key,SCOPES.review);
    const all = review.http === 200;
    if (!all && review.http !== 403) {send(res,review.http,{error:review.reason});return true;}
    const out = [...materialize(brand).values()]
      .filter(x => all || x.owner === who)
      .map(({owner,approvedBy,...record}) => record); // don't disclose identity hashes
    send(res,200,{brand,records:out,visibility:all?'BRAND_REVIEW':'OWNER_ONLY',persistent:true});
    return true;
  } catch (error) {
    console.error(JSON.stringify({event:'LIVE_CASES_FAILED',message:error.message}));
    send(res,error.status || 503,{error:error.code || 'persistent_business_service_unavailable'}); return true;
  }
}
