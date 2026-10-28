/**
 * WSO2 IS 7.3 tenant-owner password repair, explicitly authorized, fail closed.
 * Uses the existing super-tenant Tenant Management API. No Docker changes and
 * no mutation of tenant-brand.private.json / ownerRecovery journal.
 *
 * Modes: check <brand> (GET-only), apply <brand> (at most one PUT per brand),
 *        status, clipboard <brand> (macOS pbcopy, never logs password).
 */
import { randomBytes, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, openSync, closeSync, writeFileSync,
  fsyncSync, renameSync, unlinkSync, realpathSync, constants } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const SCHEMA = 'identity.wso2.owner-password-repair.v1';
const PATH = '/api/server/v1/tenants';
const DOMAINS = Object.freeze({aurora:'aurora.identity.test',brisa:'brisa.identity.test'});
const IDENTIFIER = /^[A-Za-z0-9-]{5,128}$/;
const REPAIR_CONFIRM = 'RESET_EXISTING_OWNER_WITH_WRITE_AHEAD_JOURNAL';
const AURORA_CONFIRM = 'SUPERSEDE_UNRESOLVED_AURORA_RECOVERY_WITH_NEW_REPAIR';

function stop(code) { const e = new Error(code); e.code = code; throw e; }
const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
function privateDir(root) {
  const home = resolve(root);
  const variable = join(home, 'var');
  const state = join(variable, 'wso2');
  for (const dir of [home, variable, state]) {
    const st = lstatSync(dir);
    if (!st.isDirectory() || st.isSymbolicLink()) stop('UNSAFE_STATE_DIRECTORY');
  }
  if (realpathSync(state) !== join(realpathSync(home), 'var', 'wso2')) stop('UNSAFE_STATE_PATH');
  return state;
}
function readPrivate(path, {optional=false}={}) {
  if (optional && !existsSync(path)) return {value:null,revision:null};
  const st = lstatSync(path);
  if (!st.isFile() || st.isSymbolicLink() || st.size<2 || st.size>128*1024 ||
      (st.mode & 0o077)!==0 || (typeof process.getuid==='function' && st.uid!==process.getuid()))
    stop('PRIVATE_FILE_UNSAFE');
  const revision = readFileSync(path,'utf8');
  let value;
  try { value = JSON.parse(revision); } catch { stop('PRIVATE_JSON_INVALID'); }
  if (!obj(value)) stop('PRIVATE_SCHEMA_INVALID');
  return {value,revision};
}
function durableWrite(path,value,previousRevision) {
  // Before every write, compare exact previous contents; no silent overwrites.
  const existing = existsSync(path) ? readPrivate(path).revision : null;
  if (existing !== previousRevision) stop('JOURNAL_CHANGED_STOP');
  const temp = `${path}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
  let fd;
  try {
    fd = openSync(temp, constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL,0o600);
    writeFileSync(fd,JSON.stringify(value,null,2)+'\n');
    fsyncSync(fd); closeSync(fd); fd=undefined;
    if ((existsSync(path) ? readPrivate(path).revision : null) !== previousRevision)
      stop('JOURNAL_CHANGED_STOP');
    renameSync(temp,path);
  } finally {
    if (fd!==undefined) closeSync(fd);
    try { unlinkSync(temp); } catch {}
  }
  return readPrivate(path).revision;
}
function validatedEnvironment(env, root) {
  let u;
  try { u=new URL(env.WSO2_BASE_URL||''); } catch { stop('LOCAL_WSO2_ORIGIN_REQUIRED'); }
  if (u.protocol!=='https:' || u.port!=='9443' ||
      !['localhost','127.0.0.1'].includes(u.hostname) ||
      u.pathname!=='/' || u.username || u.password || u.search || u.hash)
    stop('UNTRUSTED_WSO2_ORIGIN');
  if (!env.WSO2_ADMIN_USER || !env.WSO2_ADMIN_PASSWORD) stop('SUPER_TENANT_ADMIN_CREDENTIALS_REQUIRED');
  if (env.NODE_TLS_REJECT_UNAUTHORIZED==='0') stop('TLS_VERIFICATION_DISABLED');
  const ca = join(resolve(root),'var/wso2/tls/wso2-local.pem');
  if (!env.NODE_EXTRA_CA_CERTS || resolve(env.NODE_EXTRA_CA_CERTS)!==ca || !existsSync(ca))
    stop('PINNED_LOCAL_CA_REQUIRED');
  return u.origin;
}
function verifyLocalOwner(journal,brand) {
  const tenant=journal?.tenants?.[brand];
  if (journal.schema!=='identity.wso2.tenant-brand.v1' || tenant?.owned!==true ||
      tenant.domain!==DOMAINS[brand] || tenant.state!=='created' ||
      tenant.owner?.username!=='labtenantadmin' ||
      !['email','firstname','lastname'].every(k=>typeof tenant.owner[k]==='string' && tenant.owner[k].length>0) ||
      typeof tenant.owner.password!=='string') stop('TENANT_OWNER_JOURNAL_UNVERIFIED');
  if (tenant.ownerRecovery && (brand!=='aurora' || tenant.ownerRecovery.state!=='update-started' ||
      !IDENTIFIER.test(tenant.ownerRecovery.tenantId||'') ||
      !IDENTIFIER.test(tenant.ownerRecovery.ownerId||'')))
    stop('UNKNOWN_OWNER_RECOVERY_STATE');
  return tenant;
}
function pathFor(...items) { return PATH+'/'+items.map(x=>encodeURIComponent(x)).join('/'); }
async function api(fetchImpl,base,env,pathname,{method='GET',payload}={}) {
  if (!pathname.startsWith(PATH) || pathname.includes('..') || pathname.includes('\\') ||
      !['GET','PUT'].includes(method)) stop('UNSAFE_REMOTE_REQUEST');
  const url=new URL(pathname,base);
  if (url.origin!==base) stop('UNSAFE_REMOTE_ORIGIN');
  let response;
  try {
    response=await fetchImpl(url.href,{method,redirect:'error',signal:AbortSignal.timeout(12000),
      headers:{Authorization:'Basic '+Buffer.from(`${env.WSO2_ADMIN_USER}:${env.WSO2_ADMIN_PASSWORD}`).toString('base64'),
        Accept:'application/json', ...(method==='PUT'?{'Content-Type':'application/json'}:{})},
      ...(method==='PUT'?{body:JSON.stringify(payload)}:{})});
  } catch { stop(method==='PUT'?'WRITE_OUTCOME_UNCERTAIN':'READ_ONLY_NETWORK_FAILURE'); }
  if (method==='PUT') return {status:response.status};
  if (response.status!==200) stop(`READ_ONLY_HTTP_${response.status}`);
  let body;
  try { const text=await response.text(); if(text.length>65536) stop('REMOTE_JSON_TOO_LARGE'); body=JSON.parse(text); }
  catch { stop('REMOTE_JSON_INVALID'); }
  return body;
}
async function remoteIdentity(fetchImpl,base,env,tenant) {
  const list=await api(fetchImpl,base,env,PATH+'?limit=100&offset=0');
  if (!Array.isArray(list.tenants)) stop('TENANT_LIST_UNRECOGNIZED');
  const ts=list.tenants.filter(x=>x.domain===tenant.domain);
  if(ts.length!==1 || !IDENTIFIER.test(ts[0].id||'') || ts[0].lifecycleStatus?.activated!==true)
    stop('REMOTE_TENANT_NOT_UNIQUELY_ACTIVE');
  if(tenant.tenantId && ts[0].id!==tenant.tenantId) stop('REMOTE_TENANT_ID_CHANGED');
  const id=ts[0].id;
  const owners=await api(fetchImpl,base,env,pathFor(id,'owners'));
  if(!Array.isArray(owners) || owners.length!==1) stop('REMOTE_OWNERS_AMBIGUOUS');
  const owner=owners[0];
  if(owner.username!==tenant.owner.username || !IDENTIFIER.test(owner.id||'')) stop('REMOTE_OWNER_MISMATCH');
  if(tenant.ownerId && owner.id!==tenant.ownerId) stop('REMOTE_OWNER_ID_CHANGED');
  if(tenant.ownerRecovery && (tenant.ownerRecovery.tenantId!==id || tenant.ownerRecovery.ownerId!==owner.id))
    stop('PENDING_RECOVERY_REMOTE_IDENTIFIERS_DIFFER');
  const detail=await api(fetchImpl,base,env,pathFor(id,'owners',owner.id));
  if(detail.id!==owner.id || detail.username!==owner.username ||
     !['email','firstname','lastname'].every(k=>detail[k]===tenant.owner[k]))
    stop('REMOTE_OWNER_DETAILS_MISMATCH');
  return {tenantId:id,ownerId:owner.id};
}
function journalPath(root) { return join(privateDir(root),'owner-password-repair.private.json'); }
function rootJournalPath(root) { return join(privateDir(root),'tenant-brand.private.json'); }
function safeSummary(entry) { return entry?{state:entry.state,remoteWriteCount:entry.remoteWriteCount,
  browserAuthentication:'NOT_VERIFIED',previousRecoveryRetained:Boolean(entry.previousRecoveryPending)} :
  {state:'NOT_STARTED',remoteWriteCount:0,browserAuthentication:'NOT_VERIFIED'}; }

export async function execute({mode,brand,root=ROOT,env=process.env,fetchImpl=fetch,
  generatePassword=()=>randomBytes(24).toString('base64url')+'Aa1!'}={}) {
  if (!['status','check','apply'].includes(mode)) stop('UNKNOWN_MODE');
  if (mode!=='status' && !Object.hasOwn(DOMAINS,brand)) stop('UNKNOWN_BRAND');
  const file=journalPath(root);
  const repair=readPrivate(file,{optional:true});
  if (repair.value && (repair.value.schema!==SCHEMA || !obj(repair.value.tenants))) stop('REPAIR_JOURNAL_SCHEMA_INVALID');
  if (mode==='status') return {purpose:'OWNER_PASSWORD_REPAIR',
    aurora:safeSummary(repair.value?.tenants?.aurora),brisa:safeSummary(repair.value?.tenants?.brisa)};
  const local=readPrivate(rootJournalPath(root)).value;
  const tenant=verifyLocalOwner(local,brand);
  const base=validatedEnvironment(env,root);
  if (repair.value && repair.value.originHash!==createHash('sha256').update(base).digest('hex'))
    stop('JOURNAL_REMOTE_ORIGIN_MISMATCH');
  const existing=repair.value?.tenants?.[brand];
  if(existing && !['check'].includes(mode)) stop('PREVIOUS_RESET_INTENT_EXISTS_NO_RETRY');
  const remote=await remoteIdentity(fetchImpl,base,env,tenant);
  if(mode==='check') return {purpose:'OWNER_PASSWORD_REPAIR',brand,mode:'GET_ONLY',
    tenantConfirmed:true,ownerConfirmed:true,remoteWrites:0,pendingPreviousRecovery:Boolean(tenant.ownerRecovery),
    priorRepair:safeSummary(existing)};

  if(env.WSO2_OWNER_RESET_CONFIRM!==REPAIR_CONFIRM) stop('EXPLICIT_RESET_CONFIRMATION_REQUIRED');
  if(brand==='aurora' && tenant.ownerRecovery && env.WSO2_AURORA_PENDING_RECOVERY_CONFIRM!==AURORA_CONFIRM)
    stop('AURORA_PREVIOUS_RECOVERY_UNRESOLVED_EXPLICIT_OVERRIDE_REQUIRED');
  // Guard against two local processes concurrently issuing a PUT.
  const lock=join(privateDir(root),'.owner-password-repair.lock');
  let lockFd;
  try { lockFd=openSync(lock,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL,0o600); }
  catch { stop('REPAIR_LOCKED_OR_PREVIOUS_CRASH'); }
  try {
    const current=readPrivate(file,{optional:true});
    if(current.revision!==repair.revision) stop('REPAIR_JOURNAL_CHANGED');
    if(current.value?.tenants?.[brand]) stop('PREVIOUS_RESET_INTENT_EXISTS_NO_RETRY');
    const password=generatePassword();
    if(typeof password!=='string'||password.length<28||password.length>80||!/[A-Z]/.test(password)||
       !/[a-z]/.test(password)||!/[0-9]/.test(password)||!/[!_\-]/.test(password))
      stop('GENERATED_PASSWORD_POLICY_WEAK');
    const data=current.value ?? {schema:SCHEMA,originHash:createHash('sha256').update(base).digest('hex'),tenants:{}};
    let revision=current.revision;
    const entry={brand,domain:tenant.domain,tenantId:remote.tenantId,ownerId:remote.ownerId,
      ownerUsername:tenant.owner.username,password,previousRecoveryPending:Boolean(tenant.ownerRecovery),
      state:'WRITE_INTENT_RECORDED',remoteWriteCount:0,createdAt:new Date().toISOString()};
    data.tenants[brand]=entry;
    revision=durableWrite(file,data,revision);
    entry.state='WRITE_IN_FLIGHT';
    revision=durableWrite(file,data,revision); // journal BEFORE the network PUT
    let result;
    try {
      result=await api(fetchImpl,base,env,pathFor(remote.tenantId,'owners',remote.ownerId),{
        method:'PUT',payload:{password,email:tenant.owner.email,
          firstname:tenant.owner.firstname,lastname:tenant.owner.lastname}});
    } catch {
      entry.state='WRITE_OUTCOME_UNCERTAIN';
      entry.remoteWriteCount=1;
      durableWrite(file,data,revision);
      stop('OWNER_WRITE_OUTCOME_UNKNOWN_DO_NOT_RETRY');
    }
    entry.remoteWriteCount=1;
    entry.httpStatus=result.status;
    entry.state=result.status===200?'HTTP_200_ACKNOWLEDGED_NOT_AUTHENTICATED':'WRITE_OUTCOME_UNCERTAIN';
    revision=durableWrite(file,data,revision);
    if(result.status!==200) stop('OWNER_UPDATE_NOT_200_DO_NOT_RETRY');
    try {
      const reread=await remoteIdentity(fetchImpl,base,env,tenant);
      if(reread.tenantId!==remote.tenantId||reread.ownerId!==remote.ownerId)
        stop('OWNER_IDENTITY_CHANGED_AFTER_WRITE');
      entry.state='OWNER_READBACK_CONFIRMED_PASSWORD_UNVERIFIED';
      durableWrite(file,data,revision);
    } catch { /* HTTP 200 stays journaled, never blindly issue another PUT. */ }
    return {purpose:'OWNER_PASSWORD_REPAIR',brand,remoteWriteCount:1,
      state:entry.state,credentialLocation:'var/wso2/owner-password-repair.private.json',
      ownerRecoveryJournalUnchanged:true,browserAuthentication:'NOT_VERIFIED'};
  } finally {
    if(lockFd!==undefined) closeSync(lockFd);
    try { unlinkSync(lock); } catch {}
  }
}

export function copyPassword({brand,root=ROOT,copy=secret=>{
  const r=spawnSync('pbcopy',[],{input:secret,stdio:['pipe','ignore','ignore']});
  if(r.status!==0) stop('MACOS_CLIPBOARD_UNAVAILABLE');
}}={}) {
  if (!Object.hasOwn(DOMAINS,brand)) stop('UNKNOWN_BRAND');
  const data=readPrivate(journalPath(root)).value;
  if(data.schema!==SCHEMA) stop('REPAIR_JOURNAL_SCHEMA_INVALID');
  const item=data.tenants?.[brand];
  if(!item || !['HTTP_200_ACKNOWLEDGED_NOT_AUTHENTICATED','OWNER_READBACK_CONFIRMED_PASSWORD_UNVERIFIED'].includes(item.state) ||
     item.domain!==DOMAINS[brand] || typeof item.password!=='string')
    stop('NO_ACKNOWLEDGED_RESET_PASSWORD');
  copy(item.password);
  return {purpose:'OWNER_PASSWORD_REPAIR',brand,clipboard:'SET',
    browserAuthentication:'NOT_VERIFIED'};
}

const invoked=process.argv[1] && resolve(process.argv[1])===resolve(fileURLToPath(import.meta.url));
if(invoked) {
  const [mode,brand]=process.argv.slice(2);
  try {
    const result=mode==='clipboard' ? copyPassword({brand}) : await execute({mode,brand});
    process.stdout.write(JSON.stringify(result,null,2)+'\n');
  } catch(e) {
    const code=typeof e?.code==='string'&&/^[A-Z0-9_]{4,100}$/.test(e.code) ? e.code :
      typeof e?.message==='string'&&/^[A-Z0-9_]{4,100}$/.test(e.message) ? e.message : 'OWNER_REPAIR_FAILED_REDACTED';
    process.stderr.write('OWNER_REPAIR_STOP: '+code+'\n');
    process.exitCode=1;
  }
}
