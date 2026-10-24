/**
 * Narrow, auditable repair of a SINGLE journaled Aurora tenant-owner credential.
 * `--check`: GET only and prints safe evidence. `--apply`: one authorized PUT;
 * `--resume`: GET only, finalizes a previously successful PUT if the candidate works.
 * Never creates, deletes or adopts tenants. Does not print credentials or API bodies.
 * Requires NODE_EXTRA_CA_CERTS to be supplied before Node launches.
 */
import {randomBytes} from 'node:crypto';
import {readFileSync, writeFileSync, lstatSync, openSync, closeSync, fsyncSync, renameSync,
  unlinkSync, constants} from 'node:fs';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const fileDir=dirname(fileURLToPath(import.meta.url));
const repo=resolve(fileDir,'../..');
const defaultStateFile=join(repo,'var/wso2/tenant-brand.private.json');
const DOMAIN='aurora.identity.test';
const PATH='/api/server/v1/tenants';
const idPattern=/^[a-zA-Z0-9-]{1,128}$/;

function fail(code){const e=new Error(code);e.code=code;throw e;}

export function validate(state){
 const t=state?.tenants?.aurora;
 if(state?.schema!=='identity.wso2.tenant-brand.v1'||
    t?.owned!==true||t.domain!==DOMAIN||!['create-started','created'].includes(t.state)||
    !t.owner||t.owner.username!=='labtenantadmin'||
    typeof t.owner.password!=='string'||t.owner.password.length!==40||
    !['email','firstname','lastname'].every(k=>typeof t.owner[k]==='string'&&t.owner[k].length>0))
   fail('UNEXPECTED_JOURNAL_NO_CHANGE');
 if(t.ownerRecovery&&(
   t.ownerRecovery.state!=='update-started'||
   typeof t.ownerRecovery.candidatePassword!=='string'||
   t.ownerRecovery.candidatePassword.length!==28||
   !idPattern.test(t.ownerRecovery.tenantId||'')||
   !idPattern.test(t.ownerRecovery.ownerId||'')))
   fail('UNKNOWN_RECOVERY_STATE_NO_CHANGE');
 return t;
}

function makeBase(env){
 const url=new URL(env.WSO2_BASE_URL||'');
 if(url.protocol!=='https:'||!['localhost','127.0.0.1'].includes(url.hostname)||
    url.username||url.password||url.search||url.hash||url.pathname!=='/'||url.port!=='9443')
  fail('UNTRUSTED_WSO2_ORIGIN');
 if(env.NODE_TLS_REJECT_UNAUTHORIZED==='0')fail('TLS_VERIFICATION_DISABLED');
 if(!env.NODE_EXTRA_CA_CERTS)fail('LOCAL_CA_NOT_CONFIGURED');
 return url;
}

async function call(fetchImpl,base,path,username,password,opts={}){
 if(!path.startsWith('/')||path.startsWith('//')||path.includes('..')||path.includes('\\'))
  fail('INVALID_REQUEST_PATH');
 const method=opts.method||'GET';
 const url=new URL(path,base);
 if(url.origin!==base.origin)fail('UNTRUSTED_REQUEST_ORIGIN');
 let response;
 try{
  response=await fetchImpl(url.href,{
   method,redirect:'error',signal:AbortSignal.timeout(10000),
   headers:{Accept:'application/json',Authorization:'Basic '+Buffer.from(`${username}:${password}`,'utf8').toString('base64'),
    ...(method==='PUT'?{'Content-Type':'application/json'}:{})},
   ...(method==='PUT'?{body:JSON.stringify(opts.payload)}:{})
  });
 }catch{fail('NETWORK_OUTCOME_UNKNOWN_STOP');}
 if(method==='PUT')return {status:response.status};
 if(response.status!==200)return {status:response.status,data:null};
 try{const body=await response.text();if(body.length>65536)fail('RESPONSE_TOO_LARGE');
  return {status:response.status,data:JSON.parse(body)};
 }catch{fail('INVALID_GET_JSON_STOP');}
}

export async function runRecovery({mode,env,fetchImpl=fetch,loadState,saveState,generate=()=>randomBytes(21).toString('base64url')}={}){
 if(!['check','apply','resume'].includes(mode))fail('INVALID_MODE');
 const base=makeBase(env);
 if(!env.WSO2_ADMIN_USER||!env.WSO2_ADMIN_PASSWORD)fail('SUPER_ADMIN_REQUIRED');
 const {state,revision}=loadState();
 const tenant=validate(state);
 const auth=(path,opts)=>call(fetchImpl,base,path,env.WSO2_ADMIN_USER,env.WSO2_ADMIN_PASSWORD,opts);
 const found=await auth(PATH+'?limit=100&offset=0');
 if(found.status!==200||!Array.isArray(found.data?.tenants))fail('TENANT_LIST_UNAVAILABLE_STOP');
 const matches=found.data.tenants.filter(x=>x.domain===DOMAIN);
 if(matches.length!==1||!idPattern.test(matches[0].id||'')||
    matches[0].lifecycleStatus?.activated!==true)fail('TENANT_IDENTITY_UNVERIFIED_STOP');
 const tenantId=matches[0].id;
 const owners=await auth(`${PATH}/${encodeURIComponent(tenantId)}/owners`);
 if(owners.status!==200||!Array.isArray(owners.data))fail('OWNERS_UNAVAILABLE_STOP');
 const ownerMatches=owners.data.filter(x=>x.username===tenant.owner.username);
 if(owners.data.length!==1||ownerMatches.length!==1||!idPattern.test(ownerMatches[0].id||''))
  fail('OWNER_IDENTITY_MISMATCH_STOP');
 const ownerId=ownerMatches[0].id;
 const details=await auth(`${PATH}/${encodeURIComponent(tenantId)}/owners/${encodeURIComponent(ownerId)}`);
 if(details.status!==200||!details.data||details.data.username!==tenant.owner.username||
   !['email','firstname','lastname'].every(k=>details.data[k]===tenant.owner[k]))
  fail('OWNER_DETAILS_MISMATCH_STOP');
 const report={purpose:'AURORA_OWNER_RECOVERY',mode,tenantConfirmed:true,ownerConfirmed:true,
   journalState:tenant.state,recoveryState:tenant.ownerRecovery?.state||'NOT_STARTED',remoteWrites:0};
 if(mode==='check')return report;
 if(env.WSO2_LAB_CONFIRM!=='CREATE_SYNTHETIC_RESOURCES'||
    env.WSO2_OWNER_RECOVERY_CONFIRM!=='RESET_JOURNALED_AURORA_OWNER')
   fail('EXPLICIT_RECOVERY_CONFIRMATION_REQUIRED');
 let recovery=tenant.ownerRecovery;
 if(recovery){
  if(recovery.tenantId!==tenantId||recovery.ownerId!==ownerId)
   fail('RECOVERY_IDENTIFIERS_MISMATCH_STOP');
  if(mode==='apply')fail('UPDATE_ALREADY_ATTEMPTED_USE_RESUME');
 }else{
  if(mode==='resume')fail('NO_PENDING_RECOVERY');
  const candidate=generate();
  if(typeof candidate!=='string'||candidate.length!==28||!/^[A-Za-z0-9_-]{28}$/.test(candidate))
   fail('GENERATED_PASSWORD_INVALID');
  recovery={state:'update-started',candidatePassword:candidate,tenantId,ownerId};
  tenant.ownerRecovery=recovery;
  // Write the candidate before sending the one permitted PUT.
  saveState(state,revision);
  const updated=await auth(`${PATH}/${encodeURIComponent(tenantId)}/owners/${encodeURIComponent(ownerId)}`,{
   method:'PUT',payload:{password:candidate,email:tenant.owner.email,
    firstname:tenant.owner.firstname,lastname:tenant.owner.lastname}
  });
  if(updated.status!==200)fail('OWNER_UPDATE_NOT_FULLY_SUCCESSFUL_STOP');
  report.remoteWrites=1;
 }
 // Reconcile from a GET-only verified login; no repeat password change after uncertainty.
 const verified=await call(fetchImpl,base,
  `/t/${encodeURIComponent(DOMAIN)}/api/server/v1/applications?limit=1`,
  `${tenant.owner.username}@${DOMAIN}`,recovery.candidatePassword);
 if(verified.status!==200)fail('OWNER_LOGIN_NOT_VERIFIED_STOP');
 tenant.owner.password=recovery.candidatePassword;
 delete tenant.ownerRecovery;
 saveState(state,revision); // still create-started until normal bootstrap verifies
 report.recoveryState='AUTHENTICATED_AND_JOURNALED';
 report.ownerCredentialsVerified=true;
 return report;
}

function secureRead(filename){
 const st=lstatSync(filename);
 if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)!==0)
  fail('PRIVATE_JOURNAL_PERMISSIONS_UNSAFE');
 const raw=readFileSync(filename,'utf8');
 const state=JSON.parse(raw);
 return {state,revision:raw};
}
function secureWrite(filename,state,revision){
 if(readFileSync(filename,'utf8')!==revision)fail('JOURNAL_CHANGED_STOP');
 let temp=null, fd=null;
 try{
  temp=filename+`.recovery-${process.pid}-${randomBytes(8).toString('hex')}.tmp`;
  fd=openSync(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL,0o600);
  writeFileSync(fd,JSON.stringify(state,null,2)+'\n',{encoding:'utf8'});
  fsyncSync(fd);closeSync(fd);fd=null;
  if(readFileSync(filename,'utf8')!==revision)fail('JOURNAL_CHANGED_STOP');
  renameSync(temp,filename);temp=null;
 }finally{
  if(fd!==null)closeSync(fd);
  if(temp){try{unlinkSync(temp)}catch{}}
 }
}

const invoked=process.argv[1]&&resolve(process.argv[1])===resolve(fileURLToPath(import.meta.url));
if(invoked){
 const mode=(process.argv[2]||'').replace(/^--/,'');
 if(!['check','apply','resume'].includes(mode)){
  console.error('USAGE: recover-aurora-owner.mjs --check|--apply|--resume');
  process.exitCode=2;
 }else{
  let revision;
  try{
   const result=await runRecovery({mode,env:process.env,
    loadState:()=>{const x=secureRead(defaultStateFile);revision=x.revision;return x;},
    saveState:(s)=>{secureWrite(defaultStateFile,s,revision);revision=readFileSync(defaultStateFile,'utf8');}
   });
   console.log(JSON.stringify(result,null,2));
  }catch(e){
   const safe=typeof e?.code==='string'&&/^[A-Z][A-Z0-9_]{3,95}$/.test(e.code)?e.code:'RECOVERY_FAILED_NO_SENSITIVE_OUTPUT';
   console.error('AURORA_RECOVERY_ERROR:',safe);process.exitCode=1;
  }
 }
}
