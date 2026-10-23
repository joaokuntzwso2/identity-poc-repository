/** Evidence-first release gate. This script does not infer PASS from source code or statuses. */
import {readFile,writeFile,mkdir,realpath} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import {createHash} from 'node:crypto';
const requireReady=process.argv.includes('--require-ready');
const rows=JSON.parse(await readFile('config/rfp-132-traceability.json','utf8'));
if(rows.length!==132 || new Set(rows.map(x=>x.id)).size!==132)throw new Error('REQUIREMENT_MATRIX_INVALID: expected 132 unique IDs');
const eliminatory=rows.filter(x=>x.priority==='ELIMINATÓRIO');
if(eliminatory.length!==19)throw new Error(`ELIMINATORY_MATRIX_INVALID: expected 19; got ${eliminatory.length}`);
const scenarios=JSON.parse(await readFile('config/scenario-catalog.json','utf8'));
const expected=['M-02.1','M-02.2','M-02.3','M-02.4','M-02.5','M-02.6','M-02.7'];
for(const id of expected)if(!scenarios.some(s=>s.id===id))throw new Error(`REQUIRED_DEMO_MISSING: ${id}`);
let results={};
try {results=JSON.parse(await readFile('evidence/identity/attested-results.json','utf8'));}
catch(e){if(e.code!=='ENOENT')throw e;}
const valid=new Set(['PASS','FAIL','BLOCKED','NOT_RUN','DOCUMENTARY_PENDING']);
const root=await realpath('.');
async function verifyArtifact(a){
 if(typeof a?.path!=='string'||typeof a?.sha256!=='string'||!/^[a-f0-9]{64}$/.test(a.sha256))return false;
 const candidate=resolve(root,a.path);
 if(!relative(root,candidate) || relative(root,candidate).startsWith('..'+sep) || candidate===root)return false;
 try {
  const actual=await realpath(candidate);
  if(relative(root,actual).startsWith('..'+sep)||actual===root)return false;
  const data=await readFile(actual);if(data.length>32*1024*1024)return false;
  return createHash('sha256').update(data).digest('hex')===a.sha256;
 }catch{return false;}
}
const report=[];
for(const r of rows){
 const att=results[r.id];let status='NOT_RUN';let evidenceValid=false;
 if(att){
  if(!valid.has(att.status))throw new Error(`INVALID_STATUS: ${r.id}`);
  status=att.status;
  if(status==='PASS'){
   // Manual attestation alone is not enough; the evidence must be a real file with a verified digest.
   evidenceValid=Boolean(att.reviewer && att.executedAt && Array.isArray(att.artifacts) && att.artifacts.length>0);
   if(evidenceValid){for(const a of att.artifacts)if(!await verifyArtifact(a))evidenceValid=false;}
   if(!evidenceValid)status='BLOCKED';
  }
 }
 report.push({id:r.id,priority:r.priority,classification:r.proposedResponse,
  status,evidenceValid,source:'original_repo_traceability',note:status==='NOT_RUN'?'No independent customer acceptance execution attested':undefined});
}
const mandatory=report.filter(x=>x.priority==='ELIMINATÓRIO');
const open=mandatory.filter(x=>x.status!=='PASS');
const output={generatedAt:new Date().toISOString(),
  rule:'Do not present as compliant with any ELIMINATÓRIO not independently proven',
  matrixTotal:132,eliminatoryCount:19,demosExpected:expected,
  verified:report.filter(x=>x.status==='PASS').length,eliminatoryOpen:open.map(x=>x.id),
  overall:open.length?'NOT_READY':'DOCUMENTARY_REVIEW_REQUIRED',requirements:report};
await mkdir('evidence/identity',{recursive:true});
await writeFile('evidence/identity/release-gates.json',JSON.stringify(output,null,2)+'\n',{mode:0o600});
console.log(`IDENTITY_RELEASE_GATE: ${output.overall}; verified=${output.verified}/132; eliminatory_open=${open.length}/19`);
console.log(`Evidence: evidence/identity/release-gates.json`);
if(requireReady && open.length)process.exitCode=2;
