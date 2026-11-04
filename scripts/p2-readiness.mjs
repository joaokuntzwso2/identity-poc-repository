#!/usr/bin/env node
/** Read-only P2 fact gathering. Auth token, cookies, private claims are never requested. */
import { capabilityMatrix,parseVerifiedVersion } from './p2-capability-core.mjs';
const tenants=['aurora.identity.test','brisa.identity.test'];
const host='https://localhost:9444';
async function probe(url, expectedIssuer) {
  try {
    const r=await fetch(url,{redirect:'manual',signal:AbortSignal.timeout(5000),headers:{accept:'application/json'}});
    if(r.status!==200) return {state:'UNVERIFIED',http:r.status};
    const body=await r.text();if(body.length>131072)return {state:'UNVERIFIED',reason:'response_oversize'};
    const parsed=JSON.parse(body);
    return {state:parsed.issuer===expectedIssuer?'VERIFIED_DISCOVERY_ISSUER_ONLY':'ISSUER_MISMATCH',
      issuerMatches:parsed.issuer===expectedIssuer};
  } catch {return {state:'UNAVAILABLE_OR_TLS_UNTRUSTED'};}
}
async function main() {
  const arg=process.argv.find(x=>x.startsWith('--asserted-version='));
  const version=arg?parseVerifiedVersion(arg.slice(19)):null;
  if(arg&&!version)throw new Error('expected --asserted-version=7.3.0 or 7.3.0.<update>');
  const discovery={};
  for(const tenant of tenants) {
    const issuer=`${host}/t/${tenant}/oauth2/token`;
    const attempts=[
      `${host}/t/${tenant}/oauth2/token/.well-known/openid-configuration`,
      `${host}/t/${tenant}/oauth2/oidcdiscovery/.well-known/openid-configuration`
    ];
    let result={state:'UNVERIFIED'};
    for(const url of attempts) {
      const found=await probe(url,issuer);
      if(found.state==='VERIFIED_DISCOVERY_ISSUER_ONLY'){result=found;break;}
      result=found;
    }
    discovery[tenant]=result;
  }
  let bff;
  try {
    const r=await fetch('http://127.0.0.1:4400/api/wso2-status',{signal:AbortSignal.timeout(3000),redirect:'manual'});
    bff={state:r.status===200?'RESPONDING':'UNVERIFIED',http:r.status};
  } catch {bff={state:'UNAVAILABLE'};}
  const report={phase:'P2.24–P2.31',assessmentType:'READ_ONLY_NO_MUTATIONS',
    recordedAt:new Date().toISOString(),versionAssertion:version||'NOT_PROVIDED',
    versionEvidence:'OIDC_DISCOVERY_DOES_NOT_ATTEST_WSO2_PRODUCT_UPDATE_LEVEL',
    discovery,bff,capabilities:capabilityMatrix(version),liveAcceptance:'NOT_EXECUTED'};
  console.log(JSON.stringify(report,null,2));
  if(Object.values(discovery).some(x=>x.state!=='VERIFIED_DISCOVERY_ISSUER_ONLY'))process.exitCode=2;
}
if(import.meta.url===`file://${process.argv[1]}`)main().catch(e=>{console.error(e.message);process.exitCode=1;});
