import {readFile,access} from 'node:fs/promises';
import {discover} from '../../services/identity-bff/src/oidc.js';
import {clients} from '../../services/identity-bff/src/config.js';
const expected=['aurora-web','aurora-app','brisa-web','brisa-app'];
const failures=[];
for(const name of expected){
 const c=clients[name];
 if(!c?.clientId||!c?.issuer){failures.push(`${name}: MISSING_CLIENT_ID_OR_ISSUER`);continue;}
 try{
  const doc=await discover(c.issuer);
  if(!(doc.subject_types_supported||[]).includes('pairwise'))failures.push(`${name}: DISCOVERY_DOES_NOT_ADVERTISE_PAIRWISE`);
  else console.log(`DISCOVERY_CHECKED ${name}: ${doc.issuer}`);
 }catch(e){failures.push(`${name}: DISCOVERY_ERROR ${e.message}`);}
}
for(const b of ['AURORA','BRISA']){
 const uri=process.env[`SECTOR_${b}_URI`];
 if(!uri||!uri.startsWith('https://'))failures.push(`SECTOR_${b}_URI requires real public HTTPS document`);
}
if(!process.env.WSO2_BUILD_ATTESTATION_FILE)failures.push('Missing WSO2_BUILD_ATTESTATION_FILE (independent version/update provenance)');
else {try{await access(process.env.WSO2_BUILD_ATTESTATION_FILE);}catch{failures.push('WSO2_BUILD_ATTESTATION_FILE is unreadable');}}
console.log(JSON.stringify({phase:'PHASE1_CONFIGURATION_ONLY',verifiedLivePairwise:false,verifiedCanonicalIdentity:false,verifiedTenantIsolation:false,issues:failures},null,2));
if(failures.length)process.exitCode=2;
