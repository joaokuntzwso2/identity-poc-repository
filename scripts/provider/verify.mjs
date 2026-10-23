#!/usr/bin/env node
import {resolveConfig,Wso2ProviderAdapter,issuerFingerprint,MODES,safeStatus} from '../../services/identity-bff/src/provider/core.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
const c=resolveConfig();
if(c.mode!==MODES.LIVE||!c.configured){
 console.error('NOT_READY: live-wso2 mode and complete trusted configuration are required.');
 console.error('Missing:',c.missing.join(', ')||'(mode must be live-wso2)');process.exit(2);
}
try{
 const discovery=await new Wso2ProviderAdapter(c).discover();
 const report={schema:'identity.provider.discovery-evidence.v1',source:'REAL_DISCOVERY_ONLY',
  issuerFingerprint:issuerFingerprint(c.issuer),discovery,oidcClientsConfigured:4,
  pairwiseTokenVerification:'NOT_TESTED',login:'NOT_TESTED',consent:'NOT_TESTED',
  actorAwareExchange:'NOT_TESTED',liveAcceptance:'NOT_VERIFIED'};
 const dest=resolve('var/provider-readiness.json');mkdirSync(resolve('var'),{recursive:true});
 writeFileSync(dest,JSON.stringify(report,null,2)+'\n',{mode:0o600});
 console.log('DISCOVERY_VERIFIED_ONLY; live acceptance remains NOT_VERIFIED.');
 console.log(`Provider readiness: ${dest}`);
 if(!discovery.pairwiseAdvertised){console.error('Pairwise is not advertised in discovery; topology gate remains blocked.');process.exitCode=3}
}catch(e){console.error('PROVIDER_DISCOVERY_FAILED:',e.code||e.message);process.exitCode=2}
