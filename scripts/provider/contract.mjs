import {spawnSync} from 'node:child_process';
const result=spawnSync(process.execPath,['--test','services/identity-bff/test/provider-adapter.test.mjs','scripts/provider/provider-structure.test.mjs'],{stdio:'inherit'});
if(result.error){console.error(result.error.message);process.exit(2)}
if(result.status!==0)process.exit(result.status||1);
console.log('OFFLINE_CONTRACT_TESTS_PASS — no WSO2 or customer live verification.');
