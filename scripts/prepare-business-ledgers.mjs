#!/usr/bin/env node
/** A guarded, explicitly non-identity pre-start initializer for npm run start:bff.
 * Must run BEFORE the live BFF, never during the read-only ciam:preflight.
 * No WSO2 or PostgreSQL connections are opened here.
 */
import { bootstrapBusinessLedgers } from './bootstrap-business-ledgers.mjs';

const backend = process.env.CIAM_CASES_BACKEND || 'jsonl';
try {
  if (backend === 'postgres') {
    // PostgreSQL business storage is provisioned by the separate migration CLI.
    // Do NOT create a second JSONL writer or an ambiguous fallback.
    console.log('BUSINESS_LEDGER_PRESTART: postgres backend; JSONL initialization skipped');
  } else if (backend === 'jsonl') {
    const result = bootstrapBusinessLedgers(process.env);
    // No raw event content, subjects, or private file records in log output.
    console.log(JSON.stringify({event:'BUSINESS_LEDGER_PRESTART',
      brands:result.ledgers.map(({brand,result:state,cases,events})=>({brand,result:state,cases,events}))}));
  } else {
    throw new Error('UNSUPPORTED_CIAM_CASES_BACKEND');
  }
} catch (error) {
  console.error(`BUSINESS_LEDGER_PRESTART_FAILED: ${error.message}`);
  process.exitCode = 1;
}
