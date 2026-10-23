import { readFile, writeFile } from 'node:fs/promises';
const file = process.argv[2];
if (!file) throw new Error('Usage: node scripts/load-requirements.mjs <source-requirements.json>');
const rows = JSON.parse(await readFile(file, 'utf8'));
if (rows.length !== 132) throw new Error(`Expected 132 RFP rows, received ${rows.length}`);
const out = rows.map(r => ({ id: r.id, block: r.block, requirement: r.requirement, acceptance: r.acceptance, priority: r.type, proposedResponse: r.response, minimumVersion: r.version, implementationStatus: 'NOT_VERIFIED', evidence: [], notes: 'RFP questionnaire draft response is NOT acceptance evidence' }));
await writeFile('config/rfp-132-traceability.json', JSON.stringify(out, null, 2));
console.log('Created 132-row unverified RFP traceability register.');
