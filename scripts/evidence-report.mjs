import { readFile, writeFile, mkdir } from 'node:fs/promises';
const now = new Date().toISOString();
const r = JSON.parse(await readFile('config/rfp-132-traceability.json', 'utf8'));
const scenarios = JSON.parse(await readFile('config/scenario-catalog.json', 'utf8'));
if (r.length !== 132) throw new Error('RFP coverage register is incomplete');
if (r.some(x => x.implementationStatus !== 'NOT_VERIFIED')) throw new Error('Template must not contain fabricated verified status');
const response = { generatedAt: now, product: 'WSO2 Identity Server 7.3', runtimeStatus: 'NOT_EXECUTED', summary: { requirements: r.length, verified: 0, unverified: r.length, scenarios: scenarios.length, mandatoryScenarios: scenarios.filter(x => x.id.startsWith('M-02.')).length }, requirements: r.map(({ id, block, priority, implementationStatus }) => ({ id, block, priority, implementationStatus })), disclaimer: 'Static evidence inventory only. Runtime pass/fail must be imported from signed/hashed executions performed against WSO2.' };
await mkdir('evidence', { recursive: true }); await writeFile('evidence/acceptance-baseline.json', JSON.stringify(response, null, 2));
console.log(JSON.stringify(response.summary));
