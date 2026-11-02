/** Strict, read-only JSONL decoder. Never rewrites or truncates source files. */
import { readFileSync } from 'node:fs';
import { resolve, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
export const BRANDS = Object.freeze(['aurora', 'brisa']);
export const sha256 = data => createHash('sha256').update(data).digest('hex');
const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function ledgerFile(dir, brand) {
  if (!BRANDS.includes(brand) || !isAbsolute(dir || '')) throw new Error('INVALID_LEDGER_LOCATION');
  return resolve(dir, `requests-${brand}.jsonl`);
}
export function actorFingerprint(issuer, subject) {
  if (typeof issuer !== 'string' || !issuer || issuer.length > 1024 ||
      typeof subject !== 'string' || !subject || subject.length > 1024)
    throw new Error('INVALID_ACTOR');
  return sha256(JSON.stringify([issuer, subject]));
}
export function parseLedgerBuffer(buffer, brand) {
  if (!BRANDS.includes(brand) || !Buffer.isBuffer(buffer) || buffer.length > 10 * 1024 * 1024)
    throw new Error('INVALID_LEDGER_BUFFER');
  const text = new TextDecoder('utf-8', {fatal: true}).decode(buffer);
  if (text.length && !text.endsWith('\n')) throw new Error('LEDGER_TRUNCATED_LINE');
  const lines = text.split('\n').slice(0, -1);
  const records = new Map(), events = [];
  for (const [index, line] of lines.entries()) {
    if (!line.trim()) throw new Error(`LEDGER_EMPTY_LINE:${brand}:${index + 1}`);
    let value;
    try { value = JSON.parse(line); } catch { throw new Error(`LEDGER_INVALID_JSON:${brand}:${index + 1}`); }
    if (!value || typeof value !== 'object' || value.brand !== brand || !UUID.test(value.id || '') ||
        !HEX.test(value.actor || '') || !Number.isFinite(Date.parse(value.at)) ||
        new Date(value.at).toISOString() !== value.at)
      throw new Error(`LEDGER_INVALID_EVENT:${brand}:${index + 1}`);
    const prior = records.get(value.id);
    if (value.action === 'created') {
      if (prior || typeof value.title !== 'string' || value.title !== value.title.trim() ||
          value.title.length < 3 || value.title.length > 120 ||
          typeof value.description !== 'string' || value.description.length > 1000)
        throw new Error(`LEDGER_INVALID_CREATION:${brand}:${index + 1}`);
      records.set(value.id, {id:value.id,brand,title:value.title,description:value.description,
        owner:value.actor,createdAt:value.at,status:'OPEN',approvedAt:null,approvedBy:null});
      events.push({id:value.id, sequence:1, position:index+1, action:'created',actor:value.actor,at:value.at});
    } else if (value.action === 'approved') {
      if (!prior || prior.status !== 'OPEN' || prior.owner === value.actor ||
          Date.parse(value.at) < Date.parse(prior.createdAt))
        throw new Error(`LEDGER_INVALID_APPROVAL:${brand}:${index + 1}`);
      prior.status = 'APPROVED'; prior.approvedAt = value.at; prior.approvedBy = value.actor;
      events.push({id:value.id, sequence:2, position:index+1, action:'approved',actor:value.actor,at:value.at});
    } else throw new Error(`LEDGER_UNKNOWN_ACTION:${brand}:${index + 1}`);
  }
  return {brand,sha256:sha256(buffer),bytes:buffer.length,records:[...records.values()],events};
}
export function readLegacyLedger(dir, brand) {
  return parseLedgerBuffer(readFileSync(ledgerFile(dir, brand)),brand);
}
export function inventoryLedgers(dir) {
  const ledgers = BRANDS.map(b => readLegacyLedger(dir,b));
  return {ledgers, fingerprint:sha256(ledgers.map(x=>`${x.brand}:${x.sha256}:${x.records.length}:${x.events.length}`).join('|'))};
}
