import { readFile } from 'node:fs/promises';
if (!process.env.IDENTITY_CONSENT_DATABASE_URL) throw new Error('Set IDENTITY_CONSENT_DATABASE_URL before migration');
if (process.env.NODE_ENV === 'production' && !process.env.IDENTITY_PG_SSL_CA_FILE) throw new Error('TLS CA required');
const { Pool } = await import('pg');
const pool = new Pool({ connectionString: process.env.IDENTITY_CONSENT_DATABASE_URL, max: 1, ...(process.env.NODE_ENV === 'production' ? { ssl: { ca: await readFile(process.env.IDENTITY_PG_SSL_CA_FILE, 'utf8'), rejectUnauthorized: true } } : {}) });
try {
  const sql = await readFile(new URL('../../db/identity/001_consent_ledger.sql', import.meta.url), 'utf8');
  await pool.query(sql);
  const r = await pool.query(`SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema='identity_poc'`);
  if (r.rows[0].n < 2) throw new Error('Schema incomplete');
  console.log('IDENTITY_DURABLE_CONSENT_SCHEMA_READY');
} finally { await pool.end(); }
