/** Regression: the default JSONL BFF must boot when isolated fixtures lack pg. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = resolve(fileURLToPath(import.meta.url), '..');

test('JSONL startup can import business-db without installing pg in isolated fixture', () => {
  const dir = mkdtempSync(join(tmpdir(), 'p117-no-pg-'));
  try {
    writeFileSync(join(dir, 'package.json'), '{"type":"module"}');
    for (const name of ['business-db.js', 'business-ledger.js']) {
      copyFileSync(resolve(here, '../src', name), join(dir, name));
    }
    const entry = pathToFileURL(join(dir, 'business-db.js')).href;
    const code = `import {businessPool, BusinessError} from ${JSON.stringify(entry)};
      try { businessPool({}); process.exitCode = 42; }
      catch (e) { if (!(e instanceof BusinessError) ||
        e.code !== 'business_database_not_configured') throw e; }`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
      cwd: dir, encoding: 'utf8', timeout: 5000,
      env: { ...process.env, CIAM_BUSINESS_DATABASE_URL: '' }
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
