import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const repo = resolve(import.meta.dirname, '../..');
const pkg = JSON.parse(readFileSync(resolve(repo, 'package.json'), 'utf8'));
const expectedFirst = 'python3 scripts/p2/partner_v13.py ensure';
const expectedLast = 'node scripts/prepare-business-ledgers.mjs';
const script = readFileSync(resolve(repo, 'scripts/ciam-v10.sh'), 'utf8');

test('npm BFF prestart: V13 ensure runs once before original business ledgers', () => {
  const steps = pkg.scripts['prestart:bff'].split(' && ');
  assert.equal(steps[0], expectedFirst);
  assert.equal(steps.at(-1), expectedLast);
  assert.equal(steps.filter(step => step === expectedFirst).length, 1);
  assert.equal(steps.filter(step => step === expectedLast).length, 1);
  assert.ok(typeof pkg.scripts['start:bff'] === 'string' && pkg.scripts['start:bff'].length > 0);
  assert.ok(existsSync(resolve(repo, 'scripts/p2/partner_v13.py')));
  assert.equal(pkg.scripts['prestart:bff'].split('partner_v13.py ensure').length - 1, 1);
});

test('v10 bff-start: the same V13 gate is invoked before the original router', () => {
  const mark = '# P2.24 V13: one-time approved Aurora partner initialization.';
  const ensure = '( cd "$REPO" && python3 scripts/p2/partner_v13.py ensure )';
  const original = 'exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"';
  assert.equal(script.split(mark).length - 1, 1);
  assert.equal(script.split(ensure).length - 1, 1);
  assert.equal(script.split(original).length - 1, 1);
  assert.ok(script.includes('if [[ "${1:-}" == "bff-start" ]]; then'));
  assert.ok(script.indexOf(ensure) < script.indexOf(original));
  assert.ok(!pkg.scripts['ciam:preflight'].includes('partner_v13.py'));
});
