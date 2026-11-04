import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
const repo=resolve(import.meta.dirname,'../..');
const pkg=JSON.parse(readFileSync(resolve(repo,'package.json'),'utf8'));
const router=readFileSync(resolve(repo,'scripts/ciam-v10.sh'),'utf8');
const old='python3 scripts/p2/partner_v13.py ensure';
const probe='python3 scripts/p2/partner_access_v14.py status';
const cross='python3 scripts/p2/partner_business_plan_v15.py status';
const portal='python3 scripts/p2/partner_portal_v16_3.py bootstrap';
test('BFF startup: verified V13 first, then V14 sharing inspection, then original ledger preparation',()=>{
  assert.equal(pkg.scripts['prestart:bff'],old+' && '+probe+' && '+cross+' && '+portal+' && python3 scripts/p2/partner_share_v17_2.py bootstrap && python3 scripts/p2/partner_directory_v18.py bootstrap && node scripts/prepare-business-ledgers.mjs');
  assert.ok(existsSync(resolve(repo,'scripts/p2/partner_v13.py')));
  assert.ok(existsSync(resolve(repo,'scripts/p2/partner_access_v14.py')));
  assert.equal(pkg.scripts['prestart:bff'].split(probe).length-1,1);
  assert.ok(!pkg.scripts['ciam:preflight'].includes('partner_access_v14.py'));
});
test('v10 BFF startup path includes both gates, in order, and leaves non-BFF commands unchanged',()=>{
  const first='( cd "$REPO" && python3 scripts/p2/partner_v13.py ensure )';
  const second='( cd "$REPO" && python3 scripts/p2/partner_access_v14.py status )';
  const routerExec='exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"';
  assert.equal(router.split(first).length-1,1);
  assert.equal(router.split(second).length-1,1);
  assert.ok(router.indexOf(first)<router.indexOf(second) && router.indexOf(second)<router.indexOf(routerExec));
  assert.ok(router.includes('if [[ "${1:-}" == "bff-start" ]]; then'));
});
