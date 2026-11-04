import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const repo=resolve(import.meta.dirname,'../..');
const pkg=JSON.parse(readFileSync(resolve(repo,'package.json'),'utf8'));
const router=readFileSync(resolve(repo,'scripts/ciam-v10.sh'),'utf8');
const v13='python3 scripts/p2/partner_v13.py ensure';
const v14='python3 scripts/p2/partner_access_v14.py status';
const v15='python3 scripts/p2/partner_business_plan_v15.py status';
const v16='python3 scripts/p2/partner_portal_v16_3.py bootstrap';
test('BFF startup: V13 verification, V14 sharing inspection, V15 read-only crosscheck, ledgers',()=>{
  assert.equal(pkg.scripts['prestart:bff'],`${v13} && ${v14} && ${v15} && ${v16} && python3 scripts/p2/partner_share_v17_2.py bootstrap && python3 scripts/p2/partner_directory_v18.py bootstrap && node scripts/prepare-business-ledgers.mjs`);
  assert.equal(pkg.scripts['prestart:bff'].split(v15).length-1,1);
  assert.ok(!pkg.scripts['ciam:preflight'].includes('partner_business_plan_v15.py'));
});
test('v10 startup: V15 is restricted to BFF and executed once after V14',()=>{
  const a='( cd "$REPO" && '+v13+' )';
  const b='( cd "$REPO" && '+v14+' )';
  const c='( cd "$REPO" && '+v15+' )';
  const end='exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"';
  for(const s of [a,b,c]) assert.equal(router.split(s).length-1,1);
  assert.ok(router.indexOf(a)<router.indexOf(b));
  assert.ok(router.indexOf(b)<router.indexOf(c));
  assert.ok(router.indexOf(c)<router.indexOf(end));
  assert.ok(router.includes('if [[ "${1:-}" == "bff-start" ]]; then\n  '+c+'\nfi'));
});
