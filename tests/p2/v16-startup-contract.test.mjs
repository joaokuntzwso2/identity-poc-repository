import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const repo=resolve(import.meta.dirname,'../..');
const pkg=JSON.parse(readFileSync(resolve(repo,'package.json'),'utf8'));
const router=readFileSync(resolve(repo,'scripts/ciam-v10.sh'),'utf8');
const commands=[
'python3 scripts/p2/partner_v13.py ensure',
'python3 scripts/p2/partner_access_v14.py status',
'python3 scripts/p2/partner_business_plan_v15.py status',
'python3 scripts/p2/partner_portal_v16_3.py bootstrap',
 'python3 scripts/p2/partner_share_v17_2.py bootstrap',
 'python3 scripts/p2/partner_directory_v18.py bootstrap'];
test('npm BFF bootstrap runs V13 V14 V15 then V16 exactly once before ledgers',()=>{
  assert.equal(pkg.scripts['prestart:bff'],commands.join(' && ')+' && node scripts/prepare-business-ledgers.mjs');
  for(const command of commands)assert.equal(pkg.scripts['prestart:bff'].split(command).length-1,1);
  assert.ok(!pkg.scripts['ciam:preflight'].includes('partner_portal_v16.py'));
});
test('v10 BFF bootstrap also runs V16 once after the read-only gates',()=>{
  let last=-1;
  for(const command of commands){
    const instance='( cd "$REPO" && '+command+' )';
    assert.equal(router.split(instance).length-1,1);
    const i=router.indexOf(instance);
    assert.ok(i>last);last=i;
  }
  assert.ok(last<router.indexOf('exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"'));
  assert.ok(router.includes('if [[ "${1:-}" == "bff-start" ]]; then\n  ( cd "$REPO" && '+commands.at(-1)+' )\nfi'));
});
