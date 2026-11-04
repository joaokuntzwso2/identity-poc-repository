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
test('V16.1 BFF gate retains V13 V14 V15 and ledger ordering exactly once',()=>{
 const expected=commands.join(' && ')+' && node scripts/prepare-business-ledgers.mjs';
 assert.equal(pkg.scripts['prestart:bff'],expected);
 for(const c of commands)assert.equal(pkg.scripts['prestart:bff'].split(c).length-1,1);
 assert.ok(!pkg.scripts['ciam:preflight'].includes('partner_portal_v16_1.py'));
});
test('V16.1 v10 launcher gates only BFF, before original router',()=>{
 let last=-1;
 for(const c of commands){
  const instance='( cd "$REPO" && '+c+' )';
  assert.equal(router.split(instance).length-1,1);
  let next=router.indexOf(instance);assert.ok(next>last);last=next;
 }
 assert.ok(last<router.indexOf('exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"'));
 assert.equal(router.includes('partner_portal_v16.py ensure'),false);
});
