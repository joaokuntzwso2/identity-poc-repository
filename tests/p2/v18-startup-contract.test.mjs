import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const pre=JSON.parse(readFileSync('package.json','utf8')).scripts['prestart:bff'];
const shell=readFileSync('scripts/ciam-v10.sh','utf8');
const steps=[
  'python3 scripts/p2/partner_v13.py ensure',
  'python3 scripts/p2/partner_access_v14.py status',
  'python3 scripts/p2/partner_business_plan_v15.py status',
  'python3 scripts/p2/partner_portal_v16_3.py bootstrap',
  'python3 scripts/p2/partner_share_v17_2.py bootstrap',
  'python3 scripts/p2/partner_directory_v18.py bootstrap',
  'node scripts/prepare-business-ledgers.mjs'];
test('V18 startup: V13 through V18 exactly once, before the original ledgers',()=>{
  assert.deepEqual(pre.split(' && '),steps);
  for(const step of steps)assert.equal(pre.split(step).length-1,1);
  assert.equal(pre.includes('partner_share_v17.py bootstrap'),false);
});
test('V18 launcher: only BFF, after V17.2, does not change original router',()=>{
  for(const step of steps.slice(0,-1)){
    assert.equal(shell.split('( cd "$REPO" && '+step+' )').length-1,1);
  }
  assert.ok(shell.indexOf('partner_share_v17_2.py bootstrap')<shell.indexOf('partner_directory_v18.py bootstrap'));
  assert.ok(shell.indexOf('partner_directory_v18.py bootstrap')<shell.indexOf('exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"'));
  assert.match(shell,/if \[\[ "\$\{1:-\}" == "bff-start" \]\]; then/);
  assert.doesNotMatch(shell,/share-with-all|carbon\.super|brisa\.identity\.test/);
});
