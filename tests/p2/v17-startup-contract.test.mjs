import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const pre=JSON.parse(readFileSync('package.json','utf8')).scripts['prestart:bff'];
const router=readFileSync('scripts/ciam-v10.sh','utf8');
const steps=[
 'python3 scripts/p2/partner_v13.py ensure',
 'python3 scripts/p2/partner_access_v14.py status',
 'python3 scripts/p2/partner_business_plan_v15.py status',
 'python3 scripts/p2/partner_portal_v16_3.py bootstrap',
 'python3 scripts/p2/partner_share_v17_2.py bootstrap',
 'python3 scripts/p2/partner_directory_v18.py bootstrap',
 'node scripts/prepare-business-ledgers.mjs'];
test('npm BFF prestart keeps V13-V17 exact order with one V17 stage',()=>{
 assert.deepEqual(pre.split(' && '),steps);
 assert.equal(pre.split('partner_share_v17_2.py bootstrap').length-1,1);
});
test('v10 launcher runs V17 only under bff-start, after V16.3',()=>{
 const a='( cd "$REPO" && python3 scripts/p2/partner_portal_v16_3.py bootstrap )';
 const b='( cd "$REPO" && python3 scripts/p2/partner_share_v17_2.py bootstrap )';
 const end='exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"';
 assert.equal(router.split(a).length-1,1);
 assert.equal(router.split(b).length-1,1);
 assert.ok(router.indexOf(a)<router.indexOf(b) && router.indexOf(b)<router.indexOf(end));
 assert.match(router,/if \[\[ "\$\{1:-\}" == "bff-start" \]\]; then\n  \( cd "\$REPO" && python3 scripts\/p2\/partner_share_v17_2\.py bootstrap \)\nfi/);
});
test('V17 hook cannot redirect to global share or grant roles',()=>{
 const source=readFileSync('scripts/p2/partner_share_v17.py','utf8');
 assert.match(source,/SELECTED_ORG_ONLY/);
 assert.match(source,/ROLE_MODE='NONE'/);
 assert.match(source,/JOURNAL=/);
 assert.doesNotMatch(pre,/share-with-all/);
});
