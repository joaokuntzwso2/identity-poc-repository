import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const pre=JSON.parse(readFileSync('package.json','utf8')).scripts['prestart:bff'];
const script=readFileSync('scripts/ciam-v10.sh','utf8');
const steps=[
 'python3 scripts/p2/partner_v13.py ensure',
 'python3 scripts/p2/partner_access_v14.py status',
 'python3 scripts/p2/partner_business_plan_v15.py status',
 'python3 scripts/p2/partner_portal_v16_3.py bootstrap',
 'python3 scripts/p2/partner_share_v17_2.py bootstrap',
 'python3 scripts/p2/partner_directory_v18.py bootstrap',
 'node scripts/prepare-business-ledgers.mjs'];
test('V17.2 startup: exact authorized sequence, one calibrated gate and no old V17 writer',()=>{
 assert.deepEqual(pre.split(' && '),steps);
 assert.equal(pre.includes('partner_share_v17.py bootstrap'),false);
 const c='( cd "$REPO" && '+steps[4]+' )';
 assert.equal(script.split(c).length-1,1);
 assert.equal(script.includes('partner_share_v17.py bootstrap'),false);
 assert.ok(script.indexOf(steps[3])<script.indexOf(steps[4]));
 assert.ok(script.indexOf(steps[4])<script.indexOf('exec python3 "$REPO/deploy/ciam-v10/cli.py" "$@"'));
});
test('V17.2 only adds a same-tenant calibration; V17.0 POST payload and write-ahead remain pinned',()=>{
 const writer=readFileSync('scripts/p2/partner_share_v17.py','utf8');
 const gate=readFileSync('scripts/p2/partner_share_v17_2.py','utf8');
 assert.match(writer,/ROLE_MODE='NONE'/);
 assert.match(writer,/SELECTED_ORG_ONLY/);
 assert.match(writer,/exclusive_json\(file,template\)/);
 assert.match(gate,/positive_control\(/);
 assert.match(gate,/empty_portal_views\(/);
 assert.doesNotMatch(gate,/share-with-all/);
});
