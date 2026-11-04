import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const command='python3 scripts/p2/partner_portal_v16_3.py bootstrap';
const base='python3 scripts/p2/partner_v13.py ensure && python3 scripts/p2/partner_access_v14.py status && python3 scripts/p2/partner_business_plan_v15.py status';
test('npm startup runs V13 V14 V15 V16.3 once in order, then ledger initialization',()=>{
  const p=JSON.parse(readFileSync('package.json','utf8'));
  assert.equal(p.scripts['prestart:bff'],`${base} && ${command} && python3 scripts/p2/partner_share_v17_2.py bootstrap && python3 scripts/p2/partner_directory_v18.py bootstrap && node scripts/prepare-business-ledgers.mjs`);
});
test('v10 bootstrap runs same exact gate before the original routing command',()=>{
  const content=readFileSync('scripts/ciam-v10.sh','utf8');
  assert.equal(content.split(command).length-1,1);
  assert.match(content,/if \[\[ "\$\{1:-\}" == "bff-start" \]\]; then/);
  assert.match(content,/exec python3 "\$REPO\/deploy\/ciam-v10\/cli.py" "\$@"/);
});
test('legacy v16.1 bootstrap does not remain in supported startup paths',()=>{
  for(const p of ['package.json','scripts/ciam-v10.sh']) {
    const content=readFileSync(p,'utf8');
    assert.doesNotMatch(content,/partner_portal_v16_1\.py bootstrap/);
  }
});
test('new portal OIDC handler is actually dispatched before old four-channel pattern',()=>{
  const source=readFileSync('services/identity-bff/src/server.js','utf8');
  assert.match(source,/from '\.\/partner-portal-route\.js'/);
  const a=source.indexOf('await handlePartnerPortalAuth(');
  const b=source.indexOf('const login = /^\\/auth\\/(aurora|brisa)');
  assert.ok(a>0 && b>a);
});
