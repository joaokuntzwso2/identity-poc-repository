#!/usr/bin/env python3
"""Static zero-fixture release gate; also execute live HTTP and browser tests."""
from pathlib import Path
import json,sys,re
root=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
files={
 'apps/experience-center/src/main.tsx': ['personas.json','setPersonaId','setCheckout','AUR-24019'],
 'services/identity-bff/src/server.js': ['new ConsentLedger(', 'profile:self:read', 'synthetic-preview-not-authoritative', 'return reply(res, 200, JSON.parse(await readFile(fixturePath'],
 'services/identity-bff/src/live-brand-v3.js': ['personas.json','customer-ana', 'marcos.oliveira','setPersonaId','localStorage','sessionStorage'],
}
issues=[]
for rel, phrases in files.items():
 f=root/rel
 if not f.is_file(): issues.append({'file':rel,'problem':'missing'});continue
 content=f.read_text()
 for phrase in phrases:
  if phrase in content: issues.append({'file':rel,'problem':'synthetic pattern found: '+phrase})
if (root/'apps/experience-center/src/data/personas.json').exists():
 issues.append({'file':'apps/experience-center/src/data/personas.json','problem':'synthetic identity fixture still present'})
server=(root/'services/identity-bff/src/server.js')
if server.exists() and "if (process.env.IDENTITY_MODE !== 'live-wso2')" not in server.read_text():
 issues.append({'file':str(server),'problem':'live-only startup guard missing'})
print(json.dumps({'stage':'ZERO_MOCK_SOURCE_GATE_V3', 'result':'FAIL' if issues else 'PASS_STATIC_ONLY',
  'issues':issues, 'runtimeVerification':'REQUIRED: negative tests, positive WSO2 login, userinfo, tenant isolation, MFA and RBAC if enabled'},indent=2))
raise SystemExit(bool(issues))
