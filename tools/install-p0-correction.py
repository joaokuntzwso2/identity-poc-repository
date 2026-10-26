#!/usr/bin/env python3
"""Source-only, fail-before-write corrective overlay for inspected main layout.
Must run from Git checkout after unpacking bundle; never accesses private state.
"""
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path.cwd().resolve()
if subprocess.run(['git','rev-parse','--show-toplevel'],capture_output=True,text=True).stdout.strip()!=str(ROOT):
    raise SystemExit('STOP: run at Git checkout root')
if subprocess.run(['git','branch','--show-current'],capture_output=True,text=True).stdout.strip()!='main':
    raise SystemExit('STOP: checkout main first; never rewrite pushed history')
if subprocess.run(['git','diff','--quiet']).returncode or subprocess.run(['git','diff','--cached','--quiet']).returncode:
    raise SystemExit('STOP: tracked working tree/index is dirty; preserve user edits')
if not (ROOT/'scripts/ciam-v10.sh').is_file() or not (ROOT/'deploy/ciam-v10/authority/bootstrap.py').is_file():
    raise SystemExit('STOP: missing repository/bootstrap or correction payload')

changes={}
issues=[]
def replace(filename,old,new):
    path=ROOT/filename
    if path.is_symlink() or not path.is_file():raise SystemExit('STOP: path not a regular file: '+filename)
    text=changes.get(path,path.read_text())
    if text.count(old) == 0 and new in text:return
    if text.count(old)!=1:
        issues.append((filename, text.count(old), old[:90]));return
    changes[path]=text.replace(old,new,1)

replace('services/identity-bff/src/wso2-private.js',
    "result[key] = Object.freeze({ name: key, brand, channel, clientId, clientSecret, issuer, scope: 'openid', redirectUri });",
    "// Requesting a scope never grants it; WSO2 still decides at token issuance.\n    // The v10 bootstrap enables this only after readback-verified API and roles.\n    const profileScope = process.env.WSO2_AUTHORITY_OIDC_SCOPE === 'ciam:profile:read'\n      ? 'openid ciam:profile:read' : 'openid';\n    result[key] = Object.freeze({ name: key, brand, channel, clientId, clientSecret, issuer, scope: profileScope, redirectUri });")
replace('deploy/ciam-v10/cli.py',
    "RESOURCES = HERE / 'resources/bootstrap.py'\n",
    "RESOURCES = HERE / 'resources/bootstrap.py'\nAUTHORITY = HERE / 'authority/bootstrap.py'\n")
replace('deploy/ciam-v10/cli.py',
    "    elif command=='bff-diagnose':bff_diagnose()",
    "    elif command in ('authority-preflight','authority-evidence','authorization-plan','authorization-apply',\n"
    "                     'authorization-reconcile','consent-verify','consent-plan',\n"
    "                     'consent-apply','authority-status'):\n"
    "        repo_guard();root_guard()\n"
    "        run([sys.executable,AUTHORITY,command])\n"
    "    elif command=='runtime-acceptance':\n"
    "        root_guard()\n"
    "        run([sys.executable,HERE/'authority/acceptance.py'])\n"
    "    elif command=='bff-diagnose':bff_diagnose()")
replace('deploy/ciam-v10/cli.py',
    "for d in ('server','tenants','resources','oidc'):",
    "for d in ('server','tenants','resources','oidc','authority'):")
replace('deploy/ciam-v10/cli.py',
    "else:raise Stop('UNKNOWN_COMMAND: fresh bootstrap status bff-diagnose bff-start bff-clear-stale test')",
    "else:raise Stop('UNKNOWN_COMMAND: help fresh bootstrap status bff-diagnose bff-start bff-clear-stale test authority-preflight authority-evidence authorization-plan authorization-apply authorization-reconcile consent-verify consent-plan consent-apply authority-status runtime-acceptance')")
replace('deploy/ciam-v10/cli.py',
    "    if command=='fresh':prepare()",
    "    if command=='help':\n        output({'commands':['fresh','bootstrap','status','bff-diagnose','bff-start','bff-clear-stale','test',\n                           'authority-preflight','authority-evidence','authorization-plan','authorization-apply','authorization-reconcile',\n                           'consent-verify','consent-plan','consent-apply','authority-status','runtime-acceptance'],\n                'writeConfirmation':{'authorization-apply':'WSO2_CIAM_V10_AUTHORITY_CONFIRM=AUTHORIZE_EXISTING_V10_OIDC_AND_ASSIGN_SCIM_USERS'},\n                'safety':'Consent apply refuses until feature and API contract verified'})\n    elif command=='fresh':prepare()")
replace('deploy/ciam-v10/oidc/bootstrap.py',
    "    logfile=PRIVATE/'bff-v10.log';pidfile=PRIVATE/'bff-v10.pid'",
    "    # Read-only bridge of the separately verified authority journal. No client\n    # registration, rotation, or mutation of either existing private journal.\n    authority_file=PRIVATE/'bootstrap-authority-v10.private.json'\n    if authority_file.exists() or authority_file.is_symlink():\n        authority=read_private(authority_file)\n        if (authority.get('schema')=='identity.wso2.ciam.v10.authority.v1'\n            and authority.get('base')==BASE\n            and authority.get('apiIdentifier')=='https://api.ciam-v10.test/profile'\n            and authority.get('scope')=='ciam:profile:read'\n            and authority.get('acceptance')=='API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED'\n            and all(authority.get('tenants',{}).get(b,{}).get('apps',{}).get(c) == s['tenants'][b]['clients'][c]['id']\n                    and authority['tenants'][b].get('resource',{}).get('state')=='verified'\n                    and authority['tenants'][b].get('authorizations',{}).get(c,{}).get('state')=='verified'\n                    and authority['tenants'][b].get('role_'+c,{}).get('state')=='verified'\n                    for b in DOMAINS for c in CHANNELS)):\n            env['WSO2_AUTHORITY_OIDC_SCOPE']='ciam:profile:read'\n            env['WSO2_BUSINESS_API_AUDIENCE']=authority['apiIdentifier']\n    logfile=PRIVATE/'bff-v10.log';pidfile=PRIVATE/'bff-v10.pid'")
replace('services/identity-bff/src/server.js',
    "u.pathname === '/api/m2m/client-credentials' || u.pathname === '/api/logout' ||",
    "u.pathname === '/api/m2m/client-credentials' ||")
replace('services/identity-bff/src/server.js',
    "  if (wso2Live && (u.pathname === '/api/scenarios' || u.pathname === '/api/session' ||",
    "  // Local session invalidation remains available even during a WSO2 outage.\n  // This does NOT assert WSO2 SSO logout or access-token revocation.\n  if (wso2Live && u.pathname === '/api/logout') {\n    if (req.method !== 'POST') return reply(res, 405, {error:'method_not_allowed'});\n    if (req.headers.origin !== appConfig.origin || !req.headers['x-csrf-token'] ||\n        !safeEqual(req.headers['x-csrf-token'], s.csrf))\n      return reply(res, 403, {error:'csrf_or_origin_denied'});\n    sessionStore.destroy(s, res);\n    return reply(res, 200, { status:'BFF_SESSION_DESTROYED',\n      wso2Session:'NOT_TERMINATED', accessTokenRevocation:'NOT_VERIFIED' });\n  }\n  if (wso2Live && (u.pathname === '/api/scenarios' || u.pathname === '/api/session' ||")
replace('deploy/ciam-v10/resources/bootstrap.py',
    "Stage: 2 management M2M clients, scopes for Application API and SCIM2 Users,",
    "Stage: 2 management M2M clients, scopes for Application API and SCIM2 Users,\nFollow-on additive business API/role bootstrap: ../authority/bootstrap.py;")



replace('services/identity-bff/src/live-wso2-ui.js',
    "    state.textContent = active.length ? `WSO2 validated sessions: ${active.join(', ')}` : 'No WSO2-validated session';",
    "    state.textContent = active.length ? `WSO2 validated sessions: ${active.join(', ')}` : 'No WSO2-validated session';\n"
    "    // Buttons are visual probes only: HTTP authorization always runs in BFF/WSO2.\n"
    "    for (const key of active) {\n"
    "      const button = document.createElement('button');\n"
    "      button.type = 'button'; button.textContent = 'Check WSO2 profile scope: ' + key;\n"
    "      const result = document.createElement('output');\n"
    "      button.addEventListener('click', async () => {\n"
    "        result.textContent = 'Checking...';\n"
    "        try { const response = await fetch('/api/protected/profile?client=' + encodeURIComponent(key),\n"
    "            {credentials:'same-origin',cache:'no-store'});\n"
    "          result.textContent = response.status === 200 ? 'WSO2 access token authorized (HTTP 200)'\n"
    "            : 'Denied by backend (HTTP ' + response.status + ')';\n"
    "        } catch { result.textContent = 'WSO2/BFF unavailable; operation denied'; }\n"
    "      });\n"
    "      state.parentNode.append(button, result);\n"
    "    }")
replace('services/identity-bff/src/live-wso2.html',
    '<p>Consent and protected APIs remain unavailable unless WSO2 authorizes them.</p>',
    '<p>Consent remains disabled until WSO2 v2 is verified. Protected profile reads require a live, correctly scoped WSO2 access token; a browser login alone is insufficient.</p>')

# New v10 factual status does not modify the legacy preview's mode or history.
replace('README.md', '# Identity Experience Center\n',
    '# Identity Experience Center\n\n> **Isolated v10 WSO2 status:** A separate 9444/4400 deployment exists. The historical preview descriptions below do not describe its current live integration. See [WSO2 v10 P0 corrective runbook](docs/WSO2_CIAM_V10_P0_CORRECTION.md). Never equate the preview with a WSO2 authorization/consent decision.\n')

# All checks finish before making any source changes. No partial apply on drift.
if issues:
    print('STOP: source anchors changed or missing; tracked files untouched.',file=sys.stderr)
    for filename,count,snippet in issues:
        print(f'  {filename}: matches={count}: {snippet!r}',file=sys.stderr)
    raise SystemExit(1)
# Refuse to modify anything beneath private/var/home. Every destination is a tracked source file.
for path,data in changes.items():
    if path.stat().st_mode & 0o002:raise SystemExit('STOP: world-writable source: '+str(path))
    if data==path.read_text():continue
print('SOURCE_ONLY_CHANGE_PLAN:',*[str(x.relative_to(ROOT)) for x in changes],sep='\n  ')
if len(sys.argv)>2 or (len(sys.argv)==2 and sys.argv[1]!='--apply'):
    raise SystemExit('USAGE: python3 tools/install-p0-correction.py [--apply]')
if len(sys.argv)==1:
    print('DRY RUN ONLY. Re-run with --apply to write source files.')
    sys.exit(0)
for path,data in changes.items():
    # source files only; originals remain recoverable through Git.
    path.write_text(data)
print('SOURCE_ONLY_PATCH_APPLIED. Run git diff --check and tests. No Git commit or remote writes performed.')
