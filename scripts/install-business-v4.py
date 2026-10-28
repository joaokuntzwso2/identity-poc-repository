#!/usr/bin/env python3
"""Guarded additive BFF integration; no remote WSO2 calls."""
import hashlib
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent.parent
SERVER=ROOT/'services/identity-bff/src/server.js'
PAYLOAD=ROOT/'services/identity-bff/src/live-cases-v4.js'
HTML=ROOT/'services/identity-bff/src/live-brand-v3.html'
FRAGMENT=ROOT/'services/identity-bff/src/live-cases-v4-fragment.html'
JS=ROOT/'services/identity-bff/src/live-cases-v4-ui.js'
MARK='// CIAM_V4_REAL_CASES_ROUTER'
NEW_IMPORT="import { handleCases } from './live-cases-v4.js';"
ANCHOR="import { readVerifiedUserinfo } from './live-userinfo.js';"
INSERT="""  // CIAM_V4_REAL_CASES_ROUTER: WSO2 scope checks precede persistent business operations.
  if (await handleCases(req, res, u, s, {
    clients,
    authorize: (session, key, scope) => process.env.WSO2_CASES_API_AUDIENCE
      ? requireAuthorityForClient(session, key, clients, scope, process.env.WSO2_CASES_API_AUDIENCE)
      : Promise.resolve({ http: 503, reason: 'cases_audience_not_configured' }),
    sameOrigin: request => request.headers.origin === appConfig.origin,
    safeCsrf: (request, session) => Boolean(request.headers['x-csrf-token']) &&
      safeEqual(request.headers['x-csrf-token'], session.csrf)
  })) return;
"""
API_ANCHOR="async function api(req, res, u, s) {\n"
DENIAL_ANCHOR="if (u.pathname.startsWith('/api/') && !/^\\/api\\/brands\\/(aurora|brisa)\\/profile$/.test(u.pathname)) {"


def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('--check','--apply'):
        sys.exit('Usage: python3 scripts/install-business-v4.py --check|--apply')
    if not PAYLOAD.is_file() or not SERVER.is_file() or not HTML.is_file() or not FRAGMENT.is_file() or not JS.is_file():
        sys.exit('REFUSED: required source missing')
    html=HTML.read_text()
    if '<section class="panel unavailable">' not in html or '<script defer src="/live-brand-v3.js"></script>' not in html:
        sys.exit('REFUSED: v3 portal HTML layout unknown')
    src=SERVER.read_text()
    if MARK in src:
        print('ALREADY INSTALLED; no changes');return
    if src.count(ANCHOR)!=1 or src.count(API_ANCHOR)!=1:
        sys.exit('REFUSED: incompatible server.js; no changes')
    # Prevent mistakenly patching the obsolete fixture BFF.
    if "LIVE_WSO2_REQUIRED_NO_SYNTHETIC_MODE" not in src or 'personas.json' in src:
        sys.exit('REFUSED: v3 zero-mock baseline not detected')
    if "'/live-brand-v3.js': 'live-brand-v3.js'," not in src:
        sys.exit('REFUSED: static manifest differs')
    if 'scope: c.scope // Do not pass browser-controlled acr_values as proof of MFA.' not in src:
        sys.exit('REFUSED: OAuth request scope differs')
    print('V4 precheck passed; source SHA256:',hashlib.sha256(src.encode()).hexdigest())
    if sys.argv[1]=='--check':return
    backup=SERVER.with_name('server.js.pre-business-v4.bak')
    if backup.exists() and backup.read_text()!=src:sys.exit('REFUSED: backup collision')
    if not backup.exists():
        fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(src)
    new=src.replace(ANCHOR,ANCHOR+'\n'+NEW_IMPORT,1).replace(API_ANCHOR,API_ANCHOR+INSERT,1)
    # Route must bypass the legacy static deny policy; authorization occurs in handleCases.
    needle = "!/^\\/api\\/brands\\/(aurora|brisa)\\/profile$/.test(u.pathname)"
    # The real source uses literal slashes escaped for a JS regular expression.
    needle = "!/^\\/api\\/brands\\/(aurora|brisa)\\/profile$/.test(u.pathname)"
    if needle not in new:
        sys.exit('REFUSED: legacy API routing guard changed; no write')
    new = new.replace(needle, needle + " && !/^\\/api\\/brands\\/(aurora|brisa)\\/cases(?:\\/[0-9a-f-]{36}\\/approve)?$/.test(u.pathname)", 1)
    new = new.replace("'/live-brand-v3.js': 'live-brand-v3.js',",
         "'/live-brand-v3.js': 'live-brand-v3.js',\n  '/live-cases-v4-ui.js': 'live-cases-v4-ui.js',", 1)
    new = new.replace('scope: c.scope // Do not pass browser-controlled acr_values as proof of MFA.',
       "scope: process.env.WSO2_CASES_SCOPES_ENABLED === '1' && process.env.WSO2_CASES_API_AUDIENCE ? \n          `${c.scope} ciam:cases:create ciam:cases:read ciam:cases:review ciam:cases:approve` : c.scope", 1)
    backup_html=HTML.with_name('live-brand-v3.html.pre-business-v4.bak')
    if backup_html.exists() and backup_html.read_text()!=html:
        sys.exit('REFUSED: HTML backup collision')
    if not backup_html.exists():
        fd=os.open(backup_html,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(html)
    html=html.replace('<section class="panel unavailable">',FRAGMENT.read_text()+'\n    <section class="panel unavailable">',1)
    html=html.replace('<script defer src="/live-brand-v3.js"></script>',
       '<script defer src="/live-brand-v3.js"></script>\n  <script defer src="/live-cases-v4-ui.js"></script>',1)
    HTML.write_text(html)
    SERVER.write_text(new)
    print('INSTALLED: BFF service-request routes, with private source backup')
    print('WSO2 remote writes: 0')
if __name__=='__main__':main()
