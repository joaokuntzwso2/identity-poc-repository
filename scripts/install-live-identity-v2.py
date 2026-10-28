#!/usr/bin/env python3
"""Add a non-destructive, WSO2-only identity portal to the supplied BFF version."""
from pathlib import Path
import sys

root = Path.cwd()
file = root / 'services/identity-bff/src/server.js'
if not file.exists():
    raise SystemExit('REFUSED: run from the repository root')
text = file.read_text()
marker = '// WSO2_LIVE_IDENTITY_PORTAL_V2'
if marker in text:
    print('Already installed; no BFF changes')
    sys.exit(0)
assert "const s = (publicRoutes.has(u.pathname) || isSector) ? null : ensureSession(req, res);" in text, 'REFUSED: unsupported server routing version'
assert "s.pending[state] = { key, nonce, verifier, at: now };" in text, 'REFUSED: unsupported login state handler'
assert "return redirect(res, `/?client=${encodeURIComponent(key)}&authenticated=1`);" in text, 'REFUSED: unsupported callback handler'
assert "if (wso2Live) {\n      if (u.pathname === '/live-wso2-ui.js')" in text, 'REFUSED: unsupported live UI handler'

# The OAuth redirect destination is whitelisted, never taken verbatim from the browser.
text = text.replace("s.pending[state] = { key, nonce, verifier, at: now };",
    "s.pending[state] = { key, nonce, verifier, at: now, returnTo: u.searchParams.get('returnTo') === '/identity-live-v2' ? '/identity-live-v2' : '/' };")
text = text.replace("return redirect(res, `/?client=${encodeURIComponent(key)}&authenticated=1`);",
    "return redirect(res, `${p.returnTo || '/'}?client=${encodeURIComponent(key)}&authenticated=1`);")

# Only safe, explicitly present claims from already verified ID tokens can be shown.
old = "entry.verifiedAt = login.verifiedAt;\n            entry.permissions = current.scopes.filter(x => x.startsWith('ciam:'));"
assert old in text, 'REFUSED: unexpected identity response structure'
new = """entry.verifiedAt = login.verifiedAt;
            entry.permissions = current.scopes.filter(x => x.startsWith('ciam:'));
            const allowedClaims = ['name', 'given_name', 'family_name', 'preferred_username', 'email'];
            entry.claimsFromVerifiedIdToken = Object.fromEntries(allowedClaims
              .filter(k => typeof login.claims[k] === 'string' && login.claims[k].length <= 256)
              .map(k => [k, login.claims[k]]));"""
text = text.replace(old, new)

# Routes are reachable only in the already-enforced live-wso2 branch.
anchor = "if (wso2Live) {\n      if (u.pathname === '/live-wso2-ui.js')"
replacement = """if (wso2Live) {
      // WSO2_LIVE_IDENTITY_PORTAL_V2: no local persona state or synthetic data.
      if (u.pathname === '/identity-live-v2' || u.pathname === '/live-identity-v2.js' || u.pathname === '/live-identity-v2.css') {
        const entry = u.pathname === '/identity-live-v2' ? 'live-identity-v2.html' : u.pathname.slice(1);
        const contents = await readFile(join(dirname(fileURLToPath(import.meta.url)), entry));
        const isHtml = entry.endsWith('.html');
        res.writeHead(200, {
          'content-type': isHtml ? 'text/html; charset=utf-8' : entry.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8',
          'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
          'referrer-policy': 'no-referrer',
          'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        });
        res.end(contents); return;
      }
      if (u.pathname === '/live-wso2-ui.js')"""
text = text.replace(anchor,replacement)
backup = file.with_suffix('.js.pre-live-identity-v2.bak')
if backup.exists():
    raise SystemExit('REFUSED: backup exists but marker absent; manual review required')
backup.write_text(file.read_text())
file.write_text(text)
print('Installed WSO2 live v2 portal route (additive); original BFF backed up at', backup)
print('No requests made to WSO2. Live identity resources unchanged.')
