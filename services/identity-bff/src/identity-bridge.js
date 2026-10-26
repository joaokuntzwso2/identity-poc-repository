/* Same-origin session client. Never consumes OIDC tokens or secrets in browser JavaScript. */
(() => {
  'use strict';
  const panel = document.createElement('aside');
  panel.id = 'identity-bff-bridge';
  panel.setAttribute('aria-label', 'WSO2 authenticated identity');
  panel.innerHTML = '<strong>WSO2 Identity BFF</strong><span id="identity-bff-state" role="status">Verificando sessão…</span><nav id="identity-bff-actions" aria-label="Entrar com WSO2"></nav><small>Permissões de identidade são verificadas no BFF; as personas e os dados do laboratório continuam demonstrações.</small>';
  document.body.prepend(panel);
  const state = panel.querySelector('#identity-bff-state');
  const nav = panel.querySelector('#identity-bff-actions');
  const keys = ['aurora-web', 'aurora-app', 'brisa-web', 'brisa-app'];
  const captions = ['Aurora Web', 'Aurora Mobile', 'Brisa Web', 'Brisa Mobile'];
  async function refresh() {
    try {
      const response = await fetch('/api/identity/me', { credentials: 'same-origin', cache: 'no-store', headers: { accept: 'application/json' } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const session = await response.json();
      nav.replaceChildren();
      const active = keys.filter(k => session.clients[k]?.authenticated === true);
      state.textContent = active.length ? `ID token validado pelo BFF: ${active.map(k => captions[keys.indexOf(k)]).join(' · ')}` : 'Nenhuma autenticação WSO2 comprovada neste navegador';
      keys.forEach((key, idx) => {
        const a = document.createElement('a');
        a.href = `/auth/${key.replace(/-app$/, '-mobile')}/login`;
        a.textContent = active.includes(key) ? `${captions[idx]} ✓` : `Entrar ${captions[idx]}`;
        a.setAttribute('aria-label', a.textContent);
        nav.append(a);
      });
      if (active.length) {
        const logout = document.createElement('button');
        logout.type = 'button'; logout.textContent = 'Encerrar sessão BFF';
        logout.addEventListener('click', async () => {
          logout.disabled = true;
          try {
            const r = await fetch('/api/logout', { method: 'POST', credentials: 'same-origin', headers: { origin: location.origin, 'X-CSRF-Token': session.csrf } });
            if (!r.ok) throw new Error('Logout refused');
            await refresh();
          } catch { state.textContent = 'Falha ao encerrar a sessão; não presuma logout do WSO2.'; logout.disabled = false; }
        });
        nav.append(logout);
      }
    } catch {
      nav.replaceChildren(); state.textContent = 'BFF indisponível: identidade não verificada';
    }
  }
  refresh();
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
})();
