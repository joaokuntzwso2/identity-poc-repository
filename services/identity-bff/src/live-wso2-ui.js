'use strict';
(async () => {
  const state = document.getElementById('status');
  try {
    const r = await fetch('/api/identity/me', { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) throw Error('WSO2 unavailable');
    const s = await r.json();
    const active = Object.entries(s.clients || {}).filter(([, v]) => v.authenticated === true).map(([k]) => k);
    state.textContent = active.length ? `WSO2 validated sessions: ${active.join(', ')}` : 'No WSO2-validated session';
    // Buttons are visual probes only: HTTP authorization always runs in BFF/WSO2.
    for (const key of active) {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = 'Check WSO2 profile scope: ' + key;
      const result = document.createElement('output');
      button.addEventListener('click', async () => {
        result.textContent = 'Checking...';
        try { const response = await fetch('/api/protected/profile?client=' + encodeURIComponent(key),
            {credentials:'same-origin',cache:'no-store'});
          result.textContent = response.status === 200 ? 'WSO2 access token authorized (HTTP 200)'
            : 'Denied by backend (HTTP ' + response.status + ')';
        } catch { result.textContent = 'WSO2/BFF unavailable; operation denied'; }
      });
      state.parentNode.append(button, result);
    }
  } catch { state.textContent = 'WSO2 identity is unavailable; protected operations are denied'; }
})();
