'use strict';
(async () => {
  const state = document.getElementById('status');
  try {
    const r = await fetch('/api/identity/me', { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) throw Error('WSO2 unavailable');
    const s = await r.json();
    const active = Object.entries(s.clients || {}).filter(([, v]) => v.authenticated === true).map(([k]) => k);
    state.textContent = active.length ? `WSO2 validated sessions: ${active.join(', ')}` : 'No WSO2-validated session';
  } catch { state.textContent = 'WSO2 identity is unavailable; protected operations are denied'; }
})();
