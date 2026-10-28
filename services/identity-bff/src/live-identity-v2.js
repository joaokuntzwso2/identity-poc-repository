'use strict';
// This view has no persona fixtures or client-side authorization decisions.
// Scopes come from /api/identity/me after WSO2 introspection; only BFF APIs decide access.
const CHANNELS = [
  ['aurora-web', 'Aurora · Web', '/auth/aurora-web/login'],
  ['aurora-app', 'Aurora · App', '/auth/aurora-mobile/login'],
  ['brisa-web', 'Brisa · Web', '/auth/brisa-web/login'],
  ['brisa-app', 'Brisa · App', '/auth/brisa-mobile/login'],
];
let csrf = null;
const $ = (id) => document.getElementById(id);
const elt = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
};
const field = (dl, label, value) => {
  if (value === undefined || value === null || value === '') return;
  dl.append(elt('dt', label), elt('dd', value));
};
async function jsonGet(url) {
  const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
  const data = await response.json();
  return { response, data };
}
async function inspectProfile(key, resultNode) {
  resultNode.textContent = 'Consultando a API protegida...';
  try {
    const { response, data } = await jsonGet(`/api/protected/profile?client=${encodeURIComponent(key)}`);
    if (response.ok && data.allowed === true && data.authorizedBy === 'WSO2_ACTIVE_ACCESS_TOKEN_SCOPE') {
      resultNode.textContent = 'AUTORIZADO: a API validou o token ativo, audience e ciam:profile:read. Não são dados cadastrais.';
    } else {
      resultNode.textContent = `NÃO AUTORIZADO (HTTP ${response.status}): ${data.error || 'acesso negado'}`;
    }
  } catch { resultNode.textContent = 'A consulta falhou; a autorização não foi comprovada.'; }
}
async function load() {
  $('status').textContent = 'Lendo sessão e verificando tokens no WSO2...';
  $('logout').disabled = true;
  $('channels').replaceChildren();
  try {
    const { response, data } = await jsonGet('/api/identity/me');
    if (!response.ok) throw Error(`Identity Server não disponível (HTTP ${response.status}). Não há fallback local.`);
    if (!data || !data.clients || typeof data.clients !== 'object') throw Error('Resposta de identidade inválida');
    if (!['WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN', 'NO_VERIFIED_IDENTITY'].includes(data.identitySource)) {
      throw Error('Modo de identidade não-live: acesso a esta tela recusado');
    }
    csrf = typeof data.csrf === 'string' ? data.csrf : null;
    const total = CHANNELS.filter(([key]) => data.clients[key]?.authenticated === true).length;
    $('status').textContent = total ? `${total} canal(is) autenticado(s), com introspecção atual do WSO2.` : 'Nenhuma autenticação comprovada. Use o login WSO2 de um dos canais.';
    $('source').textContent = `Origem: ${data.identitySource} · ${data.evidence || 'sem evidência'}`;
    $('logout').disabled = !csrf || !total;
    for (const [key, title, loginPath] of CHANNELS) {
      const info = data.clients[key];
      const card = elt('article', undefined, 'card');
      card.append(elt('h3', title));
      if (!info?.configured) {
        card.append(elt('span', 'Aplicação não configurada', 'tag bad'));
      } else if (info.authenticated === true) {
        card.append(elt('span', 'Token ativo no WSO2', 'tag ok'));
        const details = elt('dl', undefined, 'fields');
        const claims = info.claimsFromVerifiedIdToken || {};
        field(details, 'Nome (ID token)', claims.name || [claims.given_name, claims.family_name].filter(Boolean).join(' '));
        field(details, 'Usuário (ID token)', claims.preferred_username);
        field(details, 'Email (ID token)', claims.email);
        field(details, 'Identificador pseudônimo', info.subjectFingerprint);
        field(details, 'Issuer', info.issuer);
        field(details, 'Validado em', info.verifiedAt);
        field(details, 'Scopes OAuth ativos (não papéis)', Array.isArray(info.permissions) ? info.permissions.join(', ') || 'Nenhum scope ciam:*' : 'Indisponível');
        card.append(details);
        const probe = elt('button', 'Testar ciam:profile:read');
        const result = elt('p', '', 'response');
        probe.addEventListener('click', () => { void inspectProfile(key, result); });
        card.append(probe, result);
      } else {
        card.append(elt('span', 'Não autenticado', 'tag'));
      }
      if (info?.configured) {
        const login = elt('button', 'Autenticar pelo WSO2');
        login.addEventListener('click', () => {
          location.assign(`${loginPath}?returnTo=${encodeURIComponent('/identity-live-v2')}`);
        });
        card.append(login);
      }
      $('channels').append(card);
    }
  } catch (error) {
    csrf = null;
    $('source').textContent = 'Autoridade não verificada';
    $('status').textContent = error instanceof Error ? error.message : 'Não foi possível verificar a identidade';
    $('channels').append(elt('p', 'Falha fechada: nenhuma persona, papel, scope ou sessão local é assumida.'));
  }
}
$('refresh').addEventListener('click', () => { void load(); });
$('logout').addEventListener('click', async () => {
  if (!csrf) return;
  $('logout').disabled = true;
  try {
    const response = await fetch('/api/logout', { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'X-CSRF-Token': csrf, Accept: 'application/json' } });
    if (!response.ok) throw Error(`HTTP ${response.status}`);
    await load();
    $('status').textContent = 'Sessão BFF destruída. Sessão SSO WSO2 e revogação de tokens NÃO verificadas.';
  } catch { $('status').textContent = 'Logout BFF falhou; o estado anterior não é considerado encerrado.'; await load(); }
});
void load();
