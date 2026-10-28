'use strict';
// No fixtures, hardcoded user identifiers, client-side permission grants or role mapping.
const brand = location.pathname === '/portal/brisa' ? 'brisa' : 'aurora';
const brands = { aurora: { title: 'Aurora', intro: 'Sua identidade Aurora, com dados e acesso verificados no WSO2.' },
  brisa: { title: 'Brisa', intro: 'Sua identidade Brisa, isolada das sessões e dos recursos de Aurora.' } };
const keys = [`${brand}-web`, `${brand}-app`];
let state = null;
const $ = id => document.getElementById(id);
const make = (tag, text) => { const node = document.createElement(tag); node.textContent = String(text); return node; };
$('brand-home').textContent = brands[brand].title.toUpperCase();
$('brand-home').href = `/portal/${brand}`;
$('title').textContent = `Sua conta ${brands[brand].title}.`;
$('intro').textContent = brands[brand].intro;
$('aurora-link').setAttribute('aria-current', brand === 'aurora' ? 'page' : 'false');
$('brisa-link').setAttribute('aria-current', brand === 'brisa' ? 'page' : 'false');
$('login-web').onclick = () => login('web');
$('login-app').onclick = () => login('app');
$('refresh').onclick = () => void reload();
$('channel').onchange = () => renderSelection();
$('profile-read').onclick = () => void readProfile();
function login(channel) {
  const loginRoute = channel === 'app' ? `${brand}-mobile` : `${brand}-web`;
  location.assign(`/auth/${loginRoute}/login?returnTo=${encodeURIComponent(`/portal/${brand}`)}`);
}
async function json(url, options) {
  const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store',
    headers: { accept: 'application/json', ...(options?.headers || {}) }, ...options });
  const body = await response.json();
  return { response, body };
}
function pair(dl, label, value) {
  if (value === null || value === undefined || value === '') return;
  dl.append(make('dt', label), make('dd', value));
}
function renderSelection() {
  const key = $('channel').value;
  const entry = state?.clients?.[key];
  $('profile-read').disabled = !entry?.authenticated;
  $('attributes').replaceChildren();
  pair($('attributes'), 'Status', 'Perfil ainda não consultado no UserInfo do WSO2');
  $('profile-pill').textContent = 'Não consultado';
  $('profile-result').textContent = '';
  $('scopes').textContent = entry?.permissions?.length ? entry.permissions.join(', ') : 'Nenhum scope ciam:*';
  $('roles').textContent = entry?.rolesFromVerifiedIdToken?.length ?
    entry.rolesFromVerifiedIdToken.join(', ') : 'WSO2 não incluiu roles no ID token verificado';
  const evidence = entry?.authenticated ?
    `Issuer: ${entry.issuer} · Fingerprint: ${entry.subjectFingerprint} · Verificado em: ${entry.verifiedAt}` :
    'Sem sessão autenticada para este canal';
  $('auth-proof').textContent = evidence;
  const acr = entry?.acrFromVerifiedIdToken;
  const amr = entry?.amrFromVerifiedIdToken;
  $('assurance').textContent = acr || amr?.length ?
    `Claims recebidos: acr=${acr || 'ausente'}, amr=${amr?.join(', ') || 'ausente'}. MFA NÃO afirmada sem política de validação.` :
    'Nenhuma evidência de MFA retornada neste ID token.';
  $('scope-state').textContent = entry?.permissions?.includes('ciam:profile:read') ? 'Escopo ativo' : 'Não concedido';
}
async function reload() {
  $('status').textContent = 'Consultando o token ativo no WSO2...';
  $('profile-read').disabled = true;
  $('logout').disabled = true;
  try {
    const { response, body } = await json('/api/identity/me');
    if (!response.ok || !['WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN','NO_VERIFIED_IDENTITY'].includes(body.identitySource))
      throw new Error(`Autoridade não verificada (HTTP ${response.status})`);
    state = body;
    const previous = $('channel').value;
    const active = keys.filter(k => body.clients?.[k]?.authenticated);
    $('channel').replaceChildren();
    if (!active.length) $('channel').append(new Option('Nenhuma sessão nesta marca', ''));
    for (const key of active) $('channel').append(new Option(key.endsWith('-web') ? 'Web' : 'App', key));
    if (active.includes(previous)) $('channel').value = previous;
    $('session-state').textContent = active.length ? 'Autenticado' : 'Não autenticado';
    $('session-source').textContent = active.length ? 'ID token + token ativo verificado' : 'Faça login pelo WSO2';
    $('tenant-state').textContent = brands[brand].title;
    $('status').textContent = active.length ? `${active.length} canal(is) autenticado(s) neste tenant.` :
      `Nenhuma sessão ${brands[brand].title}. Login necessário.`;
    $('logout').disabled = !body.csrf || !body.authenticated;
    if (active.length) renderSelection();
    else { $('scopes').textContent = 'Nenhum scope'; $('roles').textContent = 'Não informados';
      $('attributes').replaceChildren(); pair($('attributes'), 'Estado', 'Sem identidade autenticada'); }
    // MyAccount is an actual WSO2 portal, not a local MFA wizard.
    const issuer = body.clients?.[active[0]]?.issuer;
    if (issuer) $('myaccount').href = `${new URL(issuer).origin}/myaccount`;
  } catch (e) {
    state = null;
    $('session-state').textContent = 'Indisponível';
    $('status').textContent = `${e.message}. Nenhum fallback sintético será usado.`;
    $('scopes').textContent = 'Indisponível';
    $('roles').textContent = 'Indisponível';
    $('channel').replaceChildren(new Option('Falha na validação', ''));
  }
}
async function readProfile() {
  const key = $('channel').value;
  if (!keys.includes(key) || !state?.clients?.[key]?.authenticated) return;
  $('profile-read').disabled = true;
  $('profile-result').textContent = 'Consultando WSO2 UserInfo...';
  try {
    const { response, body } = await json(`/api/brands/${brand}/profile?client=${encodeURIComponent(key)}`);
    if (!response.ok || !body.allowed || body.identitySource !== 'WSO2_USERINFO') {
      $('profile-pill').textContent = 'Acesso negado';
      $('attributes').replaceChildren();
      $('profile-result').textContent = `HTTP ${response.status}: ${body.error || 'não autorizado'}`;
      return;
    }
    const fields = [ ['name','Nome'],['given_name','Nome próprio'],['family_name','Sobrenome'],
      ['preferred_username','Usuário'],['email','E-mail'],['email_verified','E-mail verificado'],
      ['phone_number','Telefone'],['phone_number_verified','Telefone verificado'] ];
    $('attributes').replaceChildren();
    let shown = 0;
    for (const [name,label] of fields) if (Object.hasOwn(body.attributes,name)) {
      const value = body.attributes[name]; pair($('attributes'),label,typeof value === 'boolean' ? String(value) : value); shown++;
    }
    if (!shown) pair($('attributes'),'Atributos','Nenhum atributo compartilhado; UserInfo retornou apenas sub');
    $('profile-pill').textContent = 'WSO2 verificado';
    $('profile-result').textContent = `API autorizada · ${body.client} · ${shown} atributo(s) liberado(s) pelo WSO2.`;
  } catch { $('profile-result').textContent = 'Falha UserInfo. Nenhum dado fictício exibido.'; }
  finally { $('profile-read').disabled = false; }
}
$('logout').onclick = async () => {
  if (!state?.csrf) return;
  $('logout').disabled = true;
  try {
    const { response } = await json('/api/logout', { method: 'POST',
      headers: { 'x-csrf-token': state.csrf } });
    if (!response.ok) throw new Error('logout_failed');
    await reload();
    $('status').textContent = 'Sessão BFF encerrada. Sessão SSO do WSO2 e revogação não verificadas.';
  } catch { $('status').textContent = 'Falha no logout local; consulte a sessão.'; await reload(); }
};
void reload();
