'use strict';
// Display and mutate only real business service requests authenticated via WSO2 BFF.
const caseBrand = location.pathname === '/portal/brisa' ? 'brisa' : 'aurora';
const byId = id => document.getElementById(id);
const makeNode = (tag, value) => {const n = document.createElement(tag); if(value!==undefined)n.textContent=String(value);return n;};
let current = null;
let currentKey = '';
async function callCases(method, path, body) {
  const headers = {accept:'application/json'};
  if (method==='POST') {headers['content-type']='application/json';headers['x-csrf-token']=current?.csrf || '';}
  const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',headers,
    body:body?JSON.stringify(body):undefined});
  const json=await response.json();return {response,json};
}
function url(path='') {return `/api/brands/${caseBrand}/cases${path}?client=${encodeURIComponent(currentKey)}`;}
async function refreshCaseIdentity() {
  byId('case-out').textContent='Consultando autorização WSO2...';
  const resp=await fetch('/api/identity/me',{credentials:'same-origin',cache:'no-store'});
  if(!resp.ok) throw Error('session_unavailable');
  current=await resp.json();
  const choices=[`${caseBrand}-web`,`${caseBrand}-app`].filter(k=>current.clients?.[k]?.authenticated);
  currentKey=choices[0]||'';
  const scopes=current.clients?.[currentKey]?.permissions||[];
  byId('case-open').disabled=!scopes.includes('ciam:cases:create');
  byId('case-refresh').disabled=!scopes.includes('ciam:cases:read');
  byId('case-approve').disabled=!scopes.includes('ciam:cases:approve');
  byId('case-out').textContent=currentKey?
    `Canal ${currentKey}. Permissões emitidas pelo WSO2: ${scopes.filter(s=>s.startsWith('ciam:cases:')).join(', ')||'nenhuma'}`:
    'Nenhuma sessão autenticada desta marca.';
}
async function showRecords() {
  await refreshCaseIdentity();
  if(byId('case-refresh').disabled)return;
  const {response,json}=await callCases('GET',url());
  if(!response.ok) {byId('case-out').textContent=`HTTP ${response.status}: ${json.error}`;return;}
  const ul=byId('case-list');ul.replaceChildren();
  for(const record of json.records){
    const li=makeNode('li',`${record.id} — ${record.title} — ${record.status}`);ul.append(li);
  }
  byId('case-out').textContent=`${json.records.length} registro(s) persistidos · ${json.visibility}.`;
}
byId('case-refresh').onclick=()=>showRecords().catch(()=>{byId('case-out').textContent='WSO2 ou serviço indisponível.'});
byId('case-open').onclick=async()=>{
  try {
    await refreshCaseIdentity();
    const data={title:byId('case-title').value,description:byId('case-description').value};
    const {response,json}=await callCases('POST',url(),data);
    byId('case-out').textContent=response.status===201?`Solicitação persistida: ${json.id}`:`HTTP ${response.status}: ${json.error}`;
    if(response.status===201)await showRecords();
  }catch{byId('case-out').textContent='Não foi possível confirmar a gravação.'}
};
byId('case-approve').onclick=async()=>{
  try{
    await refreshCaseIdentity();
    const id=byId('case-id').value.trim();
    if(!/^[0-9a-f-]{36}$/.test(id)){byId('case-out').textContent='Identificador UUID inválido.';return;}
    const {response,json}=await callCases('POST',url(`/${id}/approve`));
    if(response.status===202 && json.status==='WSO2_TOTP_STEP_UP_REQUIRED' && typeof json.authorizationUrl==='string'){
      location.assign(json.authorizationUrl);return;
    }
    byId('case-out').textContent=`HTTP ${response.status}: ${json.error||'acesso negado'}`;
  }catch{byId('case-out').textContent='Falha ao verificar autorização/assurance.'}
};
void refreshCaseIdentity().catch(()=>{byId('case-out').textContent='Sem sessão WSO2 verificada.'});
