'use strict';
// P1.20/P1.21 progressive enhancement. Identity data only from same-origin BFF.
// No credentials, bearer tokens, cookies, CSRF values or arbitrary attributes rendered.
(() => {
  const routes = [
    {key:'aurora-web', brand:'aurora', path:'/portal/aurora/web', label:'Aurora Web'},
    {key:'aurora-app', brand:'aurora', path:'/portal/aurora/mobile', label:'Aurora Mobile'},
    {key:'brisa-web', brand:'brisa', path:'/portal/brisa/web', label:'Brisa Web'},
    {key:'brisa-app', brand:'brisa', path:'/portal/brisa/mobile', label:'Brisa Mobile'}
  ];
  const site = routes.find(r => r.path === location.pathname);
  const root = document.getElementById('root');
  if (!root || !(location.pathname === '/' || ['/lab','/experience'].includes(location.pathname) || site)) return;
  const narrative = {
    'Uma pessoa. Duas marcas.': [
      'Uma operação com marcas distintas precisa evitar que uma sessão de uma marca seja tratada como autorização de outra.',
      'Cliente Ana Costa, em contas separadas Aurora e Brisa.',
      'Autenticar nos quatro canais e comparar emissor, cliente e permissões liberadas.',
      'OIDC Authorization Code + PKCE, tenants e introspecção.',
      'Quatro sessões e URLs de issuer obtidos de /api/identity/me; testes de perfil e negação entre marcas podem ser executados.',
      'Ilustrar governança entre marcas. Identificadores pairwise intertenant não estão comprovados.'
    ],
    'Segurança no momento certo.': [
      'Aprovar um pedido sem autenticação forte suficiente aumenta o risco operacional.',
      'Marcos Oliveira, vendedor autorizado na Aurora.',
      'Revisar uma solicitação e tentar sua aprovação pela interface protegida.',
      'Escopo de aprovação e fator TOTP recente, confirmados no backend.',
      'Resposta HTTP real de aprovação ou negação; ACR/AMR somente quando emitidos e verificados.',
      'Negação segura é comprovável; aprovação positiva só pode ser anunciada após desafio e persistência verificados.'
    ],
    'Dados com controle e propósito.': [
      'Dados pessoais não devem ser expostos por padrão.',
      'Cliente autenticado em uma marca.',
      'Consultar somente o UserInfo liberado pelo WSO2 e examinar limites da implementação.',
      'OIDC UserInfo e vínculo criptograficamente verificado do sujeito.',
      'HTTP do endpoint de perfil e conjunto mínimo liberado; não há registros de consentimento de preferências.',
      'Demonstrar minimização; consentimento e revogação permanecem pendentes.'
    ],
    'Cada empresa governa seus acessos.': [
      'Vendedores e clientes requerem níveis de acesso diferentes.',
      'Ana Costa (cliente) e Marcos Oliveira (vendedor) na Aurora.',
      'Criar/consultar pedidos com conta de cliente, revisar com conta de vendedor.',
      'Permissões concedidas em WSO2, verificadas por issuer, audience e scopes no BFF.',
      'HTTP 200/201/403 e visibilidade OWNER_ONLY/BRAND_REVIEW quando obtidos de APIs reais.',
      'Segregação de funções; delegação organizacional B2B não comprovada.'
    ],
    'Delegação sem privilégio excessivo.': [
      'Serviços e agentes precisam de limites claros de autoridade.',
      'Arquiteto de segurança avaliando identidades de workload.',
      'Inspecionar capacidades declaradas e lacunas, sem emitir tokens fictícios.',
      'Desenho de OAuth 2.0 Token Exchange; implementação live ainda não demonstrada.',
      'Nenhuma prova de ator delegado é exibida sem endpoint real e teste positivo.',
      'Roadmap de privilégio mínimo, não afirmação de funcionalidade existente.'
    ],
    'Uma nova marca, sem interrupção.': [
      'Expandir um ecossistema exige isolamento e provisionamento repetível.',
      'Arquiteto de plataforma / administrador de tenants.',
      'Comparar Aurora e Brisa e verificar descoberta dos quatro OIDC clients.',
      'Tenants separados e bootstrap com readback, sem reaplicar recursos.',
      'Descoberta OIDC online e sessão de cada cliente verificada por endpoints do BFF.',
      'Preparação para escala; criação de terceiro tenant não demonstrada.'
    ]
  };
  const fields = ['Problema de negócio','Persona','Jornada','Capacidade WSO2','Evidência técnica','Resultado de negócio'];
  const node = (tag, value, cls) => {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (value !== undefined) el.textContent = String(value);
    return el;
  };
  const a = (parent, tag, value, cls) => {const c=node(tag,value,cls);parent.append(c);return c;};
  const state = (s) => s === 'VERIFIED' ? 'p-status-ok' : s === 'DENIED' || s === 'FAILED' ? 'p-status-denied' : 'p-status-unknown';
  let lastView = null, focusReturn = null, dialog = null, content = null, refreshButton = null;
  function addPair(dl, name, value){ a(dl,'dt',name); a(dl,'dd',value); }
  function ensureDialog(){
    if (dialog) return;
    dialog=node('dialog',undefined,'p-dialog'); dialog.setAttribute('aria-labelledby','p-dialog-title');
    const heading=node('header');const titleBlock=node('div');
    a(titleBlock,'h2','Evidência técnica — fonte viva').id='p-dialog-title';
    a(titleBlock,'p','Consultas de leitura ao BFF. Sem tokens, cookies, atributos privados ou provas inventadas.');
    heading.append(titleBlock);
    const close=a(heading,'button','×','p-close');close.type='button';close.setAttribute('aria-label','Fechar painel de evidências');
    close.onclick=()=>dialog.close(); dialog.append(heading);
    content=a(dialog,'div',undefined,'p-dialog-content');
    refreshButton=a(content,'button','Atualizar evidências','p-refresh');refreshButton.type='button';refreshButton.onclick=()=>void readEvidence();
    const status=a(content,'p','Aguardando consulta');status.id='p-evidence-status';status.setAttribute('role','status');status.setAttribute('aria-live','polite');
    const results=a(content,'div');results.id='p-evidence-results';
    dialog.addEventListener('close',()=>{if(focusReturn?.isConnected)focusReturn.focus();});
    document.body.append(dialog);
  }
  async function json(path) {
    const response = await fetch(path,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
    const data = await response.json().catch(()=>({error:'invalid_json'}));
    return {http:response.status, data};
  }
  function block(title, entries){
    const card=node('section',undefined,'p-evidence-card'); a(card,'h3',title);
    const dl=a(card,'dl'); for(const [key,value] of entries) addPair(dl,key,value);
    return card;
  }
  function badgeFor(http){return http === 200 ? 'VERIFIED' : http === 403 ? 'DENIED' : http === 401 ? 'UNAUTHENTICATED' : 'UNAVAILABLE';}
  async function readEvidence(){
    const out=document.getElementById('p-evidence-results'), status=document.getElementById('p-evidence-status');
    if(!out||!status)return;
    out.replaceChildren();status.textContent='Consultando sessão, descoberta e APIs reais…';refreshButton.disabled=true;
    try{
      const [identity, discovery]=await Promise.all([json('/api/identity/me'),json('/api/wso2-status')]);
      if(identity.http!==200 || !identity.data || typeof identity.data.clients!=='object' || identity.data.clients===null){
        status.textContent=`BLOCKED: sessão não verificável (HTTP ${identity.http}). Nenhuma identidade foi presumida.`;
        return;
      }
      const summary=block('Estado da autoridade',[
        ['Proveniência','BFF → WSO2 introspecção por solicitação'],
        ['Sessão',identity.data.authenticated?'Pelo menos um client autenticado':'Nenhum client autenticado'],
        ['WSO2 descoberta',discovery.http===200?'Consulta executada':'Consulta indisponível'],
        ['Consentimento, B2B delegado, token exchange','NÃO COMPROVADOS neste ambiente']
      ]);out.append(summary);
      const live=routes.filter(r=>!site||r.key===site.key);
      for(const r of live){
        const c=identity.data.clients?.[r.key];
        const found=discovery.http===200 && Array.isArray(discovery.data.statuses) ? discovery.data.statuses.find(v=>v.key===r.key) : undefined;
        const entries=[
          ['Tenant esperado',`${r.brand}.identity.test`],['Cliente BFF',r.key],
          ['OIDC discovery',found?.discovery===true?'VERIFIED':'UNAVAILABLE'],
          ['Sessão autenticada',c?.authenticated===true?'VERIFIED':'NOT_AUTHENTICATED'],
          ['Issuer verificado',c?.authenticated===true?String(c.issuer||'NÃO EMITIDO'):'NÃO AUTENTICADO'],
          ['Sujeito',c?.authenticated===true?`Fingerprint: ${c.subjectFingerprint||'não fornecido'}`:'NÃO AUTENTICADO'],
          ['Escopos WSO2',c?.authenticated===true?(c.permissions||[]).join(', ')||'Nenhum ciam:*':'NÃO AUTENTICADO'],
          ['Roles no ID token',c?.authenticated===true?(c.rolesFromVerifiedIdToken||[]).join(', ')||'Claim não emitido':'NÃO AUTENTICADO'],
          ['ACR / AMR declarados',c?.authenticated===true?`${c.acrFromVerifiedIdToken||'não emitido'} / ${(c.amrFromVerifiedIdToken||[]).join(', ')||'não emitido'}`:'NÃO AUTENTICADO'],
          ['MFA validado para aprovação','NÃO COMPROVADO sem operação de aprovação aceita pelo backend']
        ];
        if(c?.authenticated===true){
          const opposite=r.brand==='aurora'?'brisa':'aurora';
          const [profile,cases,denial]=await Promise.all([
            json(`/api/brands/${r.brand}/profile?client=${r.key}`),
            json(`/api/brands/${r.brand}/cases?client=${r.key}`),
            json(`/api/brands/${opposite}/cases?client=${r.key}`)
          ]);
          entries.push(['UserInfo protegido',`HTTP ${profile.http} — ${badgeFor(profile.http)}`]);
          entries.push(['Solicitações persistidas',`HTTP ${cases.http}${cases.http===200&&Array.isArray(cases.data.records)?` · ${cases.data.records.length} registros · ${cases.data.visibility||'visibilidade não emitida'}`:''}`]);
          entries.push(['Isolamento entre tenants',`HTTP ${denial.http} — ${denial.http===403?'DENIED como esperado':'NÃO COMPROVADO'}`]);
        }
        out.append(block(r.label,entries));
      }
      const note=a(out,'p','A tela mostra permissões emitidas, não as concede. Uma negação HTTP 403 é evidência de controle, não erro a ocultar. A aprovação TOTP positiva e a durabilidade de banco exigem ensaios separados.','p-evidence-note');
      note.setAttribute('role','note');
      status.textContent='Consulta concluída. HTTP e valores atuais foram obtidos do backend.';
    }catch{
      status.textContent='BLOCKED: falha de rede ou resposta inválida. Sem fallback simulado.';
    }finally{refreshButton.disabled=false;}
  }
  function openEvidence(from){
    ensureDialog();focusReturn=from;
    if(!dialog.open) dialog.showModal();
    void readEvidence();
  }
  function enhanceView(){
    const view=root.firstElementChild;if(!view||view===lastView)return;
    lastView=view;
    const main=document.getElementById('main-content')||document.querySelector('.retail-site');
    if(main){main.id='main-content';main.tabIndex=-1;if(site)main.setAttribute('role','main');}
    document.querySelectorAll('.nav-link[data-nav]').forEach(b=>{
      if(b.classList.contains('nav-active')) b.setAttribute('aria-current','page');
    });
    const menu=document.querySelector('[data-action="menu"]');
    if(menu){menu.setAttribute('aria-expanded',document.querySelector('.sidebar')?.classList.contains('sidebar-open')?'true':'false');menu.setAttribute('aria-controls','lab-menu');}
    document.querySelectorAll('[data-step]').forEach(b=>{if(b.classList.contains('progress-current'))b.setAttribute('aria-current','step');});
    document.querySelectorAll('.mode-switch button').forEach(b=>b.setAttribute('aria-pressed',String(b.classList.contains('selected'))));
    document.querySelectorAll('input,textarea').forEach(i=>{if(i.id==='v5-case-title'){i.required=true;i.minLength=3;} if(i.id==='v5-case-uuid'){i.setAttribute('aria-label','UUID de solicitação a aprovar');}});
    for(const id of ['v5-case-result','site-profile-result','v5-discovery']) {const x=document.getElementById(id);if(x)x.setAttribute('aria-live','polite');}
    const detail=document.querySelector('.journey-detail');
    if(detail){
      const text=detail.querySelector('h2')?.textContent||'';
      const record=narrative[text];
      if(record){
        const panel=node('section',undefined,'p-narrative'); a(panel,'h3','Narrativa executiva e prova verificável');
        const dl=a(panel,'dl',undefined,'p-narrative-grid');
        fields.forEach((name,i)=>{const box=a(dl,'div');a(box,'dt',name);a(box,'dd',record[i]);});
        const actions=a(panel,'div',undefined,'p-narrative-actions');const button=a(actions,'button','Inspecionar evidência ao vivo','p-presenter-trigger');
        button.type='button';button.onclick=()=>openEvidence(button);
        detail.append(panel);
      }
    }
  }
  const skip=node('a','Pular para o conteúdo principal','p-skip');skip.href='#main-content';document.body.prepend(skip);
  const dock=node('div',undefined,'p-presenter-dock');const trigger=a(dock,'button','◎ Evidência ao vivo','p-presenter-trigger');
  trigger.type='button';trigger.setAttribute('aria-haspopup','dialog');trigger.onclick=()=>openEvidence(trigger);document.body.append(dock);
  // Observe top-level view replacement only; the existing v5 app remains the router.
  const observer=new MutationObserver(()=>{const current=root.firstElementChild;if(current!==lastView)enhanceView();});
  observer.observe(root,{childList:true});enhanceView();
  window.addEventListener('unhandledrejection',()=>{
    const target=document.getElementById('v5-case-result')||document.getElementById('site-profile-result');
    if(target)target.textContent='Conectividade indisponível. Operação não confirmada; atualize o estado antes de tentar novamente.';
  });
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'){
      const sidebar=document.querySelector('.sidebar.sidebar-open');
      if(sidebar){sidebar.classList.remove('sidebar-open');const b=document.querySelector('[data-action="menu"]');if(b){b.setAttribute('aria-expanded','false');b.focus();}}
    }
  });
  root.addEventListener('click',e=>{
    const t=e.target instanceof Element?e.target.closest('[data-nav],[data-story],[data-step],[data-action="menu"],[data-action="next"],[data-action="prev"]'):null;
    if(!t)return;
    if(t.matches('[data-action="menu"]')) {queueMicrotask(()=>t.setAttribute('aria-expanded',String(document.querySelector('.sidebar')?.classList.contains('sidebar-open'))));return;}
    // The original v5 click handler completes its DOM swap synchronously. Restore a logical focus target.
    queueMicrotask(()=>{enhanceView();document.getElementById('main-content')?.focus({preventScroll:true});});
  });
})();
