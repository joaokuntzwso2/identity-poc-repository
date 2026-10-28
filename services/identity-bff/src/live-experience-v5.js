'use strict';
// CIAM_V5_EXPERIENCE_CENTER: original lab styles and six guided journeys,
// live WSO2-sourced identity and permissions; NO persona identity fixtures.
// All dynamic identity data is inserted via textContent, never innerHTML.
(() => {
  const B = ['aurora', 'brisa'];
  const FOUR = [
    { brand:'aurora', channel:'web', key:'aurora-web', path:'/portal/aurora/web', label:'Aurora · Web' },
    { brand:'aurora', channel:'mobile', key:'aurora-app', path:'/portal/aurora/mobile', label:'Aurora · Mobile Browser Preview' },
    { brand:'brisa', channel:'web', key:'brisa-web', path:'/portal/brisa/web', label:'Brisa · Web' },
    { brand:'brisa', channel:'mobile', key:'brisa-app', path:'/portal/brisa/mobile', label:'Brisa · Mobile Browser Preview' }
  ];
  const STORY = [
    { id:'multi-brand', number:'01', color:'teal', title:'Uma pessoa. Duas marcas.', eyebrow:'Experiência omnichannel',
      desc:'Explore logins reais com quatro clientes OIDC independentes e namespaces de tenant distintos.',
      controls:['OIDC com PKCE','Issuer por tenant','Audience por API','Identificador verificado'],
      steps:[['Aurora · Web','Abra a experiência Aurora Web. O login precisa ser feito pelo WSO2.','aurora-web'],['Aurora · Mobile','Abra o canal mobile, que usa um cliente OIDC próprio.','aurora-app'],['Brisa · Web','Entre no tenant Brisa com outra autenticação real.','brisa-web'],['Brisa · Mobile','Compare os quatro canais usando apenas sessões e claims realmente recebidos.','brisa-app'],['Evidência','Inspecione as sessões e os escopos emitidos pelo WSO2.','evidence']] },
    { id:'adaptive-security', number:'02', color:'blue', title:'Segurança no momento certo.', eyebrow:'Segurança contextual',
      desc:'A aprovação de solicitações exige escopo real e TOTP recente no ID token verificado.',
      controls:['Escopo ciam:cases:approve','AMR TOTP','auth_time <= 300s','Negação por padrão'],
      steps:[['Abra Aurora','Entre como usuário autorizado na experiência Aurora.','aurora-web'],['Autorização','Consulte o escopo de aprovação emitido pelo WSO2.','evidence'],['MFA / aprovação','No portal, o botão de aprovação chama o backend real e será recusado sem TOTP recente.','aurora-web']] },
    { id:'consent', number:'03', color:'purple', title:'Dados com controle e propósito.', eyebrow:'Privacidade por desenho',
      desc:'O consentimento de preferências depende das APIs e do update level de WSO2; não há concessão simulada.',
      controls:['Deny by default','Escopos emitidos','Consent API v2 (pendente)','Revogação auditável (pendente)'],
      steps:[['Examine a privacidade','Veja as capacidades verificadas e pendentes.','privacy'],['Identidade real','Consulte os atributos liberados pelo UserInfo, sem inventar informações.','aurora-web']] },
    { id:'b2b', number:'04', color:'amber', title:'Cada empresa governa seus acessos.', eyebrow:'Ecossistema de parceiros',
      desc:'Perfis seller e customer são autorizados por WSO2; organizações delegadas ainda requerem prova real.',
      controls:['Roles reais','RBAC de API','Isolamento por tenant','Organizações delegadas (pendente)'],
      steps:[['Acesso de seller','Use um login real em Aurora Web. A visibilidade BRAND_REVIEW exige o escopo de review.','aurora-web'],['Evidências','Compare permissões diretamente do token.','evidence'],['B2B','Confira os limites da integração atual.','b2b']] },
    { id:'delegation', number:'05', color:'sky', title:'Delegação sem privilégio excessivo.', eyebrow:'Identidade máquina e agente',
      desc:'Token Exchange, ator delegado e políticas de agente ainda não são operações verificadas neste ambiente.',
      controls:['RFC 8693 (pendente)','Actor token (pendente)','Privilégio mínimo','Sem credenciais sintéticas'],
      steps:[['Arquitetura','Veja o contrato de confiança e o que ainda não está implementado.','delegation'],['Evidências','Nenhuma prova de token exchange é declarada sem emissão real.','evidence']] },
    { id:'growth', number:'06', color:'rose', title:'Uma nova marca, sem interrupção.', eyebrow:'Operação escalável',
      desc:'Aurora e Brisa existem como tenants reais; não é afirmada a criação de uma terceira marca.',
      controls:['Bootstrap versionado','Readback WSO2','Quatro OIDC clients','Sem resets automáticos'],
      steps:[['Aurora e Brisa','Veja os quatro canais registrados.','channels'],['Operação','Confira o estado real dos tenants e clientes.','evidence']] }
  ];
  // Visual showcase data from the original storefront. It is a catalog, NOT identity or orders.
  const PRODUCTS = {
    aurora:[['Fone Studio Pro','Áudio','R$ 799','🎧'],['Caixa Echo One','Áudio','R$ 449','🔊'],['Relógio Pulse','Tecnologia','R$ 1.199','⌚'],['Luminária Orbit','Casa smart','R$ 289','💡']],
    brisa:[['Poltrona Alva','Móveis','R$ 1.890','🪑'],['Vaso Solano','Decoração','R$ 219','🏺'],['Cafeteira Nuvem','Cozinha','R$ 699','☕'],['Manta Linho','Têxteis','R$ 349','🧶']]
  };
  const root = document.getElementById('root');
  if (!root) return;
  let me = null, status = null, selected = 'home', activeStory = 0, activeStep = 0, technical = false;
  const site = FOUR.find(x => x.path === location.pathname) || null;
  const icon = (name) => `<span aria-hidden="true" class="v5-icon">${({home:'⌂',journeys:'▤',brand:'◈',security:'◇',privacy:'♧',evidence:'◎',user:'◉',b2b:'▧',arrow:'→'})[name] || '◈'}</span>`;
  const el = (id) => document.getElementById(id);
  const addText = (parent, tag, txt, cls) => { const item=document.createElement(tag); if(cls)item.className=cls; item.textContent=String(txt ?? ''); parent.append(item); return item; };
  const verified = key => me?.clients?.[key]?.authenticated === true;
  const scopes = key => Array.isArray(me?.clients?.[key]?.permissions) ? me.clients[key].permissions : [];
  function pathFor(key){ return FOUR.find(x=>x.key===key)?.path || '/lab'; }
  // CIAM_V5_2_VISIBLE_WSO2_LOGIN: fixed, server-allowlisted auth paths only.
  function authPath(x){
    const auth = x.channel==='mobile' ? `${x.brand}-mobile` : x.key;
    return `/auth/${auth}/login?returnTo=${encodeURIComponent(x.path)}`;
  }
  function loginFor(x){ location.assign(authPath(x)); }
  async function get(url, options={}){
    const response = await fetch(url, {credentials:'same-origin',cache:'no-store',...options});
    let data; try {data=await response.json();}catch{data={error:'invalid_response'};}
    return {response,data};
  }
  async function reload(){
    const r=await get('/api/identity/me');
    if (!r.response.ok || !['WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN','NO_VERIFIED_IDENTITY'].includes(r.data.identitySource)){
      me=null; throw Error(`WSO2 session status unavailable: HTTP ${r.response.status}`);
    }
    me=r.data;
    if (site) sitePage(); else labPage();
  }
  function shell(content, areaName='Início') {
    return `<div class="app-shell"><aside class="sidebar" aria-label="Navegação principal">
      <a class="brandmark" href="/lab" style="text-decoration:none"><span class="brand-symbol">◈</span><div><strong>identity<span class="dot">.</span>lab</strong><small>Experience Center · WSO2</small></div></a>
      <div class="environment-pill"><span class="status-dot"></span> WSO2 IS 7.3 · ZERO MOCK</div>
      <nav class="side-menu" id="lab-menu">
      <div class="nav-section"><div class="nav-label">VISÃO GERAL</div>
        ${menu('home','Início','home')}${menu('journeys','Jornadas guiadas','journeys')}${menu('channels','Quatro experiências','brand')}</div>
      <div class="nav-section"><div class="nav-label">EXPERIÊNCIAS</div>
        ${menu('aurora','Aurora Store','brand')}${menu('brisa','Brisa Living','brand')}
        ${menu('privacy','Privacidade e consentimento','privacy')}${menu('security','Segurança e atributos','security')}</div>
      <div class="nav-section"><div class="nav-label">ARQUITETURA</div>
        ${menu('identities','Identidades WSO2','user')}${menu('evidence','Evidências e testes','evidence')}
        ${menu('b2b','Parceiros B2B','b2b')}${menu('delegation','Agentes e delegação','security')}</div>
      </nav><div class="sidebar-bottom"><span class="sidebar-avatar">IS</span><div><strong>WSO2 IS 7.3</strong><span>Sem persona fictícia</span></div></div>
      </aside><div class="main-shell"><header class="topbar"><div class="top-left"><button class="menu-toggle" data-action="menu" aria-label="Abrir menu">☰</button>
      <span class="breadcrumb">Identity Experience Center <span>/</span> ${areaName}</span></div>
      <div class="top-actions"><div class="mode-switch" role="group" aria-label="Modo de apresentação"><button data-action="presenter" class="${technical?'':'selected'}">Apresentador</button><button data-action="technical" class="${technical?'selected':''}">Técnico</button></div>
      <span class="header-divider"></span><span class="badge ${me?.authenticated?'badge-teal':'badge-amber'}">${me?.authenticated?'WSO2 autenticado':'Sem sessão WSO2'}</span>
      </div></header><main class="content" id="main-content">${content}</main><footer class="footer"><strong>Identity Experience Center</strong><span>Fonte de verdade: WSO2 IS 7.3 · Dados comerciais demonstrativos identificados</span></footer></div></div>`;
  }
  function menu(id,label,ico){return `<button type="button" data-nav="${id}" class="nav-link ${selected===id?'nav-active':''}">${icon(ico)}<span>${label}</span></button>`;}
  const intro=(eyebrow,title,description)=>`<section class="page-intro"><p class="overline">${eyebrow}</p><h1>${title}</h1><p>${description}</p></section>`;
  const card=(title,body,tag='')=>`<article class="v5-card"><div class="v5-card-head"><h3>${title}</h3>${tag?`<span class="badge badge-amber">${tag}</span>`:''}</div><p>${body}</p></article>`;
  function storyCards(){return `<div class="story-grid">${STORY.map((s,i)=>`<button class="story-card" data-story="${i}"><span class="story-icon bg-${s.color}">${icon('journeys')}</span><span class="story-number">${s.number} / 06</span><h3>${s.title}</h3><p>${s.desc}</p><span class="story-bottom">Roteiro guiado <span>Explorar →</span></span></button>`).join('')}</div>`;}
  function home(){return `<section class="hero"><div class="hero-copy"><div class="eyebrow"><span class="eyebrow-line"></span> IDENTITY EXPERIENCE CENTER · WSO2 IS 7.3</div>
     <h1>Uma identidade.<br><em>Muitas experiências.</em></h1>
     <p>Seis jornadas guiadas e quatro clientes OIDC reais. Navegue pela experiência original, agora conectada à autenticação, aos escopos e ao UserInfo do Identity Server.</p>
     <div class="hero-cta"><button class="btn btn-primary" data-nav="journeys">Explorar jornadas →</button><button class="btn btn-secondary" data-nav="evidence">Ver evidências</button></div>
     <nav class="v5-hero-login" aria-label="Login WSO2 por marca e canal"><strong>Login real WSO2</strong><div>${FOUR.map(x=>`<a href="${authPath(x)}">${x.label} ↗</a>`).join('')}</div></nav>
     <span class="hero-disclaimer">Identidades, roles e MFA não são simulados. Catálogo é apenas apresentação; consentimento e delegação permanecem bloqueados até integração real.</span></div>
     <div class="hero-visual" aria-hidden="true"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="center-identity">◈</div><div class="floating floating-person"><div class="floating-user">IS</div><div><strong>WSO2</strong><small>Identidade verificada</small></div></div><div class="floating floating-brand aurora-float"><span class="mini-brand mini-aurora">A</span><div><strong>Aurora</strong><small>Web e Mobile</small></div></div><div class="floating floating-brand brisa-float"><span class="mini-brand mini-brisa">b.</span><div><strong>Brisa</strong><small>Web e Mobile</small></div></div></div></section>
     <section class="v5-lab-signin" aria-label="Entrar com WSO2"><div><strong>Entrar com WSO2 Identity Server</strong><p>Escolha uma marca e um canal. Cada botão abre uma autenticação OIDC real.</p></div>
       <div class="v5-lab-signin-links">${FOUR.map(x=>`<a class="v5-login-link" href="${authPath(x)}">Entrar ${x.label} ↗</a>`).join('')}</div></section>
     <div class="kpi-row"><div><strong>06</strong><span>Jornadas guiadas</span></div><div><strong>02</strong><span>Tenants WSO2</span></div><div><strong>04</strong><span>Clientes OIDC</span></div><div><strong>${FOUR.filter(x=>verified(x.key)).length}</strong><span>Sessões verificadas aqui</span></div></div>
     <div class="section-heading"><div><p class="overline">EXPLORE POR CENÁRIO</p><h2>Escolha uma jornada</h2><p>Os controles só são considerados ativos com evidência de WSO2.</p></div><button class="text-link" data-nav="journeys">Ver todas →</button></div>${storyCards()}
     <div class="v5-panel"><h2>Quatro experiências, quatro clientes reais</h2>${channelsGrid()}</div>`;}
  function channelsGrid(){ return `<div class="v5-channel-grid">${FOUR.map(x=>`<article class="v5-channel ${x.brand}"><span>${x.brand==='aurora'?'A':'b.'}</span><strong>${x.label}</strong><small>${verified(x.key)?'Sessão WSO2 verificada':'Não autenticado neste cliente'}</small><div class="v5-channel-actions"><a href="${x.path}">Abrir experiência →</a><a class="v5-login-link" href="${authPath(x)}">Entrar com WSO2 ↗</a></div></article>`).join('')}</div>`; }
  function journeys(){const s=STORY[activeStory], step=s.steps[activeStep];return `${intro('DEMONSTRAÇÕES GUIADAS','Jornadas que conectam negócio e arquitetura','O conteúdo é guiado, mas autenticação e resultados só vêm de endpoints WSO2 reais.')}
    <div class="journey-layout"><div class="journey-list">${STORY.map((x,i)=>`<button data-story="${i}" class="journey-row ${i===activeStory?'journey-selected':''}"><span class="story-icon bg-${x.color}">${icon('journeys')}</span><span><small>${x.eyebrow}</small><strong>${x.title}</strong></span>›</button>`).join('')}</div>
    <div class="journey-detail"><div class="journey-top"><span class="overline">JORNADA ${s.number}</span><span class="badge badge-teal">Roteiro operacional</span></div><h2>${s.title}</h2><p class="lead">${s.desc}</p>
    <div class="journey-persona"><div class="person-avatar">IS</div><div><small>FONTE DE IDENTIDADE</small><strong>WSO2 Identity Server 7.3</strong></div><span class="persona-role">Sem troca de persona fictícia</span></div>
    <div class="steps-title">Roteiro de demonstração <span>${activeStep+1} de ${s.steps.length}</span></div>
    <div class="step-progress">${s.steps.map((_,i)=>`<button aria-label="Ir para etapa ${i+1}" data-step="${i}" class="${i<=activeStep?'progress-on':''} ${i===activeStep?'progress-current':''}"></button>`).join('')}</div>
    <div class="step-box"><div class="step-number">0${activeStep+1}</div><h3>${step[0]}</h3><p>${step[1]}</p><div class="step-cta"><button class="btn btn-primary" data-target="${step[2]}">Abrir etapa →</button></div></div>
    <div class="step-nav"><button data-action="prev" ${activeStep===0?'disabled':''}>← Anterior</button><button data-action="next" ${activeStep===s.steps.length-1?'disabled':''}>Próxima →</button></div>
    ${technical?`<div class="technical-spec"><h4>Controles de arquitetura</h4><div class="chips">${s.controls.map(x=>`<span>${x}</span>`).join('')}</div><p>Provas de execução: consulte a aba Evidências e a resposta de autorização do BFF. Este roteiro não grava resultados falsos.</p></div>`:''}</div></div>`;}
  function channels(){return `${intro('CANAIS OIDC','Quatro websites e quatro logins independentes','Aurora e Brisa possuem tenants distintos. Web e Mobile utilizam clientes OIDC próprios.')}${channelsGrid()}${card('Separação real','O mesmo navegador pode ter sessões diferentes, mas nenhuma é interpretada como autenticação em outro client. Issuer, token ativo, audiência e escopos são checados no backend.')}`;}
  function informative(which){
    const items={
      privacy:['Privacidade e consentimento','O UserInfo é real; preferências e concessões de consentimento ainda não estão integradas ao serviço v2 do WSO2. Nenhuma preferência fictícia é editável.'],
      security:['Segurança e atributos','Acr, amr, roles e atributos só são exibidos quando emitidos e verificados. A aprovação exige TOTP recente, mas o fluxo positivo ainda precisa ser provisionado e testado.'],
      identities:['Identidades WSO2','Não há seleção de personas simuladas. Cada card abaixo representa exclusivamente um client e o estado de sua sessão real.'],
      evidence:['Evidências e testes','Esta tela mostra estados atuais das quatro sessões e dos endpoints de saúde. Testes históricos estão documentados no repositório e não são apresentados como validação de novos clientes.'],
      b2b:['Parceiros B2B','Papéis seller e customer funcionam via API RBAC. Organizações subordinadas, compartilhamento de aplicação e administração delegada ainda precisam de provisão e prova positiva.'],
      delegation:['Agentes e delegação','Token Exchange e workload identities não foram verificados como fluxos reais. Esta área mantém o roteiro e bloqueia qualquer sucesso sintético.']
    };
    const [title,desc]=items[which]||items.evidence;
    return `${intro('LABORATÓRIO DE IDENTIDADE',title,desc)}<div class="v5-panel"><h2>Estado de cada canal</h2>${sessionCards()}</div>
      ${which==='evidence'?'<div class="v5-panel"><h2>Disponibilidade da autoridade</h2><button class="btn btn-secondary" data-action="discovery">Consultar descoberta OIDC ao vivo</button><pre id="v5-discovery" aria-live="polite">Aguardando consulta</pre></div>':''}
      <div class="v5-panel"><h2>Escopo da funcionalidade</h2><p>Dados retornados pela API são verificados por introspecção no WSO2 a cada solicitação. Não é permitido exibir roles, atributos, consentimentos, transações ou provas de MFA inventadas.</p></div>`;
  }
  function sessionCards(){return `<div class="v5-channel-grid">${FOUR.map(x=>`<div class="v5-card v5-session" data-client="${x.key}"><h3>${x.label}</h3><p class="v5-real-state">Verificando...</p><p class="v5-real-scopes">Nenhum scope confirmado</p><p class="v5-real-roles"></p><a href="${x.path}">Abrir canal →</a></div>`).join('')}</div>`;}
  function labPage(){
    const areas={home:'Início',journeys:'Jornadas guiadas',channels:'Quatro experiências',aurora:'Aurora Store',brisa:'Brisa Living',privacy:'Privacidade',security:'Segurança e atributos',identities:'Identidades WSO2',evidence:'Evidências e testes',b2b:'Parceiros B2B',delegation:'Agentes e delegação'};
    const content=selected==='home'?home():selected==='journeys'?journeys():selected==='channels'?channels():selected==='aurora'||selected==='brisa'?`${intro('EXPERIÊNCIAS DE MARCA',selected==='aurora'?'Aurora Store':'Brisa Living','Escolha Web ou Mobile e autentique-se por um client OIDC independente.')}${channelsGrid()}`:informative(selected);
    root.innerHTML=shell(content,areas[selected]||'Início');
    document.querySelectorAll('.v5-session').forEach(div=>{
      const key=div.dataset.client, client=me?.clients?.[key], ok=client?.authenticated;
      div.querySelector('.v5-real-state').textContent=ok?`Autenticado · issuer ${client.issuer}`:'Não autenticado neste client';
      div.querySelector('.v5-real-scopes').textContent=ok?`Scopes WSO2: ${(client.permissions||[]).join(', ')||'nenhum ciam:*'}`:'Aguardando login WSO2';
      div.querySelector('.v5-real-roles').textContent=ok?`Roles (ID token): ${(client.rolesFromVerifiedIdToken||[]).join(', ')||'claim não emitido'}`:'';
    });
  }
  function sitePage(){
    const x=site, c=me?.clients?.[x.key], signed=c?.authenticated===true;
    const name=x.brand==='aurora'?'AURORA':'brisa.', mobile=x.channel==='mobile';
    root.innerHTML=`<div class="retail-site retail-${x.brand} ${mobile?'v5-mobile-site':''}">
      <div class="rt-demo-banner"><strong>DEMONSTRAÇÃO COM IDENTIDADE REAL</strong><span>Catálogo ilustrativo · Sem pedidos ou pagamentos fictícios</span><a href="/lab">Voltar ao Experience Center →</a></div>
      <div class="rt-service-strip"><span>WSO2 Identity Server 7.3 · ${x.brand.toUpperCase()} TENANT</span><span>${mobile?'Canal Mobile · Cliente próprio':'Canal Web · Cliente próprio'}</span></div>
      <header class="rt-header"><div class="rt-header-inner"><a class="rt-wordmark" href="${x.path}">${name}<small>${mobile?'MOBILE':'STORE'}</small></a>
      <nav class="rt-primary-nav" aria-label="Experiências"><a href="/lab">Lab</a><a href="/portal/aurora/web">Aurora Web</a><a href="/portal/aurora/mobile">Aurora Mobile</a><a href="/portal/brisa/web">Brisa Web</a><a href="/portal/brisa/mobile">Brisa Mobile</a></nav>
      <a class="v5-header-login" href="${authPath(x)}">${signed?'Trocar conta WSO2':'Entrar com WSO2'} ↗</a></div></header>
      <div class="v5-identity-strip"><strong id="site-identity">${signed?'Sessão real verificada':'Ainda não autenticado'}</strong><span id="site-issuer"></span>
      <a class="v5-strip-login" href="${authPath(x)}">${signed?'Autenticar novamente':'Entrar agora com WSO2'} ↗</a>
      <button data-action="reload" class="rt-btn rt-btn-outline">Atualizar</button><button data-action="logout" class="rt-btn rt-btn-outline" ${signed?'':'disabled'}>Encerrar sessão local</button></div>
      <section class="rt-hero"><div class="rt-hero-copy"><span class="rt-kicker">${x.brand==='aurora'?'TECNOLOGIA PARA A SUA VIDA':'CASA, CUIDADO E BEM-ESTAR'}</span>
      <h1>${x.brand==='aurora'?'Mais possibilidades<br><em>em cada momento.</em>':'A beleza mora<br><em>nos detalhes.</em>'}</h1>
      <p>Explore a coleção e acesse sua conta real, com autenticação pelo WSO2 e isolamento entre marcas e canais.</p>
      <div class="v5-hero-cta"><button id="site-login" class="rt-btn rt-btn-solid">${signed?'Entrar novamente no WSO2':'Entrar com WSO2'}</button><a class="rt-btn rt-btn-outline" href="#site-account">Minha conta verificada</a></div></div>
      <div class="v5-product-hero" aria-hidden="true">${x.brand==='aurora'?'◉':'✦'}</div></section>
      <section class="rt-container rt-section"><div class="rt-section-head"><h2>Seleção ${x.brand==='aurora'?'Aurora':'Brisa'}</h2><span class="badge badge-slate">Catálogo ilustrativo — não carregado do WSO2</span></div>
      <div class="v5-products">${PRODUCTS[x.brand].map(p=>`<article class="v5-product"><div class="v5-product-art" aria-hidden="true">${p[3]}</div><small>${p[1]}</small><h3>${p[0]}</h3><strong>${p[2]}</strong></article>`).join('')}</div></section>
      <section id="site-account" class="rt-container rt-section v5-account"><h2>Minha conta e autorização</h2><div class="v5-account-grid"><article class="v5-panel"><h3>Perfil liberado pelo WSO2</h3>
      <p>O backend valida token, audience, escopo, issuer e vínculo do sujeito antes do UserInfo.</p><button id="site-profile" class="rt-btn rt-btn-solid" ${signed?'':'disabled'}>Consultar UserInfo</button>
      <dl id="site-attributes"></dl><p id="site-profile-result" role="status"></p></article>
      <article class="v5-panel"><h3>Permissões desta sessão</h3><p id="site-scopes"></p><p id="site-roles"></p><p id="site-assurance"></p></article></div></section>
      <section class="rt-container rt-section v5-account"><h2>Solicitações reais à marca</h2><div class="v5-panel"><p>Dados de negócio persistidos pelo BFF; permissões validadas ao vivo no WSO2.</p>
      <div class="v5-case-form"><label>Assunto<input id="v5-case-title" maxlength="120" placeholder="Assunto da solicitação"></label>
      <label>Descrição<textarea id="v5-case-description" maxlength="1000" rows="3" placeholder="Detalhes"></textarea></label></div>
      <div class="v5-hero-cta"><button id="v5-case-create" class="rt-btn rt-btn-solid" disabled>Criar solicitação</button><button id="v5-case-list-btn" class="rt-btn rt-btn-outline" disabled>Consultar solicitações</button></div>
      <ul id="v5-case-list"></ul><p id="v5-case-result" role="status">Aguardando escopos WSO2...</p>
      <div class="v5-case-approve"><label>UUID para aprovar<input id="v5-case-uuid" placeholder="UUID da solicitação"></label><button id="v5-case-approve" class="rt-btn rt-btn-outline" disabled>Validar autorização e MFA para aprovação</button></div></div></section>
      <section class="rt-container rt-section v5-panel"><h3>Privacidade, MFA e parceiros</h3><p>Preferências e delegação organizacional não são simuladas. Aprovações exigem TOTP recente real no ID token, além do escopo de aprovação.</p>
      <a href="/lab#privacy">Abrir roteiro de privacidade</a> · <a href="/lab#security">Segurança e assurance</a></section>
      <footer class="v5-footer">${x.label} · Tenant ${x.brand}.identity.test · Verificação WSO2 por solicitação protegida</footer></div>`;
    if (signed){
      el('site-identity').textContent=c?.claimsFromVerifiedIdToken?.name || c?.claimsFromVerifiedIdToken?.preferred_username || 'Identidade verificada no WSO2';
      el('site-issuer').textContent=`Issuer: ${c.issuer} · fingerprint: ${c.subjectFingerprint}`;
      el('site-scopes').textContent=`Escopos: ${scopes(x.key).join(', ')||'nenhum ciam:*'}`;
      el('site-roles').textContent=`Papéis declarados no ID token: ${(c.rolesFromVerifiedIdToken||[]).join(', ')||'claim não fornecido pelo WSO2'}`;
      el('site-assurance').textContent=`ACR: ${c.acrFromVerifiedIdToken||'não fornecido'} · AMR: ${(c.amrFromVerifiedIdToken||[]).join(', ')||'não fornecido'} (somente evidência declarada)`;
      el('v5-case-create').disabled=!scopes(x.key).includes('ciam:cases:create');
      el('v5-case-list-btn').disabled=!scopes(x.key).includes('ciam:cases:read');
      el('v5-case-approve').disabled=!scopes(x.key).includes('ciam:cases:approve');
      el('v5-case-result').textContent=`Canal ${x.key}. Permissões determinadas por WSO2, não pela interface.`;
    } else {
      el('site-scopes').textContent='Faça login para consultar escopos ativos no WSO2.';
      el('site-roles').textContent='Roles não são inferidos de personas.';
      el('site-assurance').textContent='Nenhuma autenticação verificada.';
    }
    el('site-login').onclick=()=>loginFor(x);
    el('site-profile').onclick=readProfile;
    el('v5-case-list-btn').onclick=loadCases;
    el('v5-case-create').onclick=createCase;
    el('v5-case-approve').onclick=approveCase;
  }
  async function readProfile(){
    if(!site||!verified(site.key))return;
    const out=el('site-profile-result'); out.textContent='Consultando WSO2 UserInfo...';
    const {response,data}=await get(`/api/brands/${site.brand}/profile?client=${encodeURIComponent(site.key)}`);
    const dl=el('site-attributes');dl.replaceChildren();
    if(!response.ok){out.textContent=`HTTP ${response.status}: ${data.error||'acesso negado'}`;return;}
    for(const [k,v] of Object.entries(data.attributes||{})) {
      if (typeof v === 'string' || typeof v === 'number') {
        addText(dl,'dt',k); addText(dl,'dd',v);
      }
    }
    if (!dl.children.length) addText(dl,'dd','WSO2 não liberou atributos adicionais.');
    out.textContent='UserInfo confirmado no WSO2 para o sujeito do ID token.';
  }
  const caseUrl=(extra='')=>`/api/brands/${site.brand}/cases${extra}?client=${encodeURIComponent(site.key)}`;
  async function loadCases(){
    if(!site||!verified(site.key))return;
    const out=el('v5-case-result');out.textContent='Consultando autorização e solicitações...';
    const {response,data}=await get(caseUrl());
    if(!response.ok){out.textContent=`HTTP ${response.status}: ${data.error||'acesso negado'}`;return;}
    const ul=el('v5-case-list');ul.replaceChildren();
    for (const record of data.records||[]){
      addText(ul,'li',`${record.id} · ${record.title} · ${record.status}`);
    }
    out.textContent=`${(data.records||[]).length} solicitações persistidas · visibilidade ${data.visibility}`;
     if(new URLSearchParams(location.search).get('approval')==='check')
       out.textContent += ' · Confira acima o estado persistido após o retorno do WSO2.';
  }
  async function postCase(url,payload){
    if (!me?.csrf) throw Error('CSRF indisponível');
    return get(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf},
      body:JSON.stringify(payload||{})});
  }
  async function createCase(){
    const out=el('v5-case-result');
    const title=el('v5-case-title').value.trim(), description=el('v5-case-description').value;
    if(title.length<3){out.textContent='Assunto deve ter ao menos 3 caracteres.';return;}
    const {response,data}=await postCase(caseUrl(),{title,description});
    out.textContent=response.status===201?`Criada: ${data.id} · OPEN`:`HTTP ${response.status}: ${data.error}`;
    if(response.status===201)await loadCases();
  }
  async function approveCase(){
    const out=el('v5-case-result'), id=el('v5-case-uuid').value.trim();
    if(!/^[0-9a-f-]{36}$/i.test(id)){out.textContent='UUID inválido';return;}
    const {response,data}=await postCase(caseUrl(`/${id}/approve`));
    if(response.status===202 && data.status==='WSO2_TOTP_STEP_UP_REQUIRED' &&
       typeof data.authorizationUrl==='string') {
       out.textContent='Redirecionando para autenticação TOTP real do WSO2...';
       location.assign(data.authorizationUrl);return;
     }
     out.textContent=`HTTP ${response.status}: ${data.error||'falha de autorização'}`;
  }
  async function logout(){
    if(!me?.csrf)return;
    const {response}=await get('/api/logout',{method:'POST',headers:{'X-CSRF-Token':me.csrf}});
    if(response.ok) location.assign(site?site.path:'/lab');
  }
  function navigate(name){selected=name; if(name!=='journeys')activeStep=0;history.replaceState(null,'',`/lab#${name}`);labPage();}
  root.addEventListener('click', async e=>{
    const button=e.target.closest('[data-nav],[data-story],[data-step],[data-target],[data-action]');
    if(!button)return;
    if(button.dataset.nav){navigate(button.dataset.nav);return;}
    if(button.dataset.story!==undefined){activeStory=Number(button.dataset.story);activeStep=0;navigate('journeys');return;}
    if(button.dataset.step!==undefined){activeStep=Number(button.dataset.step);labPage();return;}
    if(button.dataset.target){const t=button.dataset.target, x=FOUR.find(v=>v.key===t);if(x){location.assign(x.path);}else navigate(t);return;}
    switch(button.dataset.action){
      case 'prev':activeStep=Math.max(0,activeStep-1);labPage();break;
      case 'next':activeStep=Math.min(STORY[activeStory].steps.length-1,activeStep+1);labPage();break;
      case 'technical':technical=true;labPage();break;
      case 'presenter':technical=false;labPage();break;
      case 'reload':try{await reload();}catch(err){alert(err.message);}break;
      case 'logout':await logout();break;
      case 'menu':document.querySelector('.sidebar')?.classList.toggle('sidebar-open');break;
      case 'discovery':{
        const output=el('v5-discovery');output.textContent='Consultando descoberta...';
        const {response,data}=await get('/api/wso2-status');
        output.textContent=response.ok?(data.statuses||[]).map(x=>`${x.key}: ${x.discovery?'discovery OK':'indisponível'}`).join('\n'):`HTTP ${response.status}`;break;
      }
    }
  });
  window.addEventListener('hashchange',()=>{if(!site){selected=location.hash.slice(1)||'home';if(!['home','journeys','channels','aurora','brisa','privacy','security','identities','evidence','b2b','delegation'].includes(selected))selected='home';labPage();}});
  if(!site){selected=location.hash.slice(1)||'home';if(!['home','journeys','channels','aurora','brisa','privacy','security','identities','evidence','b2b','delegation'].includes(selected)) selected='home';}
  reload().catch(err=>{root.innerHTML=`<main class="v5-error"><h1>Autoridade indisponível</h1><p>Sem fallback sintético. Verifique o WSO2 e o BFF.</p><a href="/lab">Tentar novamente</a></main>`;console.error('WSO2 live session unavailable',err.message);});
})();
