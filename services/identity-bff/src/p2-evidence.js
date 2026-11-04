'use strict';
/* In-browser read-only evidence projection of real BFF responses.
 * No JavaScript-held bearer tokens, passwords, credential management or grants.
 * Treat every result as a live readback, NOT complete centralized event auditing. */
(async () => {
  const root=document.getElementById('p2-inline-root')||document.getElementById('root');
  if(!root)return;
  const clients=[
    ['aurora-web','aurora','Aurora · Web'],['aurora-app','aurora','Aurora · Mobile'],
    ['brisa-web','brisa','Brisa · Web'],['brisa-app','brisa','Brisa · Mobile']
  ];
  const section=(title)=>{const s=document.createElement('section');s.className='v5-panel';
    const h=document.createElement('h2');h.textContent=title;s.append(h);root.append(s);return s;};
  const line=(box,text)=>{const p=document.createElement('p');p.textContent=text;box.append(p);};
  const link=(box,href,text)=>{const a=document.createElement('a');a.href=href;a.textContent=text;box.append(a);};
  async function read(url){
    const r=await fetch(url,{credentials:'same-origin',cache:'no-store',redirect:'error'});
    let data;try{data=await r.json();}catch{data=null;}
    return {status:r.status,ok:r.ok,data};
  }
  root.replaceChildren();
  const intro=section('P2.30 · Evidências observadas e resumos derivados');
  line(intro,'Visão somente leitura. Não coleta logs de WSO2, eventos de IdP, telemetria de autenticação ou trilhas de consentimento. Resultados abaixo não substituem SIEM ou auditoria de produção.');
  link(intro,'/lab#evidence','← Voltar ao Experience Center');
  let me;
  try {
    const out=await read('/api/identity/me');
    if(!out.ok || !['WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN','NO_VERIFIED_IDENTITY'].includes(out.data?.identitySource))throw new Error('authority_unavailable');
    me=out.data;
  } catch {
    line(intro,'BLOQUEADO: o BFF não conseguiu fornecer uma leitura confiável do WSO2. Nenhum fallback local é permitido.');
    return;
  }
  const auth=section('Diretamente observado · WSO2 + BFF');
  line(auth,`Fonte: ${me.identitySource}. Introspecção ao vivo: ${me.evidence||'não declarada'}.`);
  for(const [key,brand,label] of clients){
    const state=me.clients?.[key];const container=document.createElement('div');
    container.className='v5-card';const h=document.createElement('h3');h.textContent=label;container.append(h);
    if(state?.authenticated){
      line(container,'Autenticado: sim; emissor verificado pelo BFF: '+state.issuer);
      line(container,'Escopos ciam:* observados: '+(state.permissions||[]).join(', '));
      line(container,'ACR assinado: '+(state.acrFromVerifiedIdToken||'não fornecido'));
      line(container,'AMR assinado: '+(state.amrFromVerifiedIdToken||[]).join(', '));
      line(container,'O ACR solicitado não demonstra, por si só, a execução de MFA.');
    } else line(container,'Sessão WSO2 não autenticada para este cliente.');
    auth.append(container);
  }
  const cases=section('Diretamente observado · decisões de acesso e solicitações de negócio');
  for(const [key,brand,label] of clients){
    if(me.clients?.[key]?.authenticated!==true)continue;
    try {
      const out=await read(`/api/brands/${brand}/cases?client=${encodeURIComponent(key)}`);
      if(out.ok && Array.isArray(out.data?.records)){
        const approved=out.data.records.filter(v=>v.status==='APPROVED').length;
        line(cases,`${label}: HTTP ${out.status}, visibilidade ${out.data.visibility||'não informada'}, registros visíveis ${out.data.records.length}, aprovados ${approved}.`);
      } else line(cases,`${label}: HTTP ${out.status} / API não autorizada ou indisponível; nenhum resultado fictício.`);
    } catch {line(cases,`${label}: não foi possível ler o endpoint; evidência indisponível.`);}
  }
  if(!clients.some(([key])=>me.clients?.[key]?.authenticated))line(cases,'Faça login em uma marca para testar as regras reais de isolamento de solicitações.');
  const discovery=section('Diretamente observado · OIDC discovery');
  try {
    const response=await read('/api/wso2-status');
    for(const v of response.data?.statuses||[])line(discovery,`${v.key}: ${v.discovery?'issuer de discovery confirmado':'indisponível ou divergente'}`);
    if(!response.ok)line(discovery,`HTTP ${response.status}: sem comprovação de disponibilidade.`);
  }catch{line(discovery,'WSO2 discovery indisponível.');}
  const limitations=section('Não observado nesta visualização');
  line(limitations,'Organizações e permissões delegadas; login federado de IdP externo; eventos nativos de autenticação/MFA; passkey WebAuthn; consentimento v2; mudanças de SCIM; revogação e status de tokens após desativação. Cada um exige sua própria evidência real e os controles de privacidade apropriados.');
  line(limitations,'Métricas acima são resumos derivados apenas dos dados visíveis ao usuário autenticado. Não representam totais globais, eventos de segurança correlacionados ou um histórico temporal.');
  const foot=section('Cenários empresariais · jornada e prova necessária');
  const stories=[
    ['Atendimento Aurora','Cliente Ana e vendedor Marcos','Cliente cria caso → vendedor analisa → aprovação exige TOTP fresco','OIDC, escopos, UserInfo, autorização por caso','Registro criado e lido, TOTP negativo observado; TOTP positivo pendente','Líder de atendimento','Tempo médio de resolução'],
    ['Aprovação sensível','Aprovador autorizado','Iniciar aprovação → política WSO2 → resposta com AMR/auth_time válidos','Conditional auth e TOTP','Desafio positivo e negativo do mesmo caso pendentes','Diretoria de riscos','Fraudes bloqueadas / aprovações válidas'],
    ['Parceiro logístico','Administrador do parceiro Verde','Criação da organização → equipe → aplicação → desligamento','Organizações WSO2, organização SCIM2, RBAC','CLI de provisionamento preparado; aceitação em WSO2 pendente','Operações de parceiros','Tempo de ativação e offboarding'],
    ['Preferências de privacidade','Cliente Aurora ou Brisa','Escolher propósito → salvar → revogar → negar processamento','Consent Management v2 (7.3.0.12+)','BLOQUEADO no GA até upgrade aprovado','Privacidade / DPO','Percentual de consentimentos válidos']
  ];
  for(const [title,persona,journey,tech,evidence,stakeholder,kpi] of stories){
    const article=document.createElement('article');article.className='v5-card';
    const h=document.createElement('h3');h.textContent=title;article.append(h);
    for(const s of [`Persona: ${persona}`,`Jornada: ${journey}`,`WSO2: ${tech}`,`Evidência: ${evidence}`,`Stakeholder: ${stakeholder}`,`KPI potencial: ${kpi}`])line(article,s);
    foot.append(article);
  }
})();
