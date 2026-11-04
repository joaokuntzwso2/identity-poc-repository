'use strict';
(() => {
  const capabilities = [
    ['P2.24','B2B e administrador delegado','ORG API GA disponível; portal delegado e provas live pendentes','PENDENTE'],
    ['P2.25','Consentimento e preferências','Consent Management v2 requer update 7.3.0.12+','GATE 7.3.0.12+'],
    ['P2.26','Autenticação condicional','Login adaptativo é suportado; política e MFA positivo não atestados','PENDENTE'],
    ['P2.27','Passkeys / WebAuthn','Inscrição e autenticação devem ocorrer no WSO2, com RP origin validado','PENDENTE'],
    ['P2.28','Federação OIDC/SAML','Conexão real, claims, isolamento e falhas de IdP ainda requerem teste','PENDENTE'],
    ['P2.29','SCIM e ciclo de vida','Adapter operator source-only; desativação live e revogação de sessão pendentes','PENDENTE'],
    ['P2.30','Auditoria de segurança','Eventos WSO2 e ledger de casos devem ser correlacionados','PENDENTE'],
    ['P2.31','Marcas e histórias setoriais','Aurora/Brisa já possuem jornadas; evolução P2 não atestada','PENDENTE'],
    ['P2.TE','Delegação OAuth act / Token Exchange','Delegação com ator requer update 7.3.0.18+','GATE 7.3.0.18+']
  ];
  const target = document.getElementById('capabilities');
  for (const [id,title,desc,status] of capabilities) {
    const article=document.createElement('article'); article.className='capability';
    const small=document.createElement('small'); small.textContent=id;
    const h3=document.createElement('h3'); h3.textContent=title;
    const p=document.createElement('p'); p.textContent=desc;
    const badge=document.createElement('span'); badge.className='state'; badge.textContent=status;
    article.append(small,h3,p,badge); target.append(article);
  }
  const channels=[['aurora-web','Aurora Web'],['aurora-app','Aurora Mobile'],['brisa-web','Brisa Web'],['brisa-app','Brisa Mobile']];
  async function refresh(){
    const state=document.getElementById('state'),area=document.getElementById('sessions');
    state.textContent='Atualizando…';area.replaceChildren();
    try {
      const response=await fetch('/api/identity/me',{credentials:'same-origin',cache:'no-store',headers:{accept:'application/json'}});
      if (!response.ok) throw Error('authority unavailable');
      const me=await response.json();
      if (!['WSO2_ID_TOKEN_AND_LIVE_ACCESS_TOKEN','NO_VERIFIED_IDENTITY'].includes(me?.identitySource)) throw Error('unverified source');
      state.textContent = me.authenticated ? 'Sessões ativas verificadas pelo BFF com introspecção WSO2.' : 'Sem sessões WSO2 verificadas. Nenhuma permissão será inferida.';
      for (const [key,title] of channels){
        const data=me.clients?.[key], card=document.createElement('article');card.className='session';
        const h3=document.createElement('h3');h3.textContent=title;
        const p=document.createElement('p');p.textContent=data?.authenticated===true?'WSO2 ativo (introspecção atual)':'Não autenticado neste cliente';
        const scope=document.createElement('p');scope.textContent='Escopos CIAM: '+(data?.authenticated===true && Array.isArray(data.permissions) && data.permissions.length ? data.permissions.join(', ') : 'nenhum confirmado');
        const auth=document.createElement('p');
        const amr=Array.isArray(data?.amrFromVerifiedIdToken)?data.amrFromVerifiedIdToken:[];
        auth.textContent='ACR emitido: '+(data?.acrFromVerifiedIdToken||'não fornecido')+' · AMR emitido: '+(amr.length?amr.join(', '):'não fornecido')+' · auth_time emitido: '+(
          (Number.isSafeInteger(data?.authTimeFromVerifiedIdToken) && data.authTimeFromVerifiedIdToken >= 1 && data.authTimeFromVerifiedIdToken <= 8640000000000) ?
            new Date(data.authTimeFromVerifiedIdToken * 1000).toISOString() : 'não fornecido');
        const note=document.createElement('small');note.textContent='Claims são dados observados, não prova automática de nível de assurance.';
        card.append(h3,p,scope,auth,note);area.append(card);
      }
    } catch {
      state.textContent='WSO2/BFF indisponível ou não verificado. Negar operações protegidas.';
    }
  }
  document.getElementById('refresh').addEventListener('click',refresh);
  refresh();
})();
