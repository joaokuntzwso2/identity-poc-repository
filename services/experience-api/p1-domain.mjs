// Fictional lab authorization fixtures. NO tokens, authentication or WSO2 results.
export const scenarios=Object.freeze([
 {id:'pairwise',name:'Identidade por setor',domain:'identity',requires:'live-wso2',detail:'Assinatura e sub consistente entre canais; distinto entre marcas.'},
 {id:'claims',name:'Minimização de claims',domain:'identity',requires:'live-wso2',detail:'Dois clients com políticas mínimas distintas.'},
 {id:'step-up',name:'Autenticação step-up',domain:'identity',requires:'live-wso2',detail:'Elevação efetiva de garantia com fator real.'},
 {id:'consent',name:'Consentimento por marca',domain:'privacy',requires:'live-wso2',detail:'Decisão persistente e enforcement integrado ao IdP.'},
 {id:'exchange',name:'Delegação RFC 8693',domain:'authorization',requires:'live-wso2',detail:'Token assinado, actor, escopo reduzido, issued_token_type.'},
 {id:'stores',name:'Dois repositórios de usuários',domain:'identity',requires:'live-wso2',detail:'Autenticação real em fontes distintas.'},
 {id:'onboarding',name:'Provisionamento de marca',domain:'operations',requires:'live-wso2',detail:'Tenant criado e isolamento verificado sem impacto.'},
 {id:'b2b-delegation',name:'Administração B2B delegada',domain:'b2b',requires:'live-wso2',detail:'Hierarquia, representantes e delegação org-scoped.'},
 {id:'cc-resource',name:'M2M e recurso protegido',domain:'authorization',requires:'live-wso2',detail:'Client Credentials real com resource server.'},
 {id:'agent-authorization',name:'Agente e aprovação humana',domain:'authorization',requires:'live-wso2',detail:'Identidade de agente, delegação rastreável, aprovação.'},
 {id:'availability',name:'Disponibilidade e recuperação',domain:'operations',requires:'documentary-contractual',detail:'SLA, arquitetura, teste e compromisso contratual.'},
 {id:'compliance',name:'Segurança e certificações',domain:'operations',requires:'documentary-contractual',detail:'Certificados e acordos vigentes.'},
]);
export const resources=Object.freeze([
 {id:'catalog.read',name:'Catálogo público',method:'GET',path:'/resource/catalog',scope:'catalog.read',brand:'aurora',audience:'aurora-api',description:'Leitura de catálogo de produtos'},
 {id:'orders.read',name:'Pedidos de um consumidor',method:'GET',path:'/resource/orders',scope:'orders.read',brand:'aurora',audience:'aurora-api',requiresUser:true,description:'Informações de pedido restritas ao titular'},
 {id:'orders.write',name:'Criar pedido delegado',method:'POST',path:'/resource/orders',scope:'orders.write',brand:'aurora',audience:'aurora-api',requiresUser:true,requiresApproval:true,description:'Ação de escrita de maior risco'},
 {id:'preferences.read',name:'Preferências privadas',method:'GET',path:'/resource/preferences',scope:'preferences.read',brand:'brisa',audience:'brisa-api',requiresUser:true,requiresConsent:true,description:'Dados sujeitos a finalidade e consentimento'},
 {id:'finance.transfer',name:'Transferência financeira',method:'POST',path:'/resource/transfers',scope:'finance.transfer',brand:'aurora',audience:'aurora-api',requiresUser:true,requiresApproval:true,description:'Fora das permissões dos fixtures'}
]);
export const fixtures=Object.freeze([
 {id:'client-credentials',name:'Client Credentials',kind:'client_credentials',actor:'workload-recommender',subject:null,brand:'aurora',allowedAudiences:['aurora-api'],parentScopes:['catalog.read'],actorScopes:['catalog.read'],maxScopes:['catalog.read'],approval:false,consent:false,description:'Workload em nome próprio, sem subject humano'},
 {id:'token-exchange',name:'User Token Exchange',kind:'token_exchange',actor:'workload-recommender',subject:'customer-ana',brand:'aurora',allowedAudiences:['aurora-api'],parentScopes:['catalog.read','orders.read'],actorScopes:['catalog.read','orders.read'],maxScopes:['catalog.read','orders.read'],approval:false,consent:false,description:'Redução de privilégio via delegated subject; actor preservado'},
 {id:'agent-approved',name:'Agente com aprovação',kind:'agent_delegation',actor:'agent-assistant',subject:'customer-ana',brand:'aurora',allowedAudiences:['aurora-api'],parentScopes:['catalog.read','orders.read','orders.write'],actorScopes:['catalog.read','orders.read','orders.write'],maxScopes:['orders.read','orders.write'],approval:true,consent:false,description:'Identidade própria de agente, delegação e intervenção humana'},
 {id:'agent-unapproved',name:'Agente sem aprovação',kind:'agent_delegation',actor:'agent-assistant',subject:'customer-ana',brand:'aurora',allowedAudiences:['aurora-api'],parentScopes:['orders.write'],actorScopes:['orders.write'],maxScopes:['orders.write'],approval:false,consent:false,description:'Ação de risco sem aprovação'},
 {id:'wrong-audience',name:'Workload sem audience',kind:'client_credentials',actor:'workload-recommender',subject:null,brand:'aurora',allowedAudiences:['external-api'],parentScopes:['catalog.read'],actorScopes:['catalog.read'],maxScopes:['catalog.read'],approval:false,consent:false,description:'Escopo suficiente, audience incorreta'},
 {id:'cross-brand',name:'Pedido sem consentimento',kind:'token_exchange',actor:'workload-recommender',subject:'customer-ana',brand:'brisa',allowedAudiences:['brisa-api'],parentScopes:['preferences.read'],actorScopes:['preferences.read'],maxScopes:['preferences.read'],approval:false,consent:false,description:'Apenas escopo não autoriza finalidade e compartilhamento'}
]);
export function problem(message,status=400){return Object.assign(new Error(message),{status})}
export function evaluateAccess({fixtureId,resourceId,requestedScopes}){
 const fixture=fixtures.find(x=>x.id===fixtureId),resource=resources.find(x=>x.id===resourceId);
 if(!fixture||!resource)throw problem('UNKNOWN_PREVIEW_FIXTURE_OR_RESOURCE',404);
 if(!Array.isArray(requestedScopes)||requestedScopes.length>12||requestedScopes.some(x=>typeof x!=='string'||x.length>50))throw problem('INVALID_SCOPE_REQUEST');
 const requested=[...new Set(requestedScopes)];
 const reasons=[];
 if(requested.some(scope=>!fixture.parentScopes.includes(scope)))reasons.push('SUBJECT_TOKEN_SCOPE_ESCALATION');
 if(requested.some(scope=>!fixture.actorScopes.includes(scope)))reasons.push('ACTOR_SCOPE_ESCALATION');
 if(requested.some(scope=>!fixture.maxScopes.includes(scope)))reasons.push('ACTOR_POLICY_SCOPE_DENIED');
 if(!requested.includes(resource.scope))reasons.push('REQUIRED_SCOPE_MISSING');
 if(fixture.brand!==resource.brand)reasons.push('BRAND_BOUNDARY');
 if(!fixture.allowedAudiences.includes(resource.audience))reasons.push('AUDIENCE_NOT_ALLOWED');
 if(resource.requiresUser&&!fixture.subject)reasons.push('HUMAN_SUBJECT_REQUIRED');
 if(resource.requiresApproval&&!fixture.approval)reasons.push('APPROVAL_REQUIRED');
 if(resource.requiresConsent&&!fixture.consent)reasons.push('PURPOSE_CONSENT_REQUIRED');
 return {allowed:reasons.length===0,reasons:reasons.length?reasons:['POLICY_ALLOWED'],fixture:{id:fixture.id,kind:fixture.kind,actor:fixture.actor,subject:fixture.subject,brand:fixture.brand},resource:{id:resource.id,method:resource.method,path:resource.path,scope:resource.scope,audience:resource.audience},requestedScopes:requested,parentScopes:fixture.parentScopes,attenuated:requested.length<fixture.parentScopes.length,previewOnly:true,issuer:null,accessToken:null};
}
export function validPlan(input,existing=[]){
 const code=String(input?.code||'').trim().toLowerCase(),name=String(input?.name||'').trim();
 const issues=[];
 if(!/^[a-z][a-z0-9-]{2,23}$/.test(code))issues.push('Código: 3–24 caracteres, letras minúsculas, números ou hífen.');
 if(['aurora','brisa'].includes(code)||existing.some(p=>p.code===code))issues.push('Código da marca já reservado.');
 if(name.length<3||name.length>70||/[<>]/.test(name))issues.push('Nome da marca inválido.');
 const urls={sectorUri:input?.sectorUri,webRedirect:input?.webRedirect,mobileRedirect:input?.mobileRedirect};
 for(const [key,raw] of Object.entries(urls)){
  try{const url=new URL(raw);if(url.protocol!=='https:'||url.username||url.password||url.hash||url.hostname==='localhost'||url.hostname==='127.0.0.1'||!url.hostname.includes('.'))throw Error();}
  catch{issues.push(`${key}: obrigatório HTTPS público, sem fragmento nem credenciais.`)}
 }
 if(urls.webRedirect&&urls.mobileRedirect&&urls.webRedirect===urls.mobileRedirect)issues.push('Clients web/mobile exigem redirect URIs distintos.');
 if(typeof input?.stepUp!=='boolean'||typeof input?.independentConsent!=='boolean')issues.push('Políticas explícitas de MFA e consentimento são obrigatórias.');
 if(input?.independentConsent!==true)issues.push('Consentimento isolado por marca é obrigatório.');
 return {valid:issues.length===0,issues,normalized:{code,name,...urls,stepUp:input?.stepUp===true,independentConsent:input?.independentConsent===true}};
}
export function buildPlan(input){
 return {kind:'PROVISIONING_PLAN_ONLY',provisioned:false,identityProvider:'not_configured',topologyDecision:'unverified',sectorBoundary:'one sector for web and mobile within brand',...input,
  steps:[
   {id:'identity-topology',title:'Validar topologia tenant/organização',state:'manual_validation_required'},
   {id:'sector',title:'Publicar documento HTTPS sector_identifier_uri e dois redirect URIs',state:'planned'},
   {id:'clients',title:'Criar dois clients OIDC independentes (web e mobile)',state:'planned'},
   {id:'policies',title:'Aplicar políticas específicas: claims mínimos, MFA e consentimento',state:'planned'},
   {id:'admins',title:'Conceder administração delegada sem ampliar privilégios',state:'planned'},
   {id:'proof',title:'Verificar identificadores, cookies de SSO e isolamento',state:'live_test_required'},
   {id:'rollback',title:'Plano de rollback e regressão dos tenants já operando',state:'manual_validation_required'}],
  expectedAcceptance:['Mesmo sub entre web/mobile da marca','Sub diferente entre marcas','Consentimento não herdado','Sem interrupção aos tenants existentes'],
  rollback:'Desabilitar clients e políticas novos; não alterar tenants existentes; restaurar apenas configurações versionadas da nova marca.'};
}
