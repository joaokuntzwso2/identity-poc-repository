// Synthetic preview domain. This module does not implement real authentication.
export const DEMO_CONSENTS = Object.freeze([
  {id:'aurora-personalization',origin:'aurora',target:'aurora',purpose:'personalization',scope:'recommendations.read',title:'Recomendações personalizadas',description:'Usar preferências dentro de Aurora para sugerir produtos.'},
  {id:'brisa-personalization',origin:'brisa',target:'brisa',purpose:'personalization',scope:'recommendations.read',title:'Inspiração personalizada',description:'Usar preferências apenas dentro de Brisa.'},
  {id:'aurora-to-brisa',origin:'aurora',target:'brisa',purpose:'cross_brand_offers',scope:'preferences.share',title:'Compartilhar preferências com Brisa',description:'Compartilhamento explícito de preferências selecionadas entre marcas.'}
]);
export const DEMO_ATTRIBUTES = Object.freeze([
  {attribute:'email',display:'E-mail',value:'ana@identidade.example',source:'synthetic-email-verification',level:'verified',verifiedAt:'2026-01-12T10:00:00Z',expiresAt:'2027-01-12T10:00:00Z'},
  {attribute:'mobile',display:'Celular',value:'+55 (11) 90000-0000',source:'synthetic-otp',level:'verified',verifiedAt:'2026-01-14T10:00:00Z',expiresAt:'2027-01-14T10:00:00Z'},
  {attribute:'address',display:'Endereço',value:'Endereço fictício, 100',source:'self-declared',level:'self_asserted',verifiedAt:null,expiresAt:null},
  {attribute:'identity_document',display:'Identidade civil',value:'Documento fictício · não válido',source:'synthetic-identity-proof',level:'verified',verifiedAt:'2026-01-10T10:00:00Z',expiresAt:'2027-01-10T10:00:00Z'}
]);
export const transitionMap = Object.freeze({pending:['granted','denied'],granted:['revoked','expired'],denied:['pending'],revoked:['pending'],expired:['pending']});
export function assertTransition(from,to){
  if(!transitionMap[from]?.includes(to)) throw Object.assign(new Error(`TRANSITION_NOT_ALLOWED: ${from} → ${to}`),{status:409});
}
export function isPerson(id){return /^customer-(ana|rafael)$/.test(id)}
export function mask(value){
  if(typeof value !== 'string') return '';
  if(value.includes('@')){const [name,domain]=value.split('@');return `${name.slice(0,2)}•••@${domain}`}
  if(value.startsWith('+'))return '+55 (••) •••••-0000';
  return value;
}
export function validateAttributeChange(attr,value){
  if(!['mobile','address'].includes(attr)) throw Object.assign(new Error('ATTRIBUTE_NOT_EDITABLE'),{status:403});
  if(typeof value!=='string'||value.trim().length<4||value.length>120||/[<>\x00-\x1f]/.test(value))throw Object.assign(new Error('INVALID_ATTRIBUTE_VALUE'),{status:400});
  return value.trim();
}
// Trust must be derived from a verified server-to-server credential in a future WSO2 adapter.
// This function is NEVER exposed as an HTTP endpoint to the preview browser.
const syntheticLinkMap = new Map([
 ['aurora:synthetic-ana-aurora','synthetic-internal-001'],
 ['brisa:synthetic-ana-brisa','synthetic-internal-001'],
 ['aurora:synthetic-rafael-aurora','synthetic-internal-002']
]);
export function resolveCanonicalInternal({actor,sector,subject,requestedSector,consent}){
 if(actor?.kind!=='correlation-service'||actor?.issuerVerified!==true||!actor?.audiences?.includes('identity-correlation'))throw Object.assign(new Error('NOT_AUTHORIZED'),{status:403});
 if(!consent||consent.state!=='granted'||consent.origin!==sector||consent.target!==requestedSector||consent.purpose!=='cross_brand_offers')throw Object.assign(new Error('CONSENT_REQUIRED'),{status:403});
 const resolved=syntheticLinkMap.get(`${sector}:${subject}`);
 if(!resolved)throw Object.assign(new Error('UNKNOWN_SUBJECT'),{status:404});
 return resolved; // Internal identifier: never return via the preview API.
}
