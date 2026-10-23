export type Brand='aurora'|'brisa';
export type Section='home'|'discover'|'product'|'favorites'|'cart'|'orders'|'account'|'profile'|'security'|'privacy'|'preferences'|'addresses'|'assurance'|'activity'|'approval';
export type Product={id:string;name:string;category:string;price:number;oldPrice?:number;badge?:string;description:string;art:string;color:string};
export type Order={id:string;lines:{id:string;name:string;price:number;qty:number}[];total:number;status:string;createdAt:string};
export type Snapshot={mode:'synthetic-preview';identityVerified:false;profile:{displayName:string;email:string;city:string;phone:string};preferences:{email:boolean;sms:boolean;orderAlerts:boolean;personalization:boolean};security:{passkeyPreview:boolean;totpPreview:boolean;passwordRotationPreviewAt:string|null};devices:{id:string;label:string;lastSeen:string;active:boolean}[];addresses:{id:string;label:string;street:string;city:string}[];wishlist:string[];orders:Order[];activity:{kind:string;detail:string;createdAt:string}[]};
export type Consent={id:string;origin:Brand;target:Brand;title:string;description:string;purpose:string;scope:string;state:'pending'|'granted'|'denied'|'revoked'|'expired';version:number;expiresAt:string|null};
export type Attribute={attribute:string;display:string;maskedValue:string;source:string;level:string;version:number;verifiedAt:string|null;expiresAt:string|null};
export type CartLine={id:string;qty:number};
export const money=(amount:number)=>new Intl.NumberFormat('pt-BR',{style:'currency',currency:'BRL'}).format(amount);
export const date=(v:string)=>new Intl.DateTimeFormat('pt-BR',{dateStyle:'medium'}).format(new Date(v));
export const previewOrigin=import.meta.env.DEV?'http://127.0.0.1:4317':'';
export async function api<T>(path:string,payload?:Record<string,unknown>):Promise<T>{
 const response=await fetch(`${previewOrigin}/api/${path}`,{method:payload?'POST':'GET',headers:payload?{'Content-Type':'application/json','X-Experience-Preview':'yes'}:undefined,body:payload?JSON.stringify(payload):undefined,credentials:'omit'});
 const body=await response.json();if(!response.ok)throw Error(body.error||`Falha na API de demonstração (${response.status})`);return body as T;
}
export function validCart(lines:CartLine[],products:Product[]){return Array.isArray(lines)&&lines.length<=16&&lines.every(x=>typeof x.id==='string'&&products.some(p=>p.id===x.id)&&Number.isInteger(x.qty)&&x.qty>0&&x.qty<=10)}
export function cartKey(appId:string,persona:string){return `identity-poc:${appId}:${persona}:cart:v1`}
