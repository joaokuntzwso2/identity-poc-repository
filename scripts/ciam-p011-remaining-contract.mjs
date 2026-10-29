/** Pure, dependency-free safeguards for the real live-security scenario runner. */
export const SCENARIOS=Object.freeze(['canceled-mfa','expired-stepup-transaction','self-approval','expired-session']);
export const browserScenario=value=>typeof value==='string'&&SCENARIOS.includes(value);
export function validateUrl(raw,{wso2=false}={}) {
 try {
  const u=new URL(raw);
  if(u.username||u.password||u.hash)return false;
  if(wso2) return u.protocol==='https:'&&u.hostname==='localhost'&&u.port==='9444';
  return u.protocol==='http:'&&u.hostname==='127.0.0.1'&&u.port==='4400'&&u.pathname==='/'&& !u.search;
 }catch{return false;}
}
export function acceptedAuthCallbackError(raw,base,expectedState){
 try{
  const u=new URL(raw),b=new URL(base);
  return u.origin===b.origin&&u.pathname==='/auth/aurora-web/callback'&&
     u.searchParams.get('error')==='access_denied'&&typeof expectedState==='string'&&
     expectedState.length>=8&&u.searchParams.get('state')===expectedState&&!u.searchParams.has('code');
 }catch{return false;}
}
