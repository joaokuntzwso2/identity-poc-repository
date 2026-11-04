/** Exact Aurora/Verde SCIM URL allowlist; never exposes a generic HTTP proxy. */
import {pinned} from './p224-delegate-core.mjs';
import {UUID} from './p2-partner-core.mjs';
export function delegateClient({config,token,request=fetch}) {
  const ep=pinned(config);
  if(typeof token!=='string'||token.length<16||token.length>32768||/\s/.test(token))
    throw Error('P224_INVALID_BEARER_TOKEN');
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('P224_TLS_BYPASS_REFUSED');
  return async(method,raw,body)=>{
    const u=new URL(raw);
    if(u.origin!=='https://localhost:9444'||u.username||u.password||u.hash)
      throw Error('P224_OUTSIDE_VERIFIED_WSO2_ORIGIN');
    const url=u.origin+u.pathname;
    const resource=(s)=>url.startsWith(s+'/')&&UUID.test(url.slice(s.length+1));
    const list=(s)=>url===s;
    const allow=method==='GET'&&(url===ep.org||list(ep.users)||list(ep.groups)||list(ep.roles)||
      resource(ep.users)||resource(ep.groups)||resource(ep.roles)) ||
      method==='POST'&&(list(ep.users)||list(ep.roles)) ||
      method==='PATCH'&&(resource(ep.groups)||resource(ep.roles));
    if(!allow)throw Error('P224_SCIM_METHOD_OR_PATH_DENIED');
    if(u.search){
      const match=/^\?startIndex=([1-9][0-9]{0,3})&count=100$/.exec(u.search);
      if(!(method==='GET'&&(list(ep.users)||list(ep.groups)||list(ep.roles))&&
        match&&Number(match[1])<=3000))throw Error('P224_UNAPPROVED_SCIM_QUERY');
    }
    if(body && method==='GET')throw Error('P224_GET_BODY_DENIED');
    if(body===undefined && method!=='GET')throw Error('P224_WRITE_BODY_REQUIRED');
    let response;
    try{response=await request(u.href,{method,redirect:'manual',signal:AbortSignal.timeout(8000),
      headers:{Accept:'application/scim+json, application/json',Authorization:`Bearer ${token}`,
        ...(body?{'Content-Type':'application/scim+json'}:{})},
      ...(body?{body:JSON.stringify(body)}:{})});}
    catch{throw Error('P224_WSO2_TRANSPORT_UNCERTAIN_NO_RETRY');}
    if(!response.ok||response.status>=300)throw Error(`P224_WSO2_HTTP_${response.status}_NO_RETRY`);
    const text=await response.text();
    if(text.length>262144)throw Error('P224_WSO2_RESPONSE_TOO_LARGE');
    if(!text)return null;
    try{return JSON.parse(text);}catch{throw Error('P224_WSO2_INVALID_JSON');}
  };
}
