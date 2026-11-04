/** TLS-verified, allowlisted transport for WSO2 organization-context SCIM2. */
import { endpoints, UUID } from './p2-partner-core.mjs';
export function createPartnerClient({config,token,request=fetch}) {
  const urls=endpoints(config);
  if (typeof token !== 'string' || token.length < 16 || token.length > 32768 || /\s/.test(token))
    throw Error('invalid_management_token');
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0') throw Error('tls_verification_must_remain_enabled');
  return async (method,raw,body)=>{
    const u=new URL(raw);
    const path=`${u.origin}${u.pathname}`;
    const resource=(prefix)=>path.startsWith(prefix+'/') && UUID.test(path.slice(prefix.length+1));
    const list=(prefix)=>path===prefix;
    const validGet=method==='GET' && (path===urls.org ||
      list(urls.groups) || list(urls.users) || resource(urls.groups) || resource(urls.users));
    const validPost=method==='POST' && list(urls.groups);
    const validPatch=method==='PATCH' && resource(urls.groups);
    if (u.origin!==new URL(config.base || 'https://localhost:9444').origin ||
        u.username || u.password || u.hash || (!validGet && !validPost && !validPatch))
      throw Error('request_outside_pinned_organization_scim_paths');
    // Allow canonical, bounded SCIM offset pagination only on pinned list paths.
    const scimListQuery=(list(urls.groups) || list(urls.users)) && method==='GET';
    const match=/^\?startIndex=([1-9][0-9]{0,3})&count=100$/.exec(u.search);
    if (u.search && !(scimListQuery && match && Number(match[1])<=3000))
      throw Error('unapproved_scim_query');
    if (body && !validPost && !validPatch) throw Error('unexpected_request_body');
    const response=await request(u.href,{method,redirect:'manual',signal:AbortSignal.timeout(8000),
      headers:{Accept:'application/scim+json, application/json',Authorization:`Bearer ${token}`,
        ...(body?{'Content-Type':'application/scim+json'}:{})},
      ...(body?{body:JSON.stringify(body)}:{})});
    if (!response.ok || response.status>=300) throw Error(`wso2_http_${response.status}_do_not_retry`);
    const text=await response.text();
    if (text.length>256*1024) throw Error('wso2_response_oversize');
    if (!text) return null;
    try {return JSON.parse(text);}catch{throw Error('wso2_invalid_json');}
  };
}
