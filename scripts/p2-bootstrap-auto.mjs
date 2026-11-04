#!/usr/bin/env node
/** P2.24: one command, no manually copied tokens, guarded WSO2 OAuth integration.
 * Requires an existing bootstrap-authorized M2M OAuth application. It cannot self-grant scopes.
 */
import { readFileSync, lstatSync, openSync, fstatSync, closeSync, constants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname, join, isAbsolute } from 'node:path';
import { execFileSync } from 'node:child_process';
import { reconcile, ROOT_SCOPES, PARTNER_SCOPES } from './p2-bootstrap-core.mjs';
import { clientFor } from './p2-org.mjs';
import { createPartnerClient } from './p2-partner-transport.mjs';
const base='https://localhost:9444';
function secureRead(path) {
  if(!path || !isAbsolute(path))throw Error('BOOTSTRAP_AUTHORITY_BLOCKED_absolute_private_file_required');
  const st=lstatSync(path);
  if(!st.isFile()||st.isSymbolicLink()||(st.mode & 0o077)||st.size>65536||
    (process.getuid && st.uid!==process.getuid()))throw Error('BOOTSTRAP_AUTHORITY_BLOCKED_private_file_not_0600');
  const fd=openSync(path,constants.O_RDONLY | (constants.O_NOFOLLOW||0));
  try {
    const now=fstatSync(fd);
    if(now.ino!==st.ino || now.dev!==st.dev || (now.mode&0o077)||now.size>65536)
      throw Error('BOOTSTRAP_AUTHORITY_BLOCKED_private_file_changed');
    return readFileSync(fd,'utf8');
  } finally {closeSync(fd);}
}
export function loadAuthority(repo,env=process.env) {
  // This file must be produced by the existing bootstrap secrets provider, not the browser.
  const path=env.CIAM_P2_BOOTSTRAP_AUTH_FILE || join(repo,'var','wso2','private','p2-bootstrap-authority.json');
  let raw;
  try {raw=secureRead(path);} catch(e) {
    if(e.code==='ENOENT')throw Error('BOOTSTRAP_AUTHORITY_BLOCKED_existing_bootstrap_m2m_app_not_found');
    throw e;
  }
  let config; try {config=JSON.parse(raw);} catch {throw Error('BOOTSTRAP_AUTHORITY_BLOCKED_invalid_private_config');}
  const own=config?.['aurora.identity.test'];
  if(!own||typeof own.clientId!=='string'||typeof own.clientSecret!=='string'||
    own.clientId.length<8||own.clientSecret.length<8)
    throw Error('BOOTSTRAP_AUTHORITY_BLOCKED_aurora_oauth_client_missing');
  // Credentials are deliberately not returned to CLI output or evidence.
  return {clientId:own.clientId,clientSecret:own.clientSecret};
}
export function verifyRuntimeImage(inspect=(args)=>execFileSync('docker',args,{encoding:'utf8',timeout:5000}).trim()) {
  let image;
  try { image=inspect(['inspect','--format','{{.Config.Image}}','wso2-ciam-v10-is-1']); }
  catch {throw Error('BOOTSTRAP_VERSION_BLOCKED_cannot_inspect_running_wso2_container');}
  if(image!=='wso2/wso2is:7.3.0')throw Error('BOOTSTRAP_VERSION_BLOCKED_unapproved_wso2_image');
  return {runtimeImageTag:image,updateLevel:'NOT_ATTESTED_BY_IMAGE_TAG'};
}
export function createOAuthProvider({credentials,request=fetch}) {
  const basic=Buffer.from(`${credentials.clientId}:${credentials.clientSecret}`).toString('base64');
  async function grant(tenant,fields,expectedScopes,stage) {
    if(tenant!=='aurora.identity.test')throw Error('BOOTSTRAP_TENANT_BLOCKED');
    const form=new URLSearchParams(fields);
    const url=`${base}/t/${tenant}/oauth2/token`;
    let response;
    try {response=await request(url,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(8000),
      headers:{authorization:`Basic ${basic}`,'content-type':'application/x-www-form-urlencoded',accept:'application/json'},
      body:form.toString()});} catch {throw Error('BOOTSTRAP_OAUTH_UNAVAILABLE_no_retry');}
    if(!response.ok || response.status>=300) {
      // Only a recognized OAuth error code is exposed, never raw descriptions,
      // request bodies, tokens, or credentials. Differentiate the two grants.
      let oauthError='unspecified';
      try {
        const raw=await response.text();
        if(raw.length<=4096) {
          const parsed=JSON.parse(raw);
          const candidate=parsed?.error;
          if(typeof candidate==='string' && /^[a-z_]{3,40}$/.test(candidate))
            oauthError=candidate;
        }
      } catch {}
      throw Error(`BOOTSTRAP_AUTHORITY_BLOCKED_${stage}_token_http_${response.status}_${oauthError}`);
    }
    const body=await response.text();
    if(body.length>32768)throw Error('BOOTSTRAP_OAUTH_RESPONSE_TOO_LARGE');
    let data;try{data=JSON.parse(body);}catch{throw Error('BOOTSTRAP_OAUTH_INVALID_RESPONSE');}
    if(data.token_type?.toLowerCase()!=='bearer'||typeof data.access_token!=='string'||
      data.access_token.length<16 || /\s/.test(data.access_token))throw Error('BOOTSTRAP_OAUTH_INVALID_TOKEN');
    if(!Number.isInteger(data.expires_in)||data.expires_in<=0||data.expires_in>3600)
      throw Error('BOOTSTRAP_OAUTH_INVALID_EXPIRY');
    // Require exactly the requested subset; a server omission is never permission.
    const granted=new Set(typeof data.scope==='string'?data.scope.split(/\s+/):[]);
    const missing=expectedScopes.filter(x=>!granted.has(x));
    if(missing.length)throw Error('BOOTSTRAP_AUTHORITY_BLOCKED_missing_grants:'+missing.join(','));
    return {access_token:data.access_token,scope:data.scope};
  }
  return {
    root:async(tenant,scopes)=>grant(tenant,{grant_type:'client_credentials',scope:scopes.join(' ')},scopes,'root'),
    partner:async(tenant,orgId,scopes,token)=>{
      if(!/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(orgId))
        throw Error('BOOTSTRAP_INVALID_PARTNER_ID');
      return grant(tenant,{grant_type:'organization_switch',token,scope:scopes.join(' '),
        switching_organization:orgId},scopes,'organization_switch');
    }
  };
}
async function main(){
  const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('BOOTSTRAP_TLS_VERIFICATION_DISABLED');
  if(process.env.NODE_ENV==='production')throw Error('BOOTSTRAP_PRODUCTION_MUTATION_BLOCKED');
  const mode=process.argv[2] || 'check';
  if(!['check','apply'].includes(mode))throw Error('usage: node scripts/p2-bootstrap-auto.mjs check|apply');
  const version=verifyRuntimeImage();
  const creds=loadAuthority(repo);
  const result=await reconcile({base,write:mode==='apply',
    tokenProvider:createOAuthProvider({credentials:creds}),
    rootClientFactory:token=>clientFor(token),
    partnerClientFactory:(token,config)=>createPartnerClient({token,config}),
    shareApplication:(partnerId,shareMode)=>{
      let out;
      try {
        out=execFileSync('python3',[join(repo,'scripts/p2-bootstrap-share.py'),shareMode,partnerId],
          {encoding:'utf8',timeout:25000,maxBuffer:65536,stdio:['ignore','pipe','pipe']});
      } catch(e) {
        let errorCode='P2_SHARE_STAGE_FAILED';
        try {
          const parsed=JSON.parse(String(e.stderr||''));
          if(parsed.stage==='P2_SHARE' && typeof parsed.error==='string' &&
             /^[A-Z0-9_]{3,130}$/.test(parsed.error))errorCode=parsed.error;
        } catch {}
        throw Error('BOOTSTRAP_SHARE_BLOCKED_'+errorCode);
      }
      const data=JSON.parse(out);
      if(data?.stage!=='P2_SHARE' || !['VERIFIED','MISSING','EMPTY_UNVERIFIED'].includes(data.state))
        throw Error('BOOTSTRAP_SHARE_REPORT_INVALID');
      return data;
    }});
  console.log(JSON.stringify({...result,version},null,2));
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{
  const error=String(e.message||'BOOTSTRAP_FAILED').replace(/[\r\n]/g,' ').slice(0,220);
  console.error(JSON.stringify({phase:'P2.24',status:'BLOCKED_OR_FAILED',error,
    mutationState:'NOT_ASSUMED',evidence:'NO_SUCCESS_REPORTED'}));process.exitCode=1;
});
