#!/usr/bin/env node
/** Operator-only P2 delegation, downstream of the verified legacy P2 bootstrap. */
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadAuthority,verifyRuntimeImage,createOAuthProvider} from './p2-bootstrap-auto.mjs';
import {ROOT_SCOPES,PARTNER_SCOPES,reconcile} from './p2-bootstrap-core.mjs';
import {clientFor} from './p2-org.mjs';
import {createPartnerClient} from './p2-partner-transport.mjs';
import {reconcileDelegate,createJournalStore,TENANT,ROOT,PARTNER,GROUP} from './p224-delegate-core.mjs';
import {delegateClient} from './p224-delegate-transport.mjs';
export const DELEGATE_SCOPES=Object.freeze([...new Set([...PARTNER_SCOPES,
  'internal_org_user_mgt_create','internal_org_role_mgt_view','internal_org_role_mgt_create',
  'internal_org_role_mgt_update','internal_org_role_mgt_permissions_update',
  'internal_org_role_mgt_users_update'])]);
async function main(){
  const mode=process.argv[2]||'check';
  if(!['check','apply'].includes(mode))throw Error('P224_DELEGATE_MODE_DENIED');
  if(process.env.NODE_ENV==='production'||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')
    throw Error('P224_PRODUCTION_OR_TLS_POLICY_DENIED');
  verifyRuntimeImage();
  const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  const creds=loadAuthority(repo);
  const tokenProvider=createOAuthProvider({credentials:creds});
  // The preexisting bootstrap must still attest exactly the same Aurora/Verde
  // organization, sharing and group. Don't silently create/recreate these here.
  const foundation=await reconcile({write:false,tokenProvider,
    rootClientFactory:token=>clientFor(token),
    partnerClientFactory:(token,config)=>createPartnerClient({token,config}),
    shareApplication:async(orgId)=>{
      if(orgId!==PARTNER)throw Error('P224_FOREIGN_PARTNER_DENIED');
      // Repeated share verification remains owned by the existing Python stage.
      const {execFileSync}=await import('node:child_process');
      let response;
      try{response=JSON.parse(execFileSync('python3',[join(repo,'scripts/p2-bootstrap-share.py'),'check',orgId],
        {encoding:'utf8',timeout:30000,stdio:['ignore','pipe','ignore']}));}
      catch{throw Error('P224_SHARE_READBACK_UNAVAILABLE');}
      if(response.stage!=='P2_SHARE'||response.state!=='VERIFIED')
        throw Error('P224_SHARE_NOT_VERIFIED');
      return response;
    }});
  if(foundation.existingId!==PARTNER||foundation.rootId!==ROOT||
     foundation.existingGroupId!==GROUP||foundation.applicationSharing!=='VERIFIED'||
     foundation.scimInventory!=='VERIFIED')throw Error('P224_FOUNDATION_READBACK_NOT_VERIFIED');
  const rootToken=await tokenProvider.root(TENANT,ROOT_SCOPES);
  const partnerToken=await tokenProvider.partner(TENANT,PARTNER,DELEGATE_SCOPES,rootToken.access_token);
  const config={base:'https://localhost:9444',rootTenant:TENANT,rootId:ROOT,
    orgId:PARTNER,allowedGroupId:GROUP};
  const home=process.env.CIAM_V10_HOME||join(process.env.HOME||'', 'wso2-ciam-v10');
  const journal=createJournalStore(join(home,'private'));
  const fd=journal.acquire();
  try {
    const value=await reconcileDelegate({client:delegateClient({config,token:partnerToken.access_token}),
      config,journal,write:mode==='apply'});
    process.stdout.write(JSON.stringify(value,null,2)+'\n');
  } finally {journal.release(fd);}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{const raw=String(e.message||'P224_DELEGATE_FAILED');
    const code=/^[A-Z0-9_:.-]{3,150}$/.test(raw)?raw:'P224_DELEGATE_UNEXPECTED_BLOCKED';
    process.stderr.write(JSON.stringify({phase:'P2.24-DELEGATE',status:'BLOCKED',error:code,
      mutationState:'NOT_ASSUMED',userTokenAcceptance:'NOT_EXECUTED'})+'\n');
    process.exitCode=1;});
