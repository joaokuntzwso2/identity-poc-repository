#!/usr/bin/env node
/** Operator-only P2.24 partner SCIM2 CLI. Never send these tokens to the browser. */
import { openSync, fstatSync, lstatSync, readFileSync, closeSync, constants } from 'node:fs';
import { inspectPartner, planGroup, createGroup, planMembership, changeMembership, endpoints } from './p2-partner-core.mjs';
import { createPartnerClient } from './p2-partner-transport.mjs';

function required(x) { if (!process.env[x]) throw Error(`${x}_required`); return process.env[x]; }
function tokenFromPrivateFile() {
  const path=required('CIAM_P2_PARTNER_TOKEN_FILE');
  const st=lstatSync(path);
  if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) ||
      (process.getuid && st.uid !== process.getuid()) || st.size > 32768)
    throw Error('token_file_must_be_owner_only_0600');
  const fd=openSync(path,constants.O_RDONLY | (constants.O_NOFOLLOW||0));
  try {
    const f=fstatSync(fd);
    if (f.ino!==st.ino || f.dev!==st.dev || !f.isFile() || (f.mode&0o077) || f.size>32768)
      throw Error('token_file_changed_or_unsafe');
    const token=readFileSync(fd,'utf8').trim();
    if (token.length<16 || token.length>32768 || /\s/.test(token)) throw Error('invalid_token');
    return token;
  } finally { closeSync(fd); }
}
function configFromEnv() {
  const config={rootTenant:required('CIAM_P2_ROOT_TENANT'),
    orgId:required('CIAM_P2_PARTNER_ORG_ID'),rootId:required('CIAM_P2_ROOT_ORG_ID'),
    allowedGroupId:process.env.CIAM_P2_ALLOWED_GROUP_ID || undefined,
    base:'https://localhost:9444'};
  endpoints(config); return config;
}
async function main() {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0') throw Error('tls_verification_must_remain_enabled');
  const [action,arg1,arg2,arg3]=process.argv.slice(2);
  if(action==='requirements') {
    process.stdout.write(JSON.stringify({phase:'P2.24',liveAcceptance:'NOT_EXECUTED',
      apiVersion:'WSO2 Identity Server 7.3 organization APIs',
      scopes:['internal_org_organization_view','internal_org_user_mgt_list',
        'internal_org_user_mgt_view','internal_org_group_mgt_view',
        'internal_org_group_mgt_create','internal_org_group_mgt_update'],
      context:'WSO2 bearer organization context, not browser-selected org ID',
      writes:'EXPLICIT_APPROVAL_REQUIRED',tenantIsolation:'Aurora/Brisa independent'},null,2)+'\n');
    return;
  }
  const permitted=['inspect','plan-group','create-group','plan-add','add','plan-remove','remove'];
  if (!permitted.includes(action)) throw Error('usage: node scripts/p2-partner.mjs inspect | plan-group <name> | create-group <name> <approval> | plan-add|plan-remove <userId> | add|remove <userId> <approval>');
  const config=configFromEnv(); const client=createPartnerClient({config,token:tokenFromPrivateFile()});
  let result;
  if(action==='inspect')result=await inspectPartner({client,config});
  if(action==='plan-group')result=await planGroup({client,config,name:arg1});
  if(action==='create-group')result=await createGroup({client,config,name:arg1,approval:arg2});
  if(['plan-add','plan-remove','add','remove'].includes(action)) {
    if(!config.allowedGroupId)throw Error('CIAM_P2_ALLOWED_GROUP_ID_required_for_membership');
    const op=action.endsWith('add')?'ADD':'REMOVE';
    if (action.startsWith('plan-')) result=await planMembership({client,config,groupId:config.allowedGroupId,userId:arg1,op});
    else result=await changeMembership({client,config,groupId:config.allowedGroupId,userId:arg1,op,approval:arg2});
  }
  process.stdout.write(JSON.stringify({ok:true,...result},null,2)+'\n');
}
main().catch(e=>{
  const msg=String(e?.message||'unexpected_failure').replace(/[\r\n]/g,' ').slice(0,150);
  console.error(JSON.stringify({ok:false,error:msg})); process.exitCode=1;
});
