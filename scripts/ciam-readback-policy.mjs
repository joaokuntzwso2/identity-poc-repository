/**
 * P1.23 read-only authorization evidence evaluation.
 * This module never writes journals or performs API mutations; it only checks
 * a pre-existing private authority pin and GET-only reconciliation output.
 */
import { lstat, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

const BRANDS=['aurora','brisa'];
const CHANNELS=['web','app'];
const ACCEPTED='API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED';
const safeReason=new Set([
  'JOURNAL_MISSING','JOURNAL_UNSAFE','JOURNAL_UNREADABLE','JOURNAL_UNVERIFIED',
  'JOURNAL_ROLE_API_INVALID','JOURNAL_STATE_INCOMPLETE','READBACK_NOT_JSON',
  'READBACK_NOT_GET_ONLY','READBACK_ROLE_VERSION_MISMATCH','READBACK_API_OR_ROLE_MISSING',
  'READBACK_COMMAND_FAILED'
]);
const blocked=(reason)=>({ok:false,reason:safeReason.has(reason)?reason:'JOURNAL_UNREADABLE'});

export function checkAuthorityJournal(value) {
  if(!value || typeof value!=='object' || Array.isArray(value)) return blocked('JOURNAL_UNREADABLE');
  if(!['v2','v3'].includes(value.roleApiVersion)) return blocked('JOURNAL_ROLE_API_INVALID');
  if(value.apiIdentifier!=='https://api.ciam-v10.test/profile' || value.scope!=='ciam:profile:read')
    return blocked('JOURNAL_UNVERIFIED');
  if(value.acceptance!==ACCEPTED) return blocked('JOURNAL_UNVERIFIED');
  for(const brand of BRANDS) {
    const t=value.tenants?.[brand];
    if(t?.resource?.state!=='verified') return blocked('JOURNAL_STATE_INCOMPLETE');
    for(const channel of CHANNELS) {
      if(t?.authorizations?.[channel]?.state!=='verified' || t?.[`role_${channel}`]?.state!=='verified')
        return blocked('JOURNAL_STATE_INCOMPLETE');
    }
  }
  return {ok:true,version:value.roleApiVersion};
}

export async function readAuthorityJournalPin({env=process.env,home=homedir(),uid=process.getuid?.()}={}) {
  const dir=resolve(env.CIAM_V10_HOME||join(home,'wso2-ciam-v10'));
  const file=join(dir,'private','bootstrap-authority-v10.private.json');
  let fh;
  try {
    const ls=await lstat(file);
    if(!ls.isFile() || ls.isSymbolicLink() || (ls.mode&0o077)!==0 ||
       (uid!==undefined && ls.uid!==uid)) return blocked('JOURNAL_UNSAFE');
    // O_NOFOLLOW protects against the file being replaced by a symlink.
    fh=await open(file,constants.O_RDONLY | (constants.O_NOFOLLOW||0));
    const st=await fh.stat();
    if(!st.isFile() || st.ino!==ls.ino || st.dev!==ls.dev || st.size>1048576 ||
       (st.mode&0o077)!==0 || (uid!==undefined && st.uid!==uid)) return blocked('JOURNAL_UNSAFE');
    const text=await fh.readFile('utf8');
    return checkAuthorityJournal(JSON.parse(text));
  }catch(e) {
    return blocked(e?.code==='ENOENT'?'JOURNAL_MISSING':'JOURNAL_UNREADABLE');
  }finally {await fh?.close();}
}

export function evaluateAuthorityReadback(stdout,version) {
  let data;
  try {data=JSON.parse(stdout);}catch{return blocked('READBACK_NOT_JSON');}
  if(data?.stage!=='CIAM_V10_AUTHORITY' || data?.mode!=='READ_ONLY_RECONCILIATION' || data?.remoteWrites!==0)
    return blocked('READBACK_NOT_GET_ONLY');
  if(data.roleApiVersion!==version) return blocked('READBACK_ROLE_VERSION_MISMATCH');
  for(const brand of BRANDS) {
    const t=data.tenants?.[brand];
    if(t?.businessAPI!=='PRESENT_SCOPE_VERIFIED') return blocked('READBACK_API_OR_ROLE_MISSING');
    for(const channel of CHANNELS) {
      if(t.channels?.[channel]?.apiAuthorization!=='SCOPE_VERIFIED' || t.channels?.[channel]?.role!=='PRESENT')
        return blocked('READBACK_API_OR_ROLE_MISSING');
    }
  }
  return {ok:true,version,summary:'Both tenant profile resources, four authorized apps and four roles verified remotely with zero writes'};
}

/** Extract only fixed-format machine error identifiers, never raw command output. */
export function commandFailureSummary(result) {
  const exit=String(result?.exitCode??'UNKNOWN').replace(/[^A-Za-z0-9_-]/g,'').slice(0,18);
  const errorText=String(result?.stderr||'')+'\n'+String(result?.stdout||'');
  const matches=[...errorText.matchAll(/\b(?:CIAM_[A-Z0-9_]{4,90}|ROLE_API_VERSION_[A-Z0-9_]{4,90}|WSO2_[A-Z0-9_]{4,90}|(?:BUSINESS|AUTHORITY|RESOURCE|PROFILE)_[A-Z0-9_]{4,90})\b/g)]
    .map(x=>x[0]).filter((x,i,all)=>all.indexOf(x)===i).slice(0,3);
  return `exit=${exit||'UNKNOWN'}${matches.length?'; machineCodes='+matches.join(','):''}; raw output withheld`;
}
