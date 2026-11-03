/** P1.23: strict, text-minimizing interpretation of GET-only Phase 4 evidence.
 * Does not grant scopes, rewrite desired.json or treat revocation as success. */
const BRANDS = new Set(['aurora','brisa']);
const CHANNELS = new Set(['web','app']);
const KINDS = new Set(['customer','seller','administrator']);
const APPROVE='ciam:cases:approve';
const EXACT=['ciam:cases:read','ciam:cases:review'];
const invalid=(reason)=>({ok:false,kind:'UNVERIFIED',summary:`Role evidence unavailable: ${reason}`});
const parse=(raw)=>{try{return JSON.parse(raw);}catch{return null;}};

export function evaluateBusinessVerify(raw){
  const d=parse(raw);
  if(d?.stage==='CIAM_BUSINESS_V4' && d?.mode==='VERIFY' && d?.readback==='VERIFIED' &&
     d?.businessRuntime==='NOT_TESTED' && !('remoteWrites' in d)) {
    return {ok:true,summary:'Phase 4 API, authorized apps and roles verified by GET-only management readback; business runtime still NOT_TESTED'};
  }
  return invalid('PHASE4_VERIFY_UNRECOGNIZED');
}

export function evaluateBusinessRoleAudit(raw){
  const d=parse(raw);
  if(d?.diagnostic!=='CIAM_PHASE4_ROLE_EVIDENCE_V1' || d?.method!=='GET_ONLY' ||
    d?.sourceDigestsVerified!==true || d?.roleApiVersion!=='v2' ||
    !Array.isArray(d?.rows) || d.rows.length<1 || d.rows.length>12 ||
    d.rolesChecked!==d.rows.length || !Number.isInteger(d.rolesNotMatching) ||
    d.rolesNotMatching<0 || d.rolesNotMatching>d.rows.length) return invalid('ROLE_AUDIT_SCHEMA');
  let matched=0;const issues=[],seen=new Set();let other=0;
  for(const r of d.rows){
    if(!BRANDS.has(r.tenant) || !CHANNELS.has(r.channel) || !KINDS.has(r.roleKind))
      return invalid('ROLE_AUDIT_ROW_UNRECOGNIZED');
    const id=`${r.tenant}/${r.channel}/${r.roleKind}`;
    if(seen.has(id))return invalid('ROLE_AUDIT_DUPLICATE_ROLE');seen.add(id);
    if(r.roleGetHttp!==200 || r.roleIdentityMatches!==true ||
      r.audienceMatches!==true || r.membersMatch!==true){other++;continue;}
    if(r.result==='ROLE_PERMISSIONS_MATCH' && r.directPermissions?.exact===true){matched++;continue;}
    const direct=r.directPermissions, projected=r.projectedPermissions;
    const expected=['ciam:cases:approve','ciam:cases:read','ciam:cases:review'];
    const validDrift=(v)=>v?.schema==='SCIM_PERMISSION_OBJECT_ARRAY' &&
      v?.exact===false && v.count===2 &&
      JSON.stringify(v.expected)===JSON.stringify(expected) &&
      JSON.stringify(v.presentExpected)===JSON.stringify(EXACT) &&
      JSON.stringify(v.missingExpected)===JSON.stringify([APPROVE]) &&
      Array.isArray(v.otherKnownScopes) && v.otherKnownScopes.length===0 &&
      v.unknownPermissionValueCount===0 && v.entriesWithoutStringValue===0 &&
      v.nonObjectEntries===0 && v.duplicateValueEntries===0;
    if(r.roleKind==='administrator' && r.result==='ROLE_PERMISSIONS_MISMATCH_CONFIRMED' &&
       r.projectionGetHttp===200 && validDrift(direct) && validDrift(projected)){
      issues.push(`${r.tenant}/${r.channel}`);
    }else other++;
  }
  if(d.rolesNotMatching!==d.rows.length-matched) return invalid('ROLE_AUDIT_COUNT_MISMATCH');
  if(issues.length===4 && other===0 && matched===6 && d.rows.length===10 &&
     d.result==='ROLE_DRIFT_NEEDS_REVIEW' &&
     ['aurora/web','aurora/app','brisa/web','brisa/app'].every(s=>issues.includes(s))){
    return {ok:false,kind:'CONFIRMED_ADMIN_APPROVAL_DRIFT',summary:
      'GET-only SCIM role readback: 6/10 roles match; four administrator roles (Aurora/Brisa Web/App) lack ciam:cases:approve. Customer/seller roles match; grants not changed; policy decision required.'};
  }
  if(d.result==='ALL_ROLES_MATCH' && matched===d.rows.length && d.rolesNotMatching===0 && other===0){
    return {ok:true,kind:'ALL_ROLES_MATCH',summary:`GET-only SCIM role readback: ${matched}/${matched} roles match; independent Phase 4 API readback still required`};
  }
  return invalid('UNEXPECTED_ROLE_DRIFT');
}
