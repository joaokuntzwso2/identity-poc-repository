#!/usr/bin/env python3
"""P2.24 v36: audit or guarded five-scope source transition + full automatic bootstrap.

No manual Console registration. No WSO2 upgrade. One-attempt private journals
are preserved from v33/v34; an uncertain write is never automatically retried.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE=Path(__file__).resolve().parent
IMPL=HERE/'p2_24_v36_full_automatic_directory_bootstrap.py'
V18=Path('scripts/p2/partner_directory_v18.py')
SCOPES=tuple(sorted((
  'internal_org_user_mgt_create','internal_org_user_mgt_list','internal_org_user_mgt_view',
  'internal_org_group_mgt_create','internal_org_group_mgt_view')))
APPROVAL='BOOTSTRAP AURORA DIRECTORY M2M AND DISABLED USERS'

class Problem(Exception):pass

def require(condition,code):
    if not condition:raise Problem(code)

def load_impl():
    spec=importlib.util.spec_from_file_location('v36_impl',IMPL)
    require(spec and spec.loader,'V36_BOOTSTRAP_MODULE_MISSING')
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj)
    return obj

def convert_v18(source):
    """Strict, minimal adjustment; refuse anything other than exact known v18 guard."""
    if "'internal_org_group_mgt_list'" not in source:
        require('V18_ORGANIZATION_SCOPE_CONTRACT_V36' in source,
                'V18_SOURCE_UNEXPECTED_SCOPE_CONTRACT')
        return source,False
    require(source.count("'internal_org_group_mgt_list'")==1,
            'V18_GROUP_LIST_SCOPE_OCCURRENCE_AMBIGUOUS')
    require("V17_SHA='fea42472a4a91d4d04c368131ae4e569b5dc1aa8ce8eb5fe8040ccee344f6a53'" in source,
            'V18_V17_SOURCE_PIN_UNEXPECTED')
    require("len(names)==3 and len(set(names))==3" in source and
            source.count("len(names)==3 and len(set(names))==3")==1,
            'V18_OLD_AUTHORIZED_API_SCOPE_GUARD_NOT_FOUND')
    pat=r"(?m)^    need\(sorted\(allscopes\)==list\(SCOPES\) and len\(set\(allscopes\)\)==6 and\n[^\n]*\n[^\n]*'V18_ACTOR_EXCESS_OR_MISSING_PERMISSION'\)"
    hits=list(re.finditer(pat,source))
    require(len(hits)==1,'V18_SIX_SCOPE_CHECK_NOT_EXACTLY_ONCE')
    result=source.replace("'internal_org_group_mgt_list',",'',1)
    result=result.replace('len(names)==3 and len(set(names))==3',
                          'len(names) in (2,3) and len(set(names))==len(names)',1)
    replacement="""    expected_users={s for s in SCOPES if s.startswith('internal_org_user_mgt_')}
    expected_groups={s for s in SCOPES if s.startswith('internal_org_group_mgt_')}
    need(sorted(allscopes)==list(SCOPES) and len(set(allscopes))==len(SCOPES) and
         {frozenset(x) for x in groups.values()}==
         {frozenset(expected_users),frozenset(expected_groups)},
         'V18_ACTOR_EXCESS_OR_MISSING_PERMISSION')"""
    result=re.sub(pat,lambda m:replacement,result,count=1)
    # Versioned marker prevents another blind transition on subsequent runs.
    result=result.replace("ACTOR_SCHEMA='p2.24.aurora.partner-directory-actor.v18'",
      "ACTOR_SCHEMA='p2.24.aurora.partner-directory-actor.v18'\n# V18_ORGANIZATION_SCOPE_CONTRACT_V36: GA's organization Groups view scope covers GET/list.",1)
    compile(result,'partner_directory_v18.py','exec')
    return result,True

def trace_old_hash_dependencies(repo,old_hash):
    ps=subprocess.run(['git','ls-files','-z'],cwd=repo,capture_output=True,check=True).stdout
    hits=[]
    for raw in ps.split(b'\0'):
        if not raw:continue
        rel=os.fsdecode(raw)
        if rel==str(V18):continue
        p=repo/rel
        if p.is_file() and not p.is_symlink() and p.stat().st_size<500_000 and old_hash in p.read_bytes().decode('utf-8','ignore'):
            hits.append(rel)
    return hits

def checks(repo):
    require((repo/'scripts/ciam-v10.sh').is_file(),'MUST_RUN_FROM_PROJECT_ROOT')
    srcfile=repo/V18
    require(srcfile.is_file() and not srcfile.is_symlink(),'V18_SOURCE_MISSING_OR_SYMLINK')
    source=srcfile.read_text(encoding='utf-8')
    proposed,needs_patch=convert_v18(source)
    require('internal_org_group_mgt_list' not in proposed,
            'UNSUPPORTED_GROUP_LIST_SCOPE_REMAINS_IN_CONTRACT')
    orig_sha=hashlib.sha256(source.encode()).hexdigest()
    proposed_sha=hashlib.sha256(proposed.encode()).hexdigest()
    hits=trace_old_hash_dependencies(repo,orig_sha) if needs_patch else []
    require(not hits,'V18_PINNED_BY_OTHER_TRACKED_SOURCES_REQUIRES_COORDINATION')
    impl=load_impl()
    # v32.context() verifies exact GA image on target 9444, the v17 journal,
    # pinned TLS, Aurora partner identity and business application share.
    ctx=impl.context()
    api=impl.Api(ctx)
    resources=impl.resource_discovery(api,SCOPES)
    require(set(resources)=={'Users','Groups'},'ORG_API_RESOURCES_NOT_EXACT')
    require(set().union(*(set(v[1]) for v in resources.values()))==set(SCOPES),
            'ORG_API_SCOPE_CONTRACT_NOT_EXACT')
    # v33 journal is re-used, never reset/replaced after attempted writes.
    store=impl.Store(ctx['private']/impl.JOURNAL)
    require(store.doc is None or store.doc.get('partnerId')==ctx['partner'],
            'EXISTING_V33_JOURNAL_PARTNER_MISMATCH')
    found=impl.app_candidates(ctx)
    require(len(found)<=1,'MULTIPLE_ACTOR_APPS_DETECTED')
    if store.doc is None:
        require(not found,'UNOWNED_EXISTING_ACTOR_APP_REQUIRES_INVESTIGATION')
    if store.doc is not None:
        require(store.doc.get('name')==impl.NAME,'M2M_JOURNAL_APP_NAME_DRIFT')
    # The actor record (if present) will only be used by the v18 verifier.
    return dict(impl=impl,ctx=ctx,repo=repo,srcfile=srcfile,source=source,
                proposed=proposed,needs_patch=needs_patch,orig_sha=orig_sha,
                proposed_sha=proposed_sha,resources=resources,store=store,found=found)

def file_install_once(src,dst):
    if dst.exists() or dst.is_symlink():
        require(dst.is_file() and not dst.is_symlink() and src.read_bytes()==dst.read_bytes(),
                'PREEXISTING_V36_REPOSITORY_SOURCE_DIFFERS')
        return False
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    fd=os.open(str(dst),flags,0o644)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(src.read_bytes());f.flush();os.fsync(f.fileno())
    except BaseException:
        with contextlib.suppress(OSError):dst.unlink()
        raise
    return True

def patch_v18(stage):
    repo=stage['repo'];src=stage['srcfile']
    if not stage['needs_patch']:
        return False
    # Backups private and immutable, not Git-tracked.
    private=stage['ctx']['private']
    back=private/('p2-v36-partner-directory-v18-'+stage['orig_sha'][:16]+'.backup.py')
    require(not back.is_symlink(),'V18_BACKUP_SYMLINK_BLOCKED')
    if not back.exists():
        oldmask=os.umask(0o077)
        try:
            fd=os.open(str(back),os.O_WRONLY|os.O_EXCL|os.O_CREAT,0o600)
            with os.fdopen(fd,'w') as f:
                f.write(stage['source']);f.flush();os.fsync(f.fileno())
        finally:os.umask(oldmask)
    else:
        require(back.stat().st_uid==os.getuid() and stat.S_IMODE(back.stat().st_mode)==0o600 and
                back.read_text()==stage['source'],'PREEXISTING_V18_BACKUP_INVALID')
    require(src.read_text()==stage['source'],'V18_SOURCE_CHANGED_AFTER_PREFLIGHT')
    fd,tmp=tempfile.mkstemp(prefix='.p2-v36-',dir=src.parent)
    try:
        os.fchmod(fd,src.stat().st_mode & 0o777)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(stage['proposed']);f.flush();os.fsync(f.fileno())
        os.replace(tmp,src)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return True

def main(args):
    require(args==['audit'] or args==['bootstrap',APPROVAL],
            'USE_audit_OR_bootstrap_WITH_EXACT_APPROVAL_PHRASE')
    mode=args[0]
    repo=Path.cwd().resolve(strict=True)
    stage=checks(repo)
    out={'phase':'P2.24','tenant':'aurora.identity.test',
         'status':'PREFLIGHT_VERIFIED','code':'GA_FIVE_SCOPE_ACTOR_BOOTSTRAP_READY',
         'mode':mode,'versionUpgradeAttempted':False,'sharingPostRetried':False,
         'expectedScopes':list(SCOPES),'detectedOrganizationApis':['Users','Groups'],
         'v18SourcePatchRequired':stage['needs_patch'],
         'v18ProposedSha256':stage['proposed_sha'],
         'previousM2mJournalPresent':stage['store'].doc is not None,
         'existingActorApplicationCount':len(stage['found']),
         'managementWritesAttempted':0}
    if mode=='audit':return out
    # Explicit approval covers local v18 patch and separately journaled WSO2 writes.
    patched=patch_v18(stage)
    file_install_once(IMPL,repo/'scripts/p2/p2_24_v36_full_automatic_directory_bootstrap.py')
    file_install_once(HERE/'p2_24_v36_prepare.py',repo/'scripts/p2/p2_24_v36_prepare.py')
    file_install_once(HERE/'test_v36.py',repo/'tests/p2/test_p2_24_v36.py')
    # Source transition is complete before performing any management write.
    updated=load_impl()
    ctx=updated.context()
    require(tuple(ctx['v18'].SCOPES)==SCOPES,'PATCHED_V18_SCOPE_CONTRACT_NOT_ACTIVE')
    needold=updated.Store(ctx['private']/updated.JOURNAL)
    if needold.doc and needold.doc.get('attempts',{}).get('SHARE_ACTOR'):
        out['priorShareAttemptRecorded']=True
    outcome=updated.bootstrap(ctx,updated.Api(ctx),updated.resource_discovery(updated.Api(ctx),SCOPES))
    out.update({'status':'VERIFIED','code':'AUTOMATED_ACTOR_AND_DIRECTORY_VERIFIED',
                'v18SourcePatched':patched,'managementWritesAttempted':'SEE_PRIVATE_V33_AND_V18_JOURNALS',
                **outcome})
    return out

if __name__=='__main__':
    mode=sys.argv[1] if len(sys.argv)>1 else '?'
    try:
        data=main(sys.argv[1:]);exitcode=0
    except Problem as e:
        data={'phase':'P2.24','code':str(e),'status':'BLOCKED','mode':mode,
              'wso2ManagementWritesAttempted':0 if mode=='audit' else 'CHECK_PRIVATE_V33_V18_JOURNALS',
              'sharingPostRetried':False};exitcode=2
    except Exception as e:
        code=str(e) if type(e).__name__ in ('Block','Guard','Stop','Refuse','CatalogError') and re.fullmatch('[A-Z0-9_]{4,160}',str(e)) else 'UNEXPECTED_REVIEW_JOURNALS'
        data={'phase':'P2.24','code':code,'status':'BLOCKED','mode':mode,
              'errorClass':type(e).__name__,
              'wso2ManagementWritesAttempted':0 if mode=='audit' else 'CHECK_PRIVATE_V33_V18_JOURNALS',
              'sharingPostRetried':False};exitcode=3
    print(json.dumps(data,sort_keys=True,indent=2),flush=True)
    raise SystemExit(exitcode)
