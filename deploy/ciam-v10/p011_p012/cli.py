#!/usr/bin/env python3
"""P0.11/P0.12 add-on for the existing scripts/ciam-v10.sh facade.

Read-only by default; the only mutating authority operation is a separately
approved, single-use wrapper around the repository's existing journaled stage.
"""
from __future__ import annotations
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import urllib.error
import urllib.request
if __package__:
    from . import core
else:
    import core

REPO=Path(__file__).resolve().parents[3]
HOME=Path(os.environ.get('CIAM_V10_HOME',str(Path.home()/'wso2-ciam-v10'))).expanduser()
INSPECTION=HOME/'inspection'
PRIVATE=HOME/'private'
CLI=REPO/'deploy/ciam-v10/cli.py'
AUTHORITY=REPO/'deploy/ciam-v10/authority/bootstrap.py'
P010_DRIVER=REPO/'scripts/ciam-p010-interactive-acceptance.mjs'
P010_PREFLIGHT=REPO/'scripts/ciam-p008-p010-preflight.mjs'
COMMANDS=('offline-test','security-audit','inventory','readiness','live-acceptance','provision-plan','provision-apply')

class Refuse(Exception):pass

def execute(args,*,timeout=120,env=None):
    try:
        r=subprocess.run([str(x) for x in args],cwd=REPO,env=env or os.environ,
                         capture_output=True,timeout=timeout,check=False)
        return r
    except (OSError,subprocess.TimeoutExpired):return None

def summary_run(args,*,timeout=120):
    result=execute(args,timeout=timeout)
    return {'exit':result.returncode if result else None,'status':'PASS' if result and result.returncode==0 else 'BLOCKED' if result is None else 'FAIL'}

def audit():
    tracked=core.audit_tracked(REPO)
    evidence,available=core.audit_inspection(INSPECTION)
    return {'trackedIssues':tracked,'evidenceIssues':evidence,'inspectionAvailable':available,'status':'FAIL' if tracked or evidence else 'PASS'}

def offline_test():
    checks={
        'P011_SELF_UNIT':summary_run([sys.executable,'-m','unittest','discover','-s','deploy/ciam-v10/p011_p012/tests','-p','test_*.py','-v'],timeout=65),
        'EXISTING_BFF_NODE_UNIT_MOCKED_INTEGRATION':summary_run(['npm','test'],timeout=240),
        'EXISTING_V10_PYTHON_UNIT':summary_run([sys.executable,CLI,'test'],timeout=200),
        'P010_BROWSER_DRIVER_SYNTAX_STATIC':summary_run(['node','--check','scripts/ciam-p010-interactive-acceptance.mjs'],timeout=30)
    }
    # Existing Python/Node tests may use local doubles; they do not prove live authentication.
    status='NOT_READY' if any(x['status']=='FAIL' for x in checks.values()) else 'BLOCKED' if any(x['status']=='BLOCKED' for x in checks.values()) else 'READY'
    result={'schema':'ciam-p011.offline.v1','at':core.iso_now(),'checks':checks,'outcome':status,
            'evidenceClasses':['UNIT','MOCKED_INTEGRATION','STATIC'],'liveWso2Tested':False}
    try:
        result['sourceGitSha']=core.source_identity(REPO)[0]
        core.private_write(INSPECTION,'p011-offline',result)
    except (ValueError,OSError):pass # Offline CI does not require a private macOS runtime.
    print(json.dumps(result,indent=2))
    return 0 if status=='READY' else 2

def runtime_id():
    r=execute(['docker','inspect','--format','{{.Id}}|{{.Image}}|{{.State.Running}}','wso2-ciam-v10-is-1'],timeout=7)
    if r is None or r.returncode!=0:return None
    raw=r.stdout.decode('ascii','replace').strip().split('|')
    if len(raw)!=3 or not re.fullmatch(r'[a-f0-9]{64}',raw[0]) or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}',raw[1]) or raw[2]!='true':return None
    try:
        bff_pid=PRIVATE/'bff-v10.pid'
        if bff_pid.is_symlink():return None
        if stat.S_IMODE(bff_pid.stat().st_mode)!=0o600:return None
        pid=int(bff_pid.read_text().strip())
        if pid<=1:return None
        os.kill(pid,0)
    except (OSError,ValueError):return None
    return 'is:'+raw[0][:24]+':image:'+raw[1].removeprefix('sha256:')[:24]+':bffpid:'+str(pid)

def health():
    try:
        with socket.create_connection(('127.0.0.1',9444),timeout=3):wso2_listener=True
    except OSError:wso2_listener=False
    try:
        req=urllib.request.Request('http://127.0.0.1:4400/api/identity/me',headers={'Accept':'application/json'})
        with urllib.request.urlopen(req,timeout=4) as f:
            if f.status!=200:raise ValueError('BFF_NOT_200')
            raw=f.read(100001)
            if len(raw)>100000:raise ValueError('BFF_RESPONSE_TOO_LONG')
            data=json.loads(raw)
            configured=data.get('clients') or {}
            configured4=all(configured.get(k,{}).get('configured') is True for k in ('aurora-web','aurora-app','brisa-web','brisa-app'))
            bff=True
    except (OSError,ValueError,urllib.error.URLError,TypeError,AttributeError):bff=False;configured4=False
    return {'wso2TcpListener':wso2_listener,'bffAnonymousHttp200':bff,'fourConfiguredClientSlots':configured4}

def preflight():
    if not P010_PREFLIGHT.is_file():return False,'P010_PREFLIGHT_MISSING'
    r=execute(['node',P010_PREFLIGHT],timeout=82)
    if r is None or r.returncode!=0:return False,'P010_PREFLIGHT_UNAVAILABLE_OR_FAILED'
    try:
        obj=json.loads(r.stdout)
        if (obj.get('fourClientsReadyForInteractiveLogin') is True and
                obj.get('remoteWrites',0)==0):return True,'FOUR_CLIENT_READBACK_CONFIRMED'
    except (ValueError,TypeError,AttributeError):pass
    return False,'P010_PREFLIGHT_DID_NOT_CONFIRM_FOUR_CLIENTS'

def private_state():
    if not HOME.is_dir() or HOME.is_symlink() or not PRIVATE.is_dir() or PRIVATE.is_symlink():return False
    for p in (HOME,PRIVATE):
        m=p.stat()
        if m.st_uid!=os.getuid() or stat.S_IMODE(m.st_mode)&0o077:return False
    return True

def external_live_reference(row):
    refs=row.get('references')
    if not isinstance(refs,list) or len(refs)!=1:return False,'REFERENCE_COUNT_INVALID'
    ref=refs[0]
    if not isinstance(ref,dict) or not re.fullmatch(r'p010-live-browser-[A-Za-z0-9-]+\.json',str(ref.get('artifact',''))):
        return False,'REFERENCE_FILENAME_INVALID'
    try:
        raw=core.read_private(INSPECTION/ref['artifact'])
        if core.digest(raw)!=ref.get('sha256'):return False,'REFERENCE_TAMPERED'
        obj=json.loads(raw)
        if not core.assess_p010(obj):return False,'P010_LIVE_ASSERTIONS_NOT_MET'
        if abs((core.parse_date(row['timestampUtc'])-core.parse_date(obj['at'])).total_seconds())>2400:
            return False,'LIVE_REFERENCE_TIME_MISMATCH'
    except (OSError,ValueError,TypeError,KeyError,AttributeError):return False,'REFERENCE_MISSING_OR_UNSAFE'
    return True,'LIVE_REFERENCE_CHECKSUM_VERIFIED'

def current_live(sha,runtime):
    if not INSPECTION.is_dir():return False,'NO_INSPECTION_DIRECTORY'
    candidates=sorted(INSPECTION.glob('p011-live-attested-*.json'),reverse=True)
    if not candidates:return False,'NO_CURRENT_LIVE_ACCEPTANCE'
    for p in candidates:
        try:
            row=json.loads(core.read_private(p))
            defect=core.verify_evidence(row,sha,runtime)
            if defect:return False,defect
            if row.get('status')!='PASS' or row.get('evidenceClass')!='BROWSER_E2E':return False,'LIVE_EVIDENCE_NOT_PASS'
            return external_live_reference(row)
        except (OSError,ValueError):return False,'LIVE_EVIDENCE_UNREADABLE'
    return False,'NO_CURRENT_LIVE_ACCEPTANCE'

def report(inventory_only=False):
    gates=[]
    try:sha,dirty=core.source_identity(REPO)
    except ValueError:sha='UNAVAILABLE';dirty=None
    gates.append(core.gate('GIT_SHA','BLOCKED' if sha=='UNAVAILABLE' else 'PASS','STATIC','Git checkout SHA','available' if sha!='UNAVAILABLE' else 'unavailable'))
    gates.append(core.gate('WORKTREE','BLOCKED' if dirty is None else 'FAIL' if dirty else 'PASS','STATIC','clean checkout',
                          'unavailable' if dirty is None else 'dirty' if dirty else 'clean'))
    rt=runtime_id()
    gates.append(core.gate('RUNTIME_ID','PASS' if rt else 'BLOCKED','LIVE_READBACK','verifiable Docker+BFF identity','verified' if rt else 'unavailable'))
    gates.append(core.gate('PRIVATE_CONFIG','PASS' if private_state() else 'BLOCKED','LIVE_READBACK','secure initialized runtime state','secure' if private_state() else 'unavailable-or-unsafe'))
    hp=health()
    for key in hp:
        gates.append(core.gate('HEALTH_'+key,'PASS' if hp[key] else 'BLOCKED','LIVE_READBACK',True,hp[key]))
    ok,reason=preflight()
    gates.append(core.gate('FOUR_CLIENT_WSO2_READBACK','PASS' if ok else 'BLOCKED','LIVE_READBACK','four exact registered OIDC apps/PKCE policy',reason))
    # Existing dedicated readback stages are GET-only. Their private output is never echoed.
    for gate_id,script,action in (
        ('CASE_RESOURCE_ROLE_READBACK',REPO/'deploy/ciam-v10/cases-rbac/bootstrap.py','verify'),
        ('IDENTITY_MEMBERSHIP_READBACK',REPO/'deploy/ciam-v10/identities/bootstrap.py','verify'),
    ):
        r=execute([sys.executable,script,action],timeout=100) if script.is_file() else None
        passed=bool(r and r.returncode==0)
        gates.append(core.gate(gate_id,'PASS' if passed else 'BLOCKED','LIVE_READBACK',
            'existing WSO2-managed scoped object readback', 'VERIFIED' if passed else 'INACCESSIBLE_OR_UNVERIFIED'))
    # Evaluate tracked source independently from inspection evidence. An unsafe blob is NOT_READY.
    try: audit_result=audit()
    except (ValueError,OSError):audit_result={'status':'BLOCKED','trackedIssues':[],'evidenceIssues':[],'inspectionAvailable':False}
    gates.append(core.gate('SECRET_AUDIT',audit_result['status'],'STATIC','zero unresolved tracked/evidence secrets',
                          {'trackedFindings':len(audit_result['trackedIssues']),'evidenceFindings':len(audit_result['evidenceIssues'])}))
    negative_script=REPO/'deploy/ciam-v10/authority/acceptance.py'
    negative=execute([sys.executable,negative_script],timeout=45) if negative_script.is_file() else None
    negative_ok=False
    if negative and negative.returncode==0:
        try:
            result=json.loads(negative.stdout)
            import_automation().verify_anonymous_acceptance(result)
            negative_ok=True
        except Exception:pass  # Existing automation.Refuse is a distinct exception class.
    gates.append(core.gate('ANONYMOUS_NEGATIVE_HTTP_GATES','PASS' if negative_ok else 'BLOCKED',
       'LIVE_READBACK','existing no-session HTTP deny matrix against live BFF',
       'NEGATIVE_HTTP_GATES_VERIFIED' if negative_ok else 'NOT_EXECUTED_OR_UNVERIFIED'))
    if not inventory_only:
        present=sorted(INSPECTION.glob('p011-offline-*.json'),reverse=True) if INSPECTION.is_dir() else []
        offline_ok=False;offline_reason='NO_CURRENT_OFFLINE_EVIDENCE'
        if present:
            try:
                row=json.loads(core.read_private(present[0]))
                if row.get('sourceGitSha')!=sha:offline_reason='OFFLINE_SOURCE_SHA_MISMATCH'
                elif (core.utc_now()-core.parse_date(row.get('at'))).total_seconds()>8*3600:offline_reason='OFFLINE_EVIDENCE_STALE'
                elif row.get('outcome')!='READY':offline_reason='OFFLINE_TESTS_NOT_READY'
                elif not all(c.get('status')=='PASS' for c in row.get('checks',{}).values()):offline_reason='OFFLINE_TEST_RESULTS_INCOMPLETE'
                else:offline_ok=True;offline_reason='CURRENT_UNIT_AND_MOCKED_TESTS_PASSED'
            except (OSError,ValueError,TypeError):offline_reason='OFFLINE_EVIDENCE_INVALID'
        gates.append(core.gate('OFFLINE_TESTS','PASS' if offline_ok else 'BLOCKED','UNIT','complete current-source offline suite',offline_reason))
        live_ok,live_reason=current_live(sha,rt)
        gates.append(core.gate('REAL_BROWSER_TOTP','PASS' if live_ok else 'BLOCKED','BROWSER_E2E','fresh four-client authenticated WSO2 and real TOTP acceptance',live_reason))
        # P010 driver does not verify all mandatory negative cases. Fail closed even on fresh positive journey.
        gates.append(core.gate('FULL_LIVE_NEGATIVE_MATRIX','BLOCKED','LIVE_AUTHENTICATION',
                'callback replay, stale/canceled MFA, revocation, self-approval, SSO/logout and outage tested live',
                'NOT_IMPLEMENTED_IN_EXISTING_OPERATOR_RUNNER'))
        gates.append(core.gate('AUDIT_EVENT_READBACK','BLOCKED','LIVE_READBACK','independent approval audit ledger readback',
                'NOT_ATTESTED_BY_EXISTING_OPERATOR_RUNNER'))
    result={'schema':'ciam-p011.readiness.v1','createdUtc':core.iso_now(),'sourceGitSha':sha,'worktreeDirty':dirty,
            'runtimeIdentity':rt,'outcome':core.combine(gates),'gates':gates,
            'evidenceClassPolicy':'mocked/static results never substituted for live authentication',
            'securityFindings':{'tracked':audit_result['trackedIssues'][:60],
                                'inspection':audit_result['evidenceIssues'][:60]},
            'mode':'inventory' if inventory_only else 'readiness'}
    try:
        target=core.private_write(INSPECTION,'p011-'+result['mode'],result)
        text='# CIAM P0.11/P0.12 '+result['mode']+'\n\n'+'Outcome: **'+result['outcome']+'**  \n' + \
             'Source SHA: `'+sha+'`  \n'+'Runtime: `'+(rt or 'BLOCKED')+'`\n\n' + \
             '| Gate | Class | Status | Observed |\n|---|---|---|---|\n'+''.join(
                 '| '+g['id']+' | '+g['evidenceClass']+' | '+g['status']+' | '+str(g['observed']).replace('|','/')[:110]+' |\n' for g in gates)
        md=target.with_suffix('.md')
        fd=os.open(md,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:f.write(text)
        manifest={'schema':'ciam-p011.evidence-manifest.v1','createdUtc':core.iso_now(),
                  'sourceGitSha':sha,'runtimeIdentity':rt,'artifacts':[
                    {'file':target.name,'evidenceClass':'STATIC','sha256':core.digest(core.read_private(target)),'status':'RECORDED'},
                    {'file':md.name,'evidenceClass':'STATIC','sha256':core.digest(core.read_private(md)),'status':'RECORDED'},
                  ]}
        for pat,kind in (('p011-offline-*.json','UNIT'),('p011-live-attested-*.json','BROWSER_E2E')):
            found=sorted(INSPECTION.glob(pat),reverse=True)
            if found:
                try:
                    raw_e=core.read_private(found[0]); j=json.loads(raw_e)
                    provenance=('MATCHED' if j.get('sourceGitSha')==sha else 'SOURCE_SHA_MISMATCH')
                    if kind=='BROWSER_E2E' and core.verify_evidence(j,sha,rt) is not None:
                        provenance='NOT_CURRENT_OR_VERIFIED'
                    manifest['artifacts'].append({'file':found[0].name,'evidenceClass':kind,
                                                  'sha256':core.digest(raw_e),'status':provenance})
                except (OSError,ValueError):
                    manifest['artifacts'].append({'file':'UNREADABLE_PRIVATE_ARTIFACT','evidenceClass':kind,
                                                  'status':'BLOCKED'})
        manifest_path=core.private_write(INSPECTION,'p011-evidence-manifest',manifest)
        files={'json':str(target),'markdown':str(md),'manifest':str(manifest_path)}
    except (OSError,ValueError) as e:files={'unavailable':'PRIVATE_REPORT_WRITE_REFUSED'}
    print(json.dumps({'outcome':result['outcome'],'sourceGitSha':sha,'runtimeIdentity':rt,'gates':gates,
                      'findingsCount':len(audit_result['trackedIssues'])+len(audit_result['evidenceIssues']),
                      'files':files},indent=2))
    return 0 if result['outcome']=='READY' else 2

def security_audit():
    try:a=audit()
    except (ValueError,OSError):
        print(json.dumps({'outcome':'BLOCKED','reason':'GIT_INDEX_OR_INSPECTION_UNAVAILABLE'}));return 2
    print(json.dumps({'outcome':'NOT_READY' if a['status']=='FAIL' else 'READY','trackedFindings':a['trackedIssues'],
                      'inspectionFindings':a['evidenceIssues'],'inspectionAvailable':a['inspectionAvailable']},indent=2))
    return 2 if a['status']=='FAIL' else 0

def live_acceptance():
    if os.environ.get('CIAM_P011_LIVE_CONFIRM')!='INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE':
        raise Refuse('EXPLICIT_OPERATOR_APPROVAL_REQUIRED_BUSINESS_CASE_WRITE')
    if HOME.resolve()!=(Path.home()/'wso2-ciam-v10').resolve():
        raise Refuse('P010_DRIVER_HARDCODES_DEFAULT_PRIVATE_HOME')
    sha,dirty=core.source_identity(REPO)
    if dirty:raise Refuse('DIRTY_WORKTREE_REFUSE_LIVE_PROVENANCE')
    rt=runtime_id()
    if not rt:raise Refuse('RUNTIME_IDENTITY_NOT_VERIFIED')
    ok,reason=preflight()
    if not ok:raise Refuse(reason)
    core.private_directory(INSPECTION)
    before=set(INSPECTION.glob('p010-live-browser-*.json'))
    env=dict(os.environ);env['CIAM_P010_LIVE_CONFIRM']='INTERACTIVE_WSO2_AND_PERSISTENT_CASE_WRITE'
    r=execute(['node',P010_DRIVER],timeout=1200,env=env)
    after=set(INSPECTION.glob('p010-live-browser-*.json'))-before
    if r is None or r.returncode!=0 or len(after)!=1:
        raise Refuse('LIVE_RUN_FAILED_OR_UNATTRIBUTABLE_INSPECT_PRIVATE_P010_REPORT')
    p=next(iter(after))
    raw=core.read_private(p)
    if core.issues_in_text(raw.decode('utf-8','replace'),p.name):raise Refuse('LIVE_EVIDENCE_SECRET_SCAN_FAILED')
    obj=json.loads(raw)
    if not core.assess_p010(obj):raise Refuse('LIVE_P010_ASSERTIONS_FAILED')
    if abs((core.utc_now()-core.parse_date(obj.get('at'))).total_seconds())>1800:
        raise Refuse('LIVE_EVIDENCE_NOT_CURRENT')
    if core.source_identity(REPO)!=(sha,False) or runtime_id()!=rt:raise Refuse('SOURCE_OR_RUNTIME_CHANGED_DURING_TEST')
    row=core.evidence('P011_REAL_P010_BROWSER','Four live WSO2 clients and seller TOTP approval',sha,'local-v10',rt,
        'BROWSER_E2E','PASS','real WSO2 four-client and TOTP approval','P010_DRIVER_EXACT_ASSERTIONS_VERIFIED',
        tenant='aurora.identity.test',client='aurora-web',references=[{'artifact':p.name,'sha256':core.digest(raw)}])
    target=core.private_write(INSPECTION,'p011-live-attested',row)
    print(json.dumps({'outcome':'PASS','evidenceClass':'BROWSER_E2E','sourceGitSha':sha,
                      'attestation':str(target),'scope':'P010_POSITIVE_JOURNEY_ONLY_NEGATIVE_MATRIX_STILL_BLOCKED'},indent=2))
    return 0

def import_automation():
    path=REPO/'deploy/ciam-v10/automation.py'
    spec=importlib.util.spec_from_file_location('ciam_v10_automation_for_p012',path)
    if not spec or not spec.loader:raise Refuse('AUTHORITY_AUTOMATION_UNAVAILABLE')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod

def authority_plan():
    if os.environ.get('WSO2_CIAM_V10_ROLE_API')!='v3':raise Refuse('ROLE_API_V3_EXPLICIT_PIN_REQUIRED')
    r=execute([sys.executable,AUTHORITY,'authorization-plan'],timeout=90)
    if r is None or r.returncode!=0:raise Refuse('AUTHORIZATION_GET_ONLY_PLAN_FAILED')
    try:
        raw=json.loads(r.stdout)
        import_automation().verify_plan(raw,'v3')
        if raw.get('remoteWrites')!=0:raise ValueError('PLAN_HAS_WRITES')
    except Exception:raise Refuse('AUTHORIZATION_PLAN_INVALID') from None
    return core.digest(raw)

def provision_plan():
    sha,dirty=core.source_identity(REPO)
    if dirty:raise Refuse('DIRTY_WORKTREE_REFUSE_WRITE_PLAN')
    if not private_state():raise Refuse('PRIVATE_STATE_UNAVAILABLE')
    digest_plan=authority_plan()
    plan={'schema':'ciam-p012.authorization-plan.v1','createdUtc':core.iso_now(),'sourceGitSha':sha,
          'roleApiVersion':'v3','scope':'EXISTING_AUTHORITY_ONLY_NOT_TENANT_OR_CASES_BOOTSTRAP',
          'authorityPlanSha256':digest_plan,'state':'PLANNED','safeToApply':True}
    plan['planSha256']=core.digest(plan)
    target=core.private_write(INSPECTION,'provision-plan',plan)
    print(json.dumps({'status':'PLANNED','sourceGitSha':sha,'scope':plan['scope'],
                      'planFile':str(target),'next':'Set CIAM_P012_PLAN_FILE to this file and separately approve an apply'},indent=2))
    return 0

def provision_apply():
    if os.environ.get('CIAM_P012_APPLY_CONFIRM')!='APPLY_THIS_FRESH_AUTHORIZATION_PLAN':
        raise Refuse('EXPLICIT_P012_WRITE_APPROVAL_REQUIRED')
    if not private_state():raise Refuse('PRIVATE_STATE_UNAVAILABLE')
    plan_name=os.environ.get('CIAM_P012_PLAN_FILE','')
    plan_path=Path(plan_name).expanduser() if plan_name else None
    if not plan_path or plan_path.parent.resolve()!=INSPECTION.resolve() or not re.fullmatch(r'provision-plan-[A-Za-z0-9-]+\.json',plan_path.name):
        raise Refuse('PRIVATE_PLAN_FILE_REQUIRED')
    plan=json.loads(core.read_private(plan_path))
    sha,dirty=core.source_identity(REPO)
    if dirty:raise Refuse('DIRTY_WORKTREE_REFUSE_APPLY')
    core.validate_approval(plan,sha)
    if plan.get('scope')!='EXISTING_AUTHORITY_ONLY_NOT_TENANT_OR_CASES_BOOTSTRAP':
        raise Refuse('PLAN_SCOPE_UNSUPPORTED')
    # A write attempt consumes a plan permanently; uncertain remote results require manual reconciliation.
    for path in INSPECTION.glob('provision-apply-start-*.json'):
        try:
            journal=json.loads(core.read_private(path))
            if journal.get('planSha256')==plan['planSha256']:
                raise Refuse('PLAN_ALREADY_ATTEMPTED_NO_RETRY')
        except (OSError,ValueError):raise Refuse('UNCERTAIN_PRIVATE_JOURNAL_REFUSE_WRITES')
    if authority_plan()!=plan.get('authorityPlanSha256'):
        raise Refuse('LIVE_PLAN_CHANGED_NO_WRITES')
    journal={'createdUtc':core.iso_now(),'planSha256':plan['planSha256'],'sourceGitSha':sha,
             'state':'WRITE_ATTEMPT_STARTED_OUTCOME_UNCERTAIN_UNTIL_EXACT_READBACK',
             'scope':plan['scope']}
    core.private_write(INSPECTION,'provision-apply-start',journal) # fsynced, 0600 BEFORE write
    env=dict(os.environ)
    env['WSO2_CIAM_V10_AUTHORITY_CONFIRM']='AUTHORIZE_EXISTING_V10_OIDC_AND_ASSIGN_SCIM_USERS'
    applied=execute([sys.executable,AUTHORITY,'authorization-apply'],env=env,timeout=120)
    if applied is None or applied.returncode!=0:raise Refuse('WRITE_OUTCOME_UNCERTAIN_NO_AUTOMATIC_RETRY')
    reconciled=execute([sys.executable,AUTHORITY,'authorization-reconcile'],env=env,timeout=110)
    if reconciled is None or reconciled.returncode!=0:raise Refuse('POST_WRITE_READBACK_UNCERTAIN_NO_RETRY')
    try:
        result=json.loads(reconciled.stdout)
        import_automation().verify_reconcile(result,'v3')
    except Exception:raise Refuse('POST_WRITE_READBACK_INVALID_NO_RETRY')
    core.private_write(INSPECTION,'provision-apply-verified',{'planSha256':plan['planSha256'],
        'verifiedUtc':core.iso_now(),'state':'EXACT_AUTHORITY_RECONCILIATION_VERIFIED','sourceGitSha':sha})
    print(json.dumps({'status':'READBACK_VERIFIED','scope':plan['scope'],'writes':'EXISTING_AUTHORITY_STAGE_ONLY',
                      'warning':'DO_NOT_REPLAY_THIS_PLAN'}))
    return 0

def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if len(args)!=1 or args[0] not in COMMANDS:
        raise Refuse('USAGE: '+', '.join(COMMANDS))
    return {'offline-test':offline_test,'security-audit':security_audit,
        'inventory':lambda:report(inventory_only=True),'readiness':report,
        'live-acceptance':live_acceptance,'provision-plan':provision_plan,
        'provision-apply':provision_apply}[args[0]]()

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:
        # NO exception content from HTTP/auth libraries or private path expansion.
        reason=str(exc) if isinstance(exc,Refuse) else 'UNEXPECTED_ERROR_NO_SECRET_DETAILS'
        print(json.dumps({'outcome':'BLOCKED','reason':reason,'remoteWrites':'NOT_INITIATED_OR_UNCERTAIN'}))
        sys.exit(2)
