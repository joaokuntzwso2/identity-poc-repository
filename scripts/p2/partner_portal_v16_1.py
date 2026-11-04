#!/usr/bin/env python3
"""V16.1: fail-closed callback evidence diagnostics and bootstrap-safe V16 gate.

No route inference is treated as permission to register an OAuth client. A missing
BFF route is PENDING only if the V16 write-ahead journal is definitely absent.
Other failures, including an uncertain prior POST, still block startup.
"""
from __future__ import annotations
import hashlib,importlib.util,json,os,re,sys,urllib.parse
from pathlib import Path

TENANT='aurora.identity.test'
V16_SHA='2fd272b41a3a7b0f9cc1163ff5fabf8cf2830ed0f0029330a191573e6950cc79'
PROBE_FILES_MAX=500
PROBE_BYTES_MAX=350_000
IGNORE={'node_modules','dist','test','tests','coverage','.git','build','__pycache__'}
class Block(Exception):pass

def require(ok,code):
    if not ok:raise Block(code)
def load_v16(repo):
    file=repo/'scripts/p2/partner_portal_v16.py'
    require(file.is_file() and not file.is_symlink(),'V16_1_V16_SOURCE_MISSING')
    require(hashlib.sha256(file.read_bytes()).hexdigest()==V16_SHA,'V16_1_V16_SOURCE_PIN_MISMATCH')
    spec=importlib.util.spec_from_file_location('partner_v16_for_v161',file)
    require(spec and spec.loader,'V16_1_DEPENDENCY_IMPORT_BLOCKED')
    v16=importlib.util.module_from_spec(spec)
    try:spec.loader.exec_module(v16)
    except Exception:raise Block('V16_1_DEPENDENCY_IMPORT_BLOCKED')
    return v16

def private_path():
    return Path(os.environ.get('P2_PRIVATE_DIR') or
                str(Path.home()/'wso2-ciam-v10/private')).expanduser().absolute()

def ensure_no_write_intent(v16,private):
    # V16 writes a durable INTENT before every application POST. If a journal
    # exists, even as a broken symlink, the bootstrap must never downgrade a
    # failed registration into an informational warning.
    require(private.is_dir() and not private.is_symlink(),'V16_1_PRIVATE_DIRECTORY_UNVERIFIED')
    journal=private/v16.JOURNAL
    require(not journal.exists() and not journal.is_symlink(),
            'V16_1_EXISTING_JOURNAL_REQUIRES_STRICT_RECONCILIATION')

def report(status,code,**kwargs):
    return {'phase':'P2.24','tenant':TENANT,'status':status,'code':code,
            'managementWrites':0,'businessAuthorizationVerified':False,
            'delegatedAdministrationVerified':False,'sharingPerformed':False,
            'rolesGranted':False,'usersCreated':False,**kwargs}

def bootstrap(repo,private,v16):
    # The original V16 module owns the approval, lock, write-ahead journal,
    # transport, exact readback and safe recovery. Do not duplicate them.
    try:
        return v16.main(['ensure','--approve='+v16.APPROVAL])
    except v16.Stop as exc:
        if str(exc)!='V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF':raise
        ensure_no_write_intent(v16,private)
        # Reconfirm the reserved portal name has not appeared in WSO2 before
        # allowing an informational PENDING result. Never hide collisions.
        existing_callback_info(repo,private,v16)
        return report('PENDING','V16_1_CALLBACK_SOURCE_PROOF_PENDING_STARTUP_SAFE',
                      journalState='ABSENT',automaticRegistrationEnabled=True,
                      nextAction='VERIFY_ACTUAL_BFF_CALLBACK_IMPLEMENTATION')

def existing_callback_info(repo,private,v16):
    """Independently query the *existing* Aurora Web OAuth callback, GET only.

    Never prints URL, client ID, raw server response, credentials, or source
    snippets. If there is a mismatch, preserve a safe explicit status code.
    """
    v13=v16.load(repo/'scripts/p2/partner_v13.py','v16_1_partner_v13')
    v12=v13.import_v12(repo)
    m,_,_=v12.sources(repo)
    m.secure_dir(private);m.runtime_guard(repo,private)
    admin=m.read_existing_authority_admin(repo)
    http=m.Http(str(private/'p2-local-wso2-tls-pinned.pem'))
    apps,names=v16.strict_app_inventory(m,http,admin)
    require(not names or (private/v16.JOURNAL).is_file(),
            'V16_1_UNOWNED_PORTAL_APP_NAME_COLLISION')
    choices=[]
    for row in apps:
        name=row['name']
        if not (re.search(r'\baurora\b',name,re.I) and re.search(r'\bweb\b',name,re.I)):continue
        app_id=row['id']
        status,detail,_=http.call('GET',f'{v16.BASE}/{app_id}',basic=admin)
        require(status==200 and isinstance(detail,dict) and detail.get('id')==app_id and
                detail.get('name')==name and detail.get('isManagementApp') is False,
                'V16_1_SOURCE_APP_DETAIL_UNVERIFIED')
        status,oidc,_=http.call('GET',f'{v16.BASE}/{app_id}/inbound-protocols/oidc',basic=admin)
        require(status==200 and isinstance(oidc,dict),'V16_1_SOURCE_OIDC_UNVERIFIED')
        if 'authorization_code' not in (oidc.get('grantTypes') or []):continue
        uris=oidc.get('callbackURLs')
        require(isinstance(uris,list) and len(uris)==1,
                'V16_1_SOURCE_CALLBACK_NOT_EXACTLY_ONE')
        callback=v16.secure_callback(uris[0])
        choices.append((app_id,callback))
    require(len(choices)==1,'V16_1_SOURCE_AURORA_WEB_NOT_UNIQUE')
    return choices[0],len(apps)

def scan_sources(repo,path):
    folder=repo/'services/identity-bff'
    require(folder.is_dir() and not folder.is_symlink(), 'V16_1_BFF_SOURCE_ABSENT')
    exact=[];dynamic=[];callback_sources=[];count=0
    # Names only; no raw URLs, tokens, source code or OAuth claims are logged.
    for directory,dirs,files in os.walk(folder,followlinks=False):
        dirs[:]=[d for d in sorted(dirs) if d not in IGNORE
                 and not (Path(directory)/d).is_symlink()]
        for name in sorted(files):
            file=Path(directory)/name
            if file.is_symlink() or file.suffix not in ('.js','.mjs','.ts','.json'):continue
            count+=1;require(count<=PROBE_FILES_MAX,'V16_1_BFF_SOURCE_SCAN_OVERSIZE')
            if file.stat().st_size>PROBE_BYTES_MAX:continue
            contents=file.read_text(encoding='utf8',errors='replace')
            rel=file.relative_to(repo).as_posix()
            if path in contents:exact.append(rel)
            if re.search(r'callback',contents,re.I):
                callback_sources.append(rel)
                if ('${' in contents or 'new URL(' in contents or
                    re.search(r'/(?:\:|\{)(?:channel|brand|tenant)',contents,re.I)):
                    dynamic.append(rel)
    # A dynamic marker is only a diagnostic clue, never evidence that the
    # callback is implemented. No registration occurs on this basis.
    return {'sourceFilesScanned':count,
            'exactCallbackPathLiteralPresent':bool(exact),
            'exactCallbackPathLiteralSourceFiles':exact[:12],
            'dynamicCallbackConstructionCandidate':bool(dynamic),
            'dynamicCallbackCandidateSourceFiles':dynamic[:12],
            'callbackMentioningSourceFiles':callback_sources[:20]}

def diagnose(repo,private,v16):
    # The v15 read-only inspection reattests V13/V14 WSO2 evidence.
    v15=v16.load(repo/'scripts/p2/partner_business_plan_v15.py','v16_1_partner_v15')
    base=v15.inspect(repo,private)
    require(base.get('managementWrites')==0 and base.get('status')=='PENDING' and
            base.get('partnerFingerprint')==v16.PARTNER_FP,
            'V16_1_PARTNER_PREREQUISITES_CHANGED')
    (source_app_id,uri),n=existing_callback_info(repo,private,v16)
    path=urllib.parse.urlsplit(uri).path
    signals=scan_sources(repo,path)
    state='JOURNAL_EXISTS_STRICT_RECOVERY' if (private/v16.JOURNAL).exists() or (private/v16.JOURNAL).is_symlink() else 'ABSENT'
    return report('PENDING','V16_1_CALLBACK_ROUTE_EVIDENCE_DIAGNOSTIC',
                  journalState=state,registeredSourceApplicationFingerprint=v16.fp(source_app_id),
                  callbackFingerprint=v16.fp(uri),callbackPathFingerprint=v16.fp(path),
                  sourceApplicationCount=n,**signals,
                  nextAction='REVIEW_BFF_ROUTING_SOURCE_NO_GUESSED_CALLBACK')

def main(args):
    require(args in (['bootstrap'],['diagnose']), 'V16_1_COMMAND_REQUIRED')
    repo=Path.cwd().resolve()
    require((repo/'scripts/ciam-v10.sh').is_file() and
            (repo/'scripts/p2/partner_business_plan_v15.py').is_file(),
            'V16_1_REPOSITORY_ROOT_REQUIRED')
    v16=load_v16(repo);private=private_path()
    if args==['bootstrap']:return bootstrap(repo,private,v16)
    return diagnose(repo,private,v16)

if __name__=='__main__':
    try:
        out=main(sys.argv[1:])
        print(json.dumps(out,sort_keys=True,indent=2),flush=True)
    except Exception as e:
        code=str(e) if isinstance(e,Block) or re.fullmatch(r'V16_[A-Z0-9_]+',str(e)) else 'V16_1_DIAGNOSTIC_BLOCKED'
        print(json.dumps(report('BLOCKED',code,managementWrites='UNKNOWN_CHECK_PRIVATE_JOURNAL',
                                noAutomaticRetry=True),sort_keys=True,indent=2),flush=True)
        sys.exit(2)
