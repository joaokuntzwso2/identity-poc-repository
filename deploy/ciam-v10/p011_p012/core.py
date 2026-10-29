"""P0.11/P0.12 narrow acceptance/evidence/safety primitives (stdlib only).

No IAM writes here. All remote data is treated as untrusted. Reports are allowlisted.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

SCHEMA = 'ciam-p011.evidence.v1'
CLASSES = frozenset(('STATIC','UNIT','MOCKED_INTEGRATION','LIVE_READBACK','LIVE_AUTHENTICATION','BROWSER_E2E'))
STATUSES = frozenset(('PASS','FAIL','BLOCKED'))
SECRET_PATH = re.compile(r'(^|/)(?:\.env(?:\.(?!example$|sample$|template$)[^/]+)?|[^/]*\.private\.json|(?:private|inspection)/[^/]*(?:journal|token|credential|secret)|[^/]*(?:browser-trace|auth-trace|credential-export)[^/]*\.(?:json|zip|log))$',re.I)
SECRET_SUFFIX = {'.pem','.p8','.p12','.pfx','.key','.jks','.keystore'}
SECRET_PATTERNS = (
 ('PRIVATE_KEY',re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----')),
 ('SIGNED_TOKEN',re.compile(r'\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{12,}\b')),
 ('OAUTH_BEARER',re.compile(r'(?i)\bBearer\s+[A-Za-z0-9_+./~=-]{35,}')),
 ('BASIC_CREDENTIAL',re.compile(r'(?i)\bBasic\s+[A-Za-z0-9+/=]{36,}')),
 ('VENDOR_TOKEN',re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{15,})\b')),
 ('TOTP_SEED',re.compile(r'(?i)otpauth://totp/[^\s\"\']{10,}|\b(?:totp[_-]?seed|otp[_-]?secret)\s*[=:]\s*[\"\']?[A-Z2-7]{16,}')),
 ('COOKIE',re.compile(r"(?i)(?<![A-Za-z0-9_-])[\"'`]?(?:set-cookie|cookie)[\"'`]?\s*[:=]\s*(?:[\"'`][^\"'`\r\n]{35,}[\"'`]|[\"'`]?\s*[A-Za-z0-9_.~-]{1,70}=[A-Za-z0-9_%+./~-]{24,})")),
 ('CREDENTIAL_ASSIGNMENT',re.compile(r'(?i)\b(?:client_secret|refresh_token|access_token|id_token|password|api_key)\b[\"\']?\s*[:=]\s*[\"\']([A-Za-z0-9_./~+=-]{32,})[\"\']')),
 ('BRAZILIAN_PII',re.compile(r'(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)')),
)
SENSITIVE_KEYS = frozenset({'access_token','refresh_token','id_token','client_secret','password','authorization','cookie','set-cookie','totp_seed','otp_secret','qr_code','private_key','session_cookie','totp_uri'})
MAX_TEXT = 3_000_000
MAX_EVIDENCE = 500_000

def canonical(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('utf-8')

def digest(v):
    return hashlib.sha256(v if isinstance(v,bytes) else canonical(v)).hexdigest()

def utc_now():
    return dt.datetime.now(dt.timezone.utc)

def iso_now():
    return utc_now().isoformat().replace('+00:00','Z')

def parse_date(value):
    if not isinstance(value,str): raise ValueError('TIMESTAMP_INVALID')
    value = dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if value.tzinfo is None: raise ValueError('TIMESTAMP_NO_TIMEZONE')
    return value.astimezone(dt.timezone.utc)

def git(repo,*args,timeout=12):
    proc=subprocess.run(['git',*args],cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
    if proc.returncode:raise ValueError('GIT_QUERY_UNAVAILABLE')
    return proc.stdout

def source_identity(repo):
    sha=git(repo,'rev-parse','--verify','HEAD').decode().strip()
    if not re.fullmatch(r'[a-f0-9]{40,64}',sha): raise ValueError('GIT_SHA_INVALID')
    dirty=bool(git(repo,'status','--porcelain=v1','--untracked-files=normal'))
    return sha,dirty

def private_directory(path):
    path=Path(path).expanduser()
    if path.is_symlink():raise ValueError('PRIVATE_DIRECTORY_SYMLINK')
    if not path.exists():
        if not path.parent.exists():private_directory(path.parent)
        path.mkdir(mode=0o700)
    meta=path.stat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)&0o077:
        raise ValueError('PRIVATE_DIRECTORY_PERMISSIONS_OR_OWNER')
    return path

def private_write(directory,stem,data):
    directory=private_directory(directory)
    target=directory/(stem+'-'+utc_now().strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]+'.json')
    fd=None
    try:
        fd,tmp=tempfile.mkstemp(prefix='.tmp-',dir=directory)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f: fd=None; f.write(canonical(data)+b'\n');f.flush();os.fsync(f.fileno())
        if target.exists() or target.is_symlink():raise ValueError('PRIVATE_OUTPUT_COLLISION')
        os.replace(tmp,target)
        os.chmod(target,0o600)
        return target
    finally:
        if fd is not None:os.close(fd)
        if 'tmp' in locals() and os.path.exists(tmp):os.unlink(tmp)

def read_private(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('PRIVATE_EVIDENCE_SYMLINK')
    m=path.stat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid!=os.getuid() or stat.S_IMODE(m.st_mode)!=0o600 or m.st_size>MAX_EVIDENCE:
        raise ValueError('PRIVATE_EVIDENCE_PERMISSIONS_SIZE_OWNER')
    return path.read_bytes()

def issues_in_text(text,filename):
    found=[]
    for classification,rx in SECRET_PATTERNS:
        for match in list(rx.finditer(text))[:30]:
            found.append({'file':filename,'line':text.count('\n',0,match.start())+1,'classification':classification})
    # Sensitive JSON keys in runtime evidence/trace regardless of value length.
    if any(s in filename.casefold() for s in ('evidence','trace','inspection','session','journal')):
        for k in SENSITIVE_KEYS:
            rx=re.compile(r'(?i)[\"\']'+re.escape(k)+r'[\"\']\s*:\s*[\"\'][^\"\']+\b')
            for match in list(rx.finditer(text))[:30]:
                found.append({'file':filename,'line':text.count('\n',0,match.start())+1,'classification':'SENSITIVE_EVIDENCE_FIELD'})
    return found

def audit_tracked(repo):
    """Scan index blobs, not working tree; also reports unmerged entries and unsafe paths."""
    out=[]
    entries=git(repo,'ls-files','-z','--stage').split(b'\0')
    for line in entries:
        if not line:continue
        try:
            modeinfo,path=line.split(b'\t',1)
            mode,blob,stage=modeinfo.decode().split(' ')
            name=path.decode('utf-8','replace')
        except ValueError:
            out.append({'file':'<git-index>','line':0,'classification':'INDEX_UNREADABLE'});continue
        if stage!='0' or mode not in ('100644','100755'):
            out.append({'file':name,'line':0,'classification':'UNSAFE_INDEX_ENTRY'});continue
        if SECRET_PATH.search(name) or Path(name).suffix.lower() in SECRET_SUFFIX:
            out.append({'file':name,'line':0,'classification':'PRIVATE_TRACKED_PATH'});continue
        try: raw=git(repo,'cat-file','blob',blob)
        except ValueError:
            out.append({'file':name,'line':0,'classification':'INDEX_BLOB_UNAVAILABLE'});continue
        if len(raw)>MAX_TEXT:continue  # existing repo scanner owns oversized review
        if b'\0' in raw:continue
        out.extend(issues_in_text(raw.decode('utf-8','replace'),name))
    return out

def audit_inspection(inspection):
    """Report leaked secrets in sanitized inspection outputs. Never scan private credential journals."""
    inspection=Path(inspection)
    if inspection.is_symlink():return [{'file':'inspection','line':0,'classification':'EVIDENCE_DIRECTORY_SYMLINK'}],False
    if not inspection.is_dir():return [],False
    issues=[]
    for path in sorted(inspection.iterdir()):
        if path.is_symlink():issues.append({'file':path.name,'line':0,'classification':'EVIDENCE_SYMLINK'});continue
        if not path.is_file() or path.suffix.lower() not in ('.json','.jsonl','.md','.log','.txt'):continue
        try:
            raw=read_private(path)
            if b'\0' in raw:raise ValueError('BINARY_EVIDENCE')
            issues.extend(issues_in_text(raw.decode('utf-8','replace'),path.name))
        except (OSError,ValueError):
            issues.append({'file':path.name,'line':0,'classification':'UNSAFE_EVIDENCE_ARTIFACT'})
    return issues,True

def evidence(test_id,description,source_sha,environment,runtime,kind,status,expected,observed,*,tenant=None,client=None,http=None,references=None):
    if kind not in CLASSES or status not in STATUSES:raise ValueError('INVALID_EVIDENCE_CLASS_OR_STATUS')
    if not re.fullmatch(r'[a-zA-Z0-9._-]{3,90}',test_id):raise ValueError('INVALID_TEST_ID')
    row={'schema':SCHEMA,'testId':test_id,'description':description,'timestampUtc':iso_now(),
         'environment':environment,'sourceGitSha':source_sha,'runtimeIdentity':runtime,
         'tenant':tenant,'client':client,'evidenceClass':kind,'expected':expected,
         'observed':observed,'httpStatusOrReason':http,'status':status,
         'references':references or []}
    row['artifactSha256']=digest(row) # digest over canonical record EXCLUDING its own checksum
    return row

def verify_evidence(row,sha,runtime,now=None,max_age_hours=8):
    if not isinstance(row,dict) or row.get('schema')!=SCHEMA:return 'SCHEMA_MISMATCH'
    if row.get('status') not in STATUSES or row.get('evidenceClass') not in CLASSES:return 'FIELD_INVALID'
    if row.get('sourceGitSha')!=sha:return 'SOURCE_SHA_MISMATCH'
    if row.get('runtimeIdentity')!=runtime:return 'RUNTIME_IDENTITY_MISMATCH'
    if digest({k:v for k,v in row.items() if k!='artifactSha256'})!=row.get('artifactSha256'):
        return 'EVIDENCE_TAMPERED'
    try:
        age=((now or utc_now())-parse_date(row.get('timestampUtc'))).total_seconds()
        if age < -300 or age>max_age_hours*3600:return 'EVIDENCE_STALE'
    except (ValueError,TypeError,OverflowError):return 'TIMESTAMP_INVALID'
    if row['evidenceClass'] in ('LIVE_AUTHENTICATION','BROWSER_E2E'):
        if not row.get('references'):return 'LIVE_ARTIFACT_REFERENCE_MISSING'
    return None

def assess_p010(raw):
    """Validate the real P010 driver's pass record, not arbitrary PASS strings."""
    if not isinstance(raw,dict) or raw.get('schema')!='ciam-p010.live-acceptance.v1' or \
       raw.get('status')!='PASS_REAL_WSO2_FOUR_CLIENTS_AND_TOTP_APPROVAL' or \
       raw.get('browserDriven') is not True or raw.get('mfaOperatorInteractionRequired') is not True or \
       raw.get('credentialsSaved') is not False or raw.get('tokenOrCookieDataSaved') is not False:
        return False
    tenants={'aurora-web':'aurora','aurora-app':'aurora','brisa-web':'brisa','brisa-app':'brisa'}
    if set(raw.get('clients',{}))!=set(tenants):return False
    for name,tenant in tenants.items():
        r=raw['clients'][name]
        if not isinstance(r,dict) or r.get('issuerTenant')!=tenant or \
            r.get('loginVerified') is not True or r.get('userInfoVerified') is not True or r.get('userInfoHttp')!=200:
            return False
    customer_fp=raw['clients']['aurora-web'].get('subjectFingerprint')
    seller=raw.get('seller',{})
    if (not isinstance(customer_fp,str) or len(customer_fp)<8 or
        not isinstance(seller,dict) or not isinstance(seller.get('subjectFingerprint'),str) or
        len(seller['subjectFingerprint'])<8 or seller['subjectFingerprint']==customer_fp or
        seller.get('userInfoHttp')!=200):
        return False
    case=raw.get('cases',{})
    return (all(case.get(k)==v for k,v in {
        'createHttp':201,'ownerReadHttp':200,'sellerReviewHttp':200,
        'stepUpStartHttp':202,'sellerAfterHttp':200,'customerAfterHttp':200}.items())
        and raw.get('denials',{}).get('crossTenantHttp')==403
        and raw.get('seller',{}).get('loginVerified') is True
        and raw.get('seller',{}).get('userInfoVerified') is True)

def combine(gates):
    states={gate['status'] for gate in gates}
    return 'NOT_READY' if 'FAIL' in states else 'BLOCKED' if 'BLOCKED' in states else 'READY'

def gate(test_id,status,kind,expected,observed,reason=None):
    return {'id':test_id,'status':status,'evidenceClass':kind,'expected':expected,'observed':observed,'reason':reason}

def validate_approval(plan,actual_sha,now=None):
    if plan.get('schema')!='ciam-p012.authorization-plan.v1':
        raise ValueError('PLAN_SCHEMA_MISMATCH')
    if plan.get('sourceGitSha')!=actual_sha or plan.get('roleApiVersion') not in ('v3',):
        raise ValueError('PLAN_SOURCE_OR_ROLE_API_UNSUPPORTED')
    age=((now or utc_now())-parse_date(plan['createdUtc'])).total_seconds()
    if age<0 or age>600:raise ValueError('PLAN_EXPIRED')
    if plan.get('state')!='PLANNED' or plan.get('safeToApply') is not True:
        raise ValueError('PLAN_UNSAFE_OR_CONSUMED')
    if digest({k:v for k,v in plan.items() if k!='planSha256'})!=plan.get('planSha256'):
        raise ValueError('PLAN_TAMPERED')
    return True
