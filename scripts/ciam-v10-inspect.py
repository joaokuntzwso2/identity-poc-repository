#!/usr/bin/env python3
"""Read-only CIAM v10 source/runtime inspection. Python >=3.10, stdlib only.

No provisioning, Docker state changes, HTTP writes, or secrets in reports.
Output stays OUTSIDE the Git checkout: $CIAM_V10_HOME/inspection/<timestamp>-<sha>/.
"""
from __future__ import annotations
import argparse
import ast
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import quote, urlencode, urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
HOME = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10'))).expanduser()
PRIVATE = HOME / 'private'
DOMAINS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}
BASE = 'https://localhost:9444'
BFF = 'http://127.0.0.1:4400'
CERT = PRIVATE / 'wso2-9444-leaf.pem'
EXPECTED = {
    'tenants': 'bootstrap-tenants-v10.private.json',
    'resources': 'bootstrap-resources-v10.private.json',
    'oidc': 'bootstrap-oidc-v10.private.json',
    'authority': 'bootstrap-authority-v10.private.json',
    'identities': 'bootstrap-identities-v10.private.json',
}
MAX_READ = 1024 * 1024
ID_RE = re.compile(r'^[A-Za-z0-9_-]{5,256}={0,2}$')
REDACT = re.compile(r'(password|secret|token|authorization|cookie|privatekey|clientsecret)', re.I)

class InspectionError(Exception):
    pass

def git(*args, timeout=15):
    return subprocess.run(['git', *args], cwd=ROOT, capture_output=True, timeout=timeout, check=False)

def clean_text(raw):
    return raw.decode('utf8', 'replace').strip()

def safe_file(path: Path, required=False):
    if not path.exists() and not path.is_symlink():
        if required:
            raise InspectionError('MISSING_PRIVATE_FILE_' + path.name)
        return None
    if path.is_symlink() or not path.is_file():
        raise InspectionError('UNSAFE_PRIVATE_FILE_' + path.name)
    st = path.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > MAX_READ:
        raise InspectionError('PRIVATE_FILE_MODE_OWNER_OR_SIZE_' + path.name)
    try:
        value = json.loads(path.read_text(encoding='utf8'))
    except (OSError, ValueError):
        raise InspectionError('INVALID_PRIVATE_JSON_' + path.name) from None
    if not isinstance(value, dict):
        raise InspectionError('PRIVATE_JSON_NOT_OBJECT_' + path.name)
    return value

def make_output(sha):
    if HOME.is_symlink() or not HOME.is_dir() or HOME.resolve() == ROOT:
        raise InspectionError('CIAM_V10_HOME_MUST_EXIST_OUTSIDE_REPOSITORY')
    parent = HOME / 'inspection'
    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
        raise InspectionError('INSPECTION_OUTPUT_PARENT_UNSAFE')
    parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(parent, 0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = parent / f'{stamp}-{sha[:12]}-{os.getpid()}'
    out.mkdir(mode=0o700)
    return out

def write_json(out, name, doc):
    path = out / name
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf8') as f:
        json.dump(doc, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    return path

def add_issue(report, code, severity='BLOCKED', detail=None):
    issue = {'code': code, 'severity': severity}
    if detail is not None:
        issue['detail'] = detail
    report['issues'].append(issue)

def inspect_git():
    h = git('rev-parse', '--show-toplevel')
    if h.returncode or Path(clean_text(h.stdout)).resolve() != ROOT.resolve():
        raise InspectionError('RUN_FROM_EXPECTED_GIT_REPOSITORY')
    commit = git('rev-parse', '--verify', 'HEAD^{commit}')
    if commit.returncode:
        raise InspectionError('NO_GIT_HEAD')
    sha = clean_text(commit.stdout)
    status = git('status', '--porcelain=v1', '-z', '--untracked-files=all')
    if status.returncode:
        raise InspectionError('GIT_STATUS_FAILED')
    # No raw paths from potentially sensitive untracked work in the report.
    changes = status.stdout.split(b'\0')
    change_count = sum(bool(s) for s in changes)
    files = git('ls-files', '-z')
    if files.returncode:
        raise InspectionError('GIT_LS_FILES_FAILED')
    tracked = [s.decode('utf8', 'replace') for s in files.stdout.split(b'\0') if s]
    branch = git('branch', '--show-current')
    # Avoid exposing a credential-containing Git remote URL.
    canonical = {
        'orchestrator': 'deploy/ciam-v10/cli.py',
        'v10_entrypoint': 'scripts/ciam-v10.sh',
        'tenant_provisioner': 'deploy/ciam-v10/tenants/provision.py',
        'resource_provisioner': 'deploy/ciam-v10/resources/bootstrap.py',
        'oidc_provisioner': 'deploy/ciam-v10/oidc/bootstrap.py',
        'rbac_provisioner': 'deploy/ciam-v10/authority/bootstrap.py',
        'personas': 'deploy/ciam-v10/identities/seed.json',
        'identity_bff': 'services/identity-bff/src/server.js',
        'live_cases': 'services/identity-bff/src/live-cases-v4.js',
        'live_experience': 'services/identity-bff/src/live-experience-v5.js',
        'live_brand': 'services/identity-bff/src/live-brand-v3.js',
        'documentation': 'README.md',
    }
    categorized = Counter()
    legacy = []
    for path in tracked:
        bucket = ('v10 deployment' if path.startswith('deploy/ciam-v10/') or path == 'scripts/ciam-v10.sh'
                  else 'live BFF' if path.startswith('services/identity-bff/')
                  else 'legacy WSO2' if path.startswith('scripts/wso2/') or path.startswith('deploy/ciam-v8/') or path.startswith('deploy/ciam-v9/') or path == 'wso2-lab.sh'
                  else 'legacy/preview' if path.startswith('services/experience-api/') or path.startswith('apps/experience-center/')
                  else 'documentation' if path.endswith('.md')
                  else 'other')
        categorized[bucket] += 1
        if bucket in ('legacy WSO2', 'legacy/preview'):
            legacy.append(path)
    text = (ROOT / 'README.md').read_text(encoding='utf8', errors='replace') if (ROOT / 'README.md').is_file() else ''
    doc_check = {key: bool(re.search(pattern, text, re.I)) for key, pattern in {
        'describes_v10': r'ciam.v10|CIAM v10',
        'documents_port_9444': r'9444',
        'documents_port_4400': r'4400',
        'mentions_four_clients': r'four.{0,40}(OIDC|client)|4.{0,40}(OIDC|client)',
        'explains_runtime_acceptance': r'runtime.acceptance|browser.{0,20}acceptance',
    }.items()}
    hashes = {}
    for label, path in canonical.items():
        local = ROOT / path
        hashes[label] = {'path': path, 'present': local.is_file(),
                         'sha256': hashlib.sha256(local.read_bytes()).hexdigest() if local.is_file() else None}
        if local.is_file() and local.suffix in ('.py','.js','.mjs') and local.stat().st_size < 500000:
            content=local.read_text(encoding='utf8',errors='replace')
            try:
                if local.suffix=='.py':
                    parsed=ast.parse(content)
                    symbols=[node.name for node in parsed.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
                else:
                    symbols=re.findall(r'(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(|^\s*(?:export\s+)?class\s+([A-Za-z_][A-Za-z_0-9]*)',content)
                    symbols=[next((v for v in pair if v),'') for pair in symbols]
                hashes[label]['topLevelSymbols']=sorted(set(symbols))[:100]
            except SyntaxError:
                hashes[label]['sourceParse']='FAILED'
    return {
        'git': {'sha': sha, 'branch': clean_text(branch.stdout) if branch.returncode == 0 else 'UNKNOWN',
                'dirty': bool(change_count), 'workingTreeStatusEntryCount': change_count,
                'trackedFileCount': len(tracked),
                'treeHash': clean_text(git('rev-parse', 'HEAD^{tree}').stdout)},
        'componentCounts': dict(categorized), 'canonicalFiles': hashes,
        'legacyFiles': legacy, 'readmeCoverageHeuristics': doc_check,
        'limits': ['Source presence and static text checks do not prove runtime behavior.',
                   'HEAD is pinned in this report; this command does not create a Git tag.']
    }

def basic(username, password):
    return 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode('ascii')

class PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, fingerprint):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  # Local certificate pinned by full SHA-256 fingerprint.
        context.verify_mode = ssl.CERT_NONE
        super().__init__('localhost', 9444, timeout=15, context=context)
        self.fingerprint = fingerprint
    def connect(self):
        super().connect()
        actual = hashlib.sha256(self.sock.getpeercert(binary_form=True)).digest()
        if not hmac.compare_digest(actual, self.fingerprint):
            self.close()
            raise InspectionError('SERVER_CERTIFICATE_PIN_MISMATCH_NO_CREDENTIALS_SENT')

class API:
    def __init__(self, cert_path=CERT):
        if cert_path.is_symlink() or not cert_path.is_file():
            raise InspectionError('PINNED_WSO2_CERT_MISSING')
        with cert_path.open('r', encoding='utf8') as f:
            pem = f.read()
        try:
            self.fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).digest()
        except ValueError:
            raise InspectionError('INVALID_PINNED_WSO2_CERT') from None
        self.request_count = 0
    def get(self, path, auth=None):
        if (not path.startswith('/') or path.startswith('//') or '..' in path or '\\' in path
                or '#' in path or len(path) > 2600 or any(ord(c) < 32 for c in path)):
            raise InspectionError('UNSAFE_REQUEST_PATH')
        conn = PinnedConnection(self.fingerprint)
        try:
            headers = {'Accept': 'application/json'}
            if auth:
                headers['Authorization'] = auth
            conn.request('GET', path, headers=headers)
            response = conn.getresponse()
            data = response.read(MAX_READ + 1)
            self.request_count += 1
            if len(data) > MAX_READ:
                raise InspectionError('REMOTE_RESPONSE_TOO_LARGE')
            if 300 <= response.status < 400:
                raise InspectionError('REMOTE_REDIRECT_REFUSED')
            if response.status != 200:
                return response.status, {}
            try:
                decoded = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                raise InspectionError('REMOTE_NON_JSON_SUCCESS') from None
            return response.status, decoded
        finally:
            conn.close()

def coll(doc, *keys):
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        raise InspectionError('LIST_RESPONSE_NOT_OBJECT')
    for key in keys:
        if isinstance(doc.get(key), list):
            return doc[key]
    if doc.get('totalResults') == 0:
        return []
    raise InspectionError('UNRECOGNIZED_LIST_SHAPE')

def id_safe(value):
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))

def get_or_raise(api, path, auth=None):
    status, doc = api.get(path, auth)
    if status != 200:
        raise InspectionError('GET_HTTP_' + str(status))
    return doc

def api_cursor_from_link(href, root, seen):
    """Extract an opaque 'after' cursor; never fetch a server-provided URL.

    WSO2 may advertise absolute https://localhost:9443 links even though
    the host-side TLS-pinned bridge is https://localhost:9444. Only the
    opaque cursor is reused against the original, pinned API endpoint.
    """
    if (not isinstance(href, str) or not href or len(href) > 2048
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in href)
            or '\\' in href):
        raise InspectionError('UNSAFE_API_CURSOR')
    try:
        parsed = urlsplit(href)
        if parsed.fragment or parsed.username is not None or parsed.password is not None:
            raise InspectionError('UNSAFE_API_CURSOR_ORIGIN')
        if parsed.scheme or parsed.netloc:
            if (parsed.scheme != 'https' or parsed.hostname not in ('localhost', '127.0.0.1')
                    or parsed.port not in (9443, 9444)):
                raise InspectionError('UNSAFE_API_CURSOR_ORIGIN')
    except ValueError:
        raise InspectionError('UNSAFE_API_CURSOR_ORIGIN') from None
    # WSO2 sometimes omits the tenant prefix in links or returns query-only hrefs.
    local_root = root.split('/api/server/', 1)[-1]
    acceptable = {root, '/api/server/' + local_root, ''}
    if parsed.path not in acceptable or (not parsed.path and (parsed.scheme or parsed.netloc)):
        raise InspectionError('UNSAFE_API_CURSOR_PATH')
    if not parsed.query:
        raise InspectionError('UNSAFE_API_CURSOR')
    try:
        params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise InspectionError('UNSAFE_API_CURSOR') from None
    if not params.keys() <= {'after', 'limit'}:
        raise InspectionError('UNSAFE_API_CURSOR_QUERY')
    limit = params.get('limit')
    if limit is not None and (len(limit) != 1 or limit[0] != '100'):
        raise InspectionError('UNSAFE_API_CURSOR_QUERY')
    cursor = params.get('after', [])
    if (len(cursor) != 1 or not cursor[0] or len(cursor[0]) > 512
            or any(ord(ch) < 33 or ord(ch) == 127 for ch in cursor[0])
            or cursor[0] in seen):
        raise InspectionError('UNSAFE_API_CURSOR')
    return cursor[0]

def list_all(api, root, auth, kind):
    """Bounded pagination; refuses to label a partial response complete."""
    rows, next_page, seen = [], None, set()
    for page in range(25):
        if kind == 'scim':
            suffix = '?' + urlencode({'count': 100, 'startIndex': len(rows)+1})
        elif kind == 'apps':
            suffix = '?' + urlencode({'limit': 100, 'offset': len(rows)})
        else:
            suffix = '?' + urlencode({'limit': 100, **({'after': next_page} if next_page else {})})
        doc = get_or_raise(api, root + suffix, auth)
        part = coll(doc, *({'scim': ('Resources','resources'), 'apps': ('applications','Applications','list'),
                            'apis': ('APIResources','apiResources','resources','list')}[kind]))
        rows.extend(x for x in part if isinstance(x, dict))
        if len(part) != len([x for x in part if isinstance(x, dict)]):
            raise InspectionError('NON_OBJECT_COLLECTION_ENTRY')
        if len(rows) > 2500:
            raise InspectionError('CATALOG_TOO_LARGE')
        total = doc.get('totalResults') if isinstance(doc, dict) else None
        if isinstance(total, int):
            if total < len(rows):
                raise InspectionError('INCONSISTENT_TOTAL_RESULTS')
            if len(rows) == total:
                return rows
            if not part:
                raise InspectionError('PAGINATION_EMPTY_BEFORE_COMPLETE')
        elif len(part) < 100 and kind != 'apis':
            return rows
        if kind == 'apis':
            links = doc.get('links', []) if isinstance(doc, dict) else []
            candidates = [x for x in links if isinstance(x, dict) and x.get('rel') in ('next','after')]
            if len(candidates) > 1:
                raise InspectionError('MULTIPLE_API_PAGE_CURSORS')
            if not candidates:
                if isinstance(total, int) and total > len(rows):
                    raise InspectionError('API_PAGINATION_UNAVAILABLE')
                if len(part) >= 100:
                    raise InspectionError('API_PAGINATION_UNKNOWN_MORE')
                return rows
            next_page = api_cursor_from_link(candidates[0].get('href'), root, seen)
            seen.add(next_page)
    raise InspectionError('PAGINATION_LIMIT_REACHED')

def reduced_oidc(protocol):
    subject = protocol.get('subject', {}) if isinstance(protocol.get('subject'), dict) else {}
    pkce = protocol.get('pkce', {}) if isinstance(protocol.get('pkce'), dict) else {}
    return {
        'clientId': protocol.get('clientId'), 'publicClient': protocol.get('publicClient'),
        'grantTypes': protocol.get('grantTypes'), 'callbackURLs': protocol.get('callbackURLs'),
        'subjectType': subject.get('subjectType'), 'sectorIdentifierUri': subject.get('sectorIdentifierUri'),
        'pkceMandatory': pkce.get('mandatory'), 'pkceSupport': pkce.get('supportPlainTransformAlgorithm'),
    }

def inspect_tenant(api, brand, domain, owner_auth, journals, report):
    prefix = f'/t/{domain}'
    result = {'domain': domain, 'catalogs': {}, 'oidcDiscovery': {}, 'expectedClients': {}, 'drift': []}
    roots = {
        'applications': (prefix+'/api/server/v1/applications', 'apps'),
        'apiResources': (prefix+'/api/server/v1/api-resources', 'apis'),
        'users': (prefix+'/scim2/Users', 'scim'),
        'groups': (prefix+'/scim2/Groups', 'scim'),
    }
    role_version = journals.get('authority', {}).get('roleApiVersion') or journals.get('identities', {}).get('roleApiVersion') or os.environ.get('WSO2_CIAM_V10_ROLE_API', 'v3')
    if role_version not in ('v2','v3'):
        role_version = 'v3'
        result['drift'].append('ROLE_VERSION_INVALID_IN_PRIVATE_JOURNAL')
    roots['roles'] = (prefix+f'/scim2/{role_version}/Roles', 'scim')
    raw = {}
    for label, (root, kind) in roots.items():
        try:
            raw[label] = list_all(api, root, owner_auth, kind)
            result['catalogs'][label] = {'state': 'COMPLETE', 'count': len(raw[label])}
        except (InspectionError, OSError, ssl.SSLError) as e:
            result['catalogs'][label] = {'state': 'BLOCKED', 'error': type(e).__name__ if not isinstance(e, InspectionError) else str(e)}
            add_issue(report, f'{brand.upper()}_{label.upper()}_INVENTORY_BLOCKED')
            raw[label] = []
    result['applications'] = []
    for item in raw['applications']:
        aid = item.get('id')
        app = {'id': aid, 'name': item.get('name'), 'isManagementApp': item.get('isManagementApp')}
        if id_safe(aid):
            try:
                detail = get_or_raise(api, prefix+'/api/server/v1/applications/'+quote(aid, safe=''), owner_auth)
                app['associatedRoles'] = detail.get('associatedRoles', {}).get('allowedAudience') if isinstance(detail.get('associatedRoles'),dict) else None
                try:
                    a_doc=get_or_raise(api,prefix+'/api/server/v1/applications/'+quote(aid,safe='')+'/authorized-apis',owner_auth)
                    grants=coll(a_doc,'authorizedAPIs','authorizedApis','apis','resources','list')
                    app['authorizedAPIs']=[{'id':x.get('id'),'identifier':x.get('identifier'),
                        'authorizedScopes':[v if isinstance(v,str) else v.get('name') for v in x.get('authorizedScopes',x.get('scopes',[]))]}
                        for x in grants if isinstance(x,dict)]
                except (InspectionError,OSError,ssl.SSLError):
                    app['authorizedAPIsState']='BLOCKED'
                proto_status,proto=api.get(prefix+'/api/server/v1/applications/'+quote(aid,safe='')+'/inbound-protocols/oidc',owner_auth)
                if proto_status==200 and isinstance(proto,dict):
                    app['oidc']=reduced_oidc(proto)
                else:
                    app['oidcState']='UNAVAILABLE_HTTP_'+str(proto_status)
            except (InspectionError, OSError) as e:
                app['detail'] = 'BLOCKED_' + (str(e) if isinstance(e, InspectionError) else type(e).__name__)
        result['applications'].append(app)
    result['apiResources'] = []
    for item in raw['apiResources']:
        rid = item.get('id')
        entry = {'id': rid, 'name': item.get('name'), 'identifier': item.get('identifier')}
        if id_safe(rid):
            try:
                scopes = get_or_raise(api, prefix+'/api/server/v1/api-resources/'+quote(rid,safe='')+'/scopes',owner_auth)
                entry['scopes'] = [x if isinstance(x,str) else x.get('name') for x in coll(scopes,'scopes')]
            except (InspectionError, OSError) as e:
                entry['scopesState'] = 'BLOCKED_' + (str(e) if isinstance(e, InspectionError) else type(e).__name__)
        result['apiResources'].append(entry)
    result['users'] = [{'id': x.get('id'), 'userName': x.get('userName'), 'active': x.get('active')}
                       for x in raw['users']]
    result['groups'] = []
    for x in raw['groups']:
        gid = x.get('id'); group = {'id':gid,'displayName':x.get('displayName'),'members':[],'membersState':'UNVERIFIED'}
        if id_safe(gid):
            try:
                full = get_or_raise(api,prefix+'/scim2/Groups/'+quote(gid,safe=''),owner_auth)
                group['members'] = [m.get('value') for m in full.get('members',[]) if isinstance(m,dict)]
                group['membersState'] = 'COMPLETE' if isinstance(full.get('members', []),list) else 'UNVERIFIED'
            except (InspectionError,OSError): pass
        result['groups'].append(group)
    result['roles'] = []
    for x in raw['roles']:
        rid=x.get('id'); role = {'id':rid,'displayName':x.get('displayName'),'audience':x.get('audience'),
                                'users':[],'groups':[],'permissions':[],'detailsState':'UNVERIFIED'}
        if id_safe(rid):
            try:
                full=get_or_raise(api,prefix+f'/scim2/{role_version}/Roles/'+quote(rid,safe=''),owner_auth)
                for key in ('users','groups','permissions'):
                    role[key]=[v.get('value') for v in full.get(key,[]) if isinstance(v,dict)]
                role['detailsState']='COMPLETE' if all(isinstance(full.get(k,[]),list) for k in ('users','groups','permissions')) else 'UNVERIFIED'
            except (InspectionError,OSError): pass
        result['roles'].append(role)
    try:
        d=get_or_raise(api,prefix+'/oauth2/token/.well-known/openid-configuration')
        result['oidcDiscovery']={k:d.get(k) for k in ('issuer','authorization_endpoint','token_endpoint','jwks_uri',
                         'userinfo_endpoint','end_session_endpoint','grant_types_supported','code_challenge_methods_supported','subject_types_supported')}
        if not str(d.get('issuer','')).startswith(BASE+prefix+'/'):
            result['drift'].append('OIDC_DISCOVERY_ISSUER_MISMATCH')
        for key in ('authorization_endpoint','token_endpoint','jwks_uri'):
            if not str(d.get(key,'')).startswith(BASE+'/'):
                result['drift'].append('OIDC_DISCOVERY_'+key.upper()+'_UNTRUSTED_OR_MISSING')
    except (InspectionError,OSError,ssl.SSLError):
        add_issue(report,brand.upper()+'_OIDC_DISCOVERY_BLOCKED')
    oidc_t = journals.get('oidc',{}).get('tenants',{}).get(brand,{})
    for channel in ('web','app'):
        expected = oidc_t.get('clients',{}).get(channel,{})
        aid = expected.get('id')
        entry = {'journalAppId': aid, 'journalState': expected.get('state'), 'readback': 'UNVERIFIED'}
        if not id_safe(aid):
            entry['drift']=['OIDC_APP_ID_NOT_JOURNALED']; result['expectedClients'][channel]=entry
            continue
        try:
            app = get_or_raise(api,prefix+'/api/server/v1/applications/'+quote(aid,safe=''),owner_auth)
            p = get_or_raise(api,prefix+'/api/server/v1/applications/'+quote(aid,safe='')+'/inbound-protocols/oidc',owner_auth)
            safe=reduced_oidc(p)
            entry['readback']='COMPLETE'; entry['applicationName']=app.get('name'); entry['protocol']=safe
            checks={
                'applicationId': app.get('id')==aid,
                'clientId': bool(expected.get('clientId')) and expected['clientId']==safe['clientId'],
                'callback': safe['callbackURLs']==[expected.get('callback',BFF+f'/auth/{brand}-{channel}/callback')],
                'authorizationCode': isinstance(safe['grantTypes'],list) and 'authorization_code' in safe['grantTypes'],
                'confidentialClient': safe['publicClient'] is False,
                'pkceMandatory': safe['pkceMandatory'] is True,
                'pairwiseSubject': safe['subjectType']=='pairwise',
                'applicationRoleAudience': app.get('associatedRoles',{}).get('allowedAudience')=='APPLICATION',
            }
            entry['checks']=checks
            entry['drift']=[k for k,v in checks.items() if not v]
            if safe['sectorIdentifierUri'] in (None,''):
                entry['sectorStatus']='NOT_CONFIGURED_VALIDATE_CROSS_CHANNEL_REQUIREMENT'
            if entry['drift']:
                result['drift'].append('OIDC_'+channel.upper()+'_CONFIG_MISMATCH')
        except (InspectionError,OSError,ssl.SSLError) as e:
            entry['readback']='BLOCKED_'+(str(e) if isinstance(e,InspectionError) else type(e).__name__)
            result['drift'].append('OIDC_'+channel.upper()+'_READBACK_BLOCKED')
        result['expectedClients'][channel]=entry
    # Compare journal-owned references against inventory, without assuming a listed object is authorized.
    journal_t = journals.get('tenants',{}).get('tenants',{}).get(brand,{})
    result['journalTenantId']=journal_t.get('tenantId')
    for kind, jfile, nested, current in (
        ('managementApplication','resources','management','applications'),
        ('serviceAccount','resources','user','users')):
        expected = journals.get(jfile,{}).get('tenants',{}).get(brand,{}).get(nested,{})
        ident=expected.get('id')
        if ident and result['catalogs'].get(current,{}).get('state')=='COMPLETE' and ident not in {x.get('id') for x in (result['applications'] if current=='applications' else result['users'])}:
            result['drift'].append('JOURNAL_'+kind.upper()+'_MISSING')
    people = journals.get('identities',{}).get('tenants',{}).get(brand,{})
    if isinstance(people,dict):
        for key, entry in people.get('users',{}).items():
            if entry.get('id') and result['catalogs'].get('users',{}).get('state')=='COMPLETE' and entry['id'] not in {x['id'] for x in result['users']}:
                result['drift'].append('JOURNAL_PERSON_MISSING_'+key)
        for key, entry in people.get('roles',{}).items():
            if entry.get('id') and result['catalogs'].get('roles',{}).get('state')=='COMPLETE' and entry['id'] not in {x['id'] for x in result['roles']}:
                result['drift'].append('JOURNAL_ROLE_MISSING_'+key)
    # Strong journal-to-live checks for the existing profile API and app-scoped roles.
    authority=journals.get('authority',{})
    expected_authority=authority.get('tenants',{}).get(brand,{})
    expected_resource=expected_authority.get('resource',{})
    if expected_resource.get('state')=='verified' and result['catalogs']['apiResources']['state']=='COMPLETE':
        matching=[x for x in result['apiResources'] if x.get('id')==expected_resource.get('id')]
        if (len(matching)!=1 or matching[0].get('identifier')!=authority.get('apiIdentifier')
                or authority.get('scope') not in matching[0].get('scopes',[])):
            result['drift'].append('PROFILE_RESOURCE_OR_SCOPE_MISSING')
    for channel in ('web','app'):
        rn=expected_authority.get('role_'+channel,{})
        if rn.get('state')=='verified' and result['catalogs']['roles']['state']=='COMPLETE':
            matches=[x for x in result['roles'] if x.get('id')==rn.get('id')]
            appid=oidc_t.get('clients',{}).get(channel,{}).get('id')
            user_id=journals.get('resources',{}).get('tenants',{}).get(brand,{}).get('user',{}).get('id')
            if (len(matches)!=1 or matches[0].get('detailsState')!='COMPLETE'
                    or matches[0].get('audience',{}).get('value')!=appid
                    or authority.get('scope') not in matches[0].get('permissions',[])
                    or user_id not in matches[0].get('users',[])):
                result['drift'].append('PROFILE_ROLE_OR_ASSIGNMENT_DRIFT_'+channel.upper())
        authnode=expected_authority.get('authorizations',{}).get(channel,{})
        if authnode.get('state')=='verified':
            appid=oidc_t.get('clients',{}).get(channel,{}).get('id')
            try:
                doc=get_or_raise(api,prefix+'/api/server/v1/applications/'+quote(appid,safe='')+'/authorized-apis',owner_auth)
                auths=coll(doc,'authorizedAPIs','authorizedApis','apis','resources','list')
                match=[x for x in auths if isinstance(x,dict) and x.get('id')==expected_resource.get('id')]
                granted=set()
                for authobj in match:
                    for item in authobj.get('authorizedScopes',authobj.get('scopes',[])):
                        granted.add(item if isinstance(item,str) else item.get('name') if isinstance(item,dict) else None)
                if len(match)!=1 or authority.get('scope') not in granted:
                    result['drift'].append('APP_SCOPE_AUTHORIZATION_DRIFT_'+channel.upper())
            except (InspectionError,OSError,ssl.SSLError):
                result['drift'].append('APP_SCOPE_AUTHORIZATION_READBACK_BLOCKED_'+channel.upper())
    seed_path=ROOT/'deploy/ciam-v10/identities/seed.json'
    if seed_path.is_file() and result['catalogs']['roles']['state']=='COMPLETE':
        try:
            seed=json.loads(seed_path.read_text(encoding='utf8'))
            permissions=seed.get('implementedPermissionAssignments',{})
            for name,node in people.get('roles',{}).items():
                if not node.get('id'):continue
                matches=[x for x in result['roles'] if x.get('id')==node['id']]
                kind=name.split(':',1)[-1]
                want=set(permissions.get(kind,[]))
                if len(matches)!=1 or matches[0].get('detailsState')!='COMPLETE' or set(matches[0].get('permissions',[]))!=want:
                    result['drift'].append('PERSONA_ROLE_PERMISSION_DRIFT_'+name)
        except (ValueError,OSError):
            result['drift'].append('IDENTITY_SEED_NOT_READABLE')
    if result['drift']:
        add_issue(report,brand.upper()+'_CONFIGURATION_DRIFT', 'ACTION_REQUIRED', sorted(set(result['drift'])))
    return result

def inspect_super(api, journals, report):
    result={'catalogs': {}, 'tenants': [], 'tenantOwners': {}, 'drift': []}
    admin = journals.get('admin')
    if not admin or not admin.get('username') or not admin.get('password'):
        add_issue(report,'SUPER_ADMIN_CREDENTIALS_NOT_AVAILABLE')
        return result
    auth=basic(admin['username'],admin['password'])
    try:
        doc=get_or_raise(api,'/api/server/v1/tenants?limit=100&offset=0',auth)
        rows=coll(doc,'tenants')
        if isinstance(doc.get('totalResults'),int) and doc['totalResults']>len(rows):
            raise InspectionError('TENANT_LIST_INCOMPLETE')
        result['tenants']=[{'domain':x.get('domain'),'id':x.get('id'),'lifecycleStatus':x.get('lifecycleStatus')} for x in rows]
    except (InspectionError,OSError,ssl.SSLError) as e:
        add_issue(report,'SUPER_TENANT_LIST_BLOCKED',detail=str(e) if isinstance(e,InspectionError) else type(e).__name__)
    for brand, domain in DOMAINS.items():
        try:
            tenant=get_or_raise(api,'/api/server/v1/tenants/domain/'+domain,auth)
            tid=tenant.get('id')
            if not id_safe(tid):
                raise InspectionError('TENANT_ID_INVALID')
            owners=get_or_raise(api,'/api/server/v1/tenants/'+quote(tid,safe='')+'/owners',auth)
            owner_list=coll(owners,'owners')
            result['tenantOwners'][brand]={'tenantId':tid,'owners':[{'id':x.get('id'),'username':x.get('username')} for x in owner_list]}
            expected=journals.get('tenants',{}).get('tenants',{}).get(brand,{})
            if expected.get('tenantId')!=tid or expected.get('ownerId') not in [x.get('id') for x in owner_list]:
                result['drift'].append('TENANT_OWNER_OR_ID_DRIFT_'+brand)
        except (InspectionError,OSError,ssl.SSLError) as e:
            add_issue(report,'SUPER_OWNER_READBACK_BLOCKED_'+brand.upper(),detail=str(e) if isinstance(e,InspectionError) else type(e).__name__)
    for key,root,kind in (
        ('applications','/api/server/v1/applications','apps'),
        ('apiResources','/api/server/v1/api-resources','apis'),
        ('users','/scim2/Users','scim'),
        ('groups','/scim2/Groups','scim'),
        ('roles','/scim2/v2/Roles','scim')):
        try:
            rows=list_all(api,root,auth,kind)
            result['catalogs'][key]={'state':'COMPLETE','count':len(rows)}
            entries=[]
            for x in rows:
                entry={'id':x.get('id'), 'name':x.get('name',x.get('displayName',x.get('userName'))),
                       'identifier':x.get('identifier')}
                rid=x.get('id')
                if id_safe(rid):
                    try:
                        if key == 'roles':
                            detail=get_or_raise(api,root+'/'+quote(rid,safe=''),auth)
                            entry['audience']=detail.get('audience')
                            for field in ('permissions','users','groups'):
                                entry[field]=[v.get('value') for v in detail.get(field,[]) if isinstance(v,dict)]
                        elif key == 'groups':
                            detail=get_or_raise(api,root+'/'+quote(rid,safe=''),auth)
                            entry['members']=[v.get('value') for v in detail.get('members',[]) if isinstance(v,dict)]
                        elif key == 'apiResources':
                            detail=get_or_raise(api,root+'/'+quote(rid,safe='')+'/scopes',auth)
                            entry['scopes']=[v if isinstance(v,str) else v.get('name') for v in coll(detail,'scopes')]
                        elif key == 'applications':
                            detail=get_or_raise(api,root+'/'+quote(rid,safe=''),auth)
                            entry['isManagementApp']=detail.get('isManagementApp')
                            entry['associatedRoles']=detail.get('associatedRoles',{}).get('allowedAudience') if isinstance(detail.get('associatedRoles'),dict) else None
                    except (InspectionError,OSError,ssl.SSLError):
                        entry['detailsState']='BLOCKED'
                entries.append(entry)
            result[key]=entries
        except (InspectionError,OSError,ssl.SSLError) as e:
            result['catalogs'][key]={'state':'BLOCKED'}
            add_issue(report,'SUPER_'+key.upper()+'_INVENTORY_BLOCKED',detail=str(e) if isinstance(e,InspectionError) else type(e).__name__)
    if result['drift']:
        add_issue(report,'SUPER_TENANT_DRIFT','ACTION_REQUIRED',result['drift'])
    return result

def inspect_docker():
    info={'image':'NOT_VERIFIED','containerRunning':'NOT_VERIFIED', 'baseVersion':'UNVERIFIED',
          'exactUpdateLevel':'NOT_PROVEN', 'updateEvidence':'NONE'}
    try:
        p=subprocess.run(['docker','inspect','--format','{{.Config.Image}}|{{.State.Running}}|{{.Image}}',
                          'wso2-ciam-v10-is-1'],capture_output=True,text=True,timeout=8)
        if p.returncode == 0:
            image,running,image_id=p.stdout.strip().split('|',2)
            info.update({'image':image,'containerRunning':running,'imageId':image_id})
            match=re.search(r'(?<!\d)7\.3\.0(?!\d)',image)
            if match:
                info['baseVersion']='7.3.0_FROM_IMAGE_TAG_ONLY'
    except (OSError,subprocess.TimeoutExpired,ValueError):
        pass
    # WSO2 image tag and installation directory cannot attest update level.
    # Operator-supplied external evidence can be recorded, but not self-certified.
    return info

def baseline_commands(skip_tests, negative):
    commands=[('offlineTests',['./scripts/ciam-v10.sh','test'])] if not skip_tests else []
    commands += [('status',['./scripts/ciam-v10.sh','status']),
                 ('bffDiagnose',['./scripts/ciam-v10.sh','bff-diagnose'])]
    if negative:
        commands.append(('negativeRuntimeAcceptance',['./scripts/ciam-v10.sh','runtime-acceptance']))
    results={}
    for label,cmd in commands:
        path=ROOT/cmd[0].removeprefix('./')
        if not path.is_file():
            results[label]={'state':'UNAVAILABLE_SCRIPT'};continue
        start=time.monotonic()
        try:
            run=subprocess.run(cmd,cwd=ROOT,capture_output=True,timeout=240,check=False)
            # stdout/stderr deliberately NOT written; they can contain live identity data.
            results[label]={'state':'PASSED' if run.returncode==0 else 'FAILED',
                            'exitCode':run.returncode, 'durationSeconds':round(time.monotonic()-start,2)}
        except subprocess.TimeoutExpired:
            results[label]={'state':'TIMED_OUT'}
        except OSError:
            results[label]={'state':'EXECUTION_ERROR'}
    return results

def build_report(mode, skip_tests, negative):
    source=inspect_git()
    report={'schema':'ciam.v10.inspection.v1','timestampUtc':datetime.now(timezone.utc).isoformat(),
            'safety':{'readOnlyHttpMethods':['GET'],'remoteWrites':0,'dockerMutations':0},
            'source':source,'issues':[],'runtime':{},'evidenceLimitations':[]}
    sha=source['git']['sha']
    if source['git']['dirty']:
        add_issue(report,'SOURCE_WORKTREE_DIRTY','ACTION_REQUIRED')
    for name, record in source['canonicalFiles'].items():
        if not record['present']:
            add_issue(report,'SOURCE_COMPONENT_MISSING_'+name.upper(),'ACTION_REQUIRED')
    if mode in ('all','source'):
        report['existingBehavior']=baseline_commands(skip_tests, negative)
        if any(x.get('state')=='FAILED' for x in report['existingBehavior'].values()):
            add_issue(report,'EXISTING_BASELINE_CHECKS_FAILED','ACTION_REQUIRED')
    if mode in ('all','runtime'):
        journals={}
        for key,name in EXPECTED.items():
            try:
                journals[key]=safe_file(PRIVATE/name) or {}
            except InspectionError as e:
                journals[key]={}
                add_issue(report,'JOURNAL_'+key.upper()+'_UNAVAILABLE',detail=str(e))
        try:
            journals['admin']=safe_file(PRIVATE/'admin.private.json') or {}
        except InspectionError as e:
            journals['admin']={}
            add_issue(report,'ADMIN_JOURNAL_UNAVAILABLE',detail=str(e))
        report['runtime']['journals']={k:{'available':bool(v),'schema':v.get('schema'),
            'acceptance':v.get('acceptance'),'roleApiVersion':v.get('roleApiVersion')}
            for k,v in journals.items()}
        report['runtime']['docker']=inspect_docker()
        if report['runtime']['docker']['exactUpdateLevel']=='NOT_PROVEN':
            add_issue(report,'WSO2_EXACT_UPDATE_LEVEL_NOT_PROVEN')
        try:
            api=API()
            report['runtime']['super']=inspect_super(api,journals,report)
            report['runtime']['tenants']={}
            for brand,domain in DOMAINS.items():
                owner=journals.get('tenants',{}).get('tenants',{}).get(brand,{}).get('owner',{})
                if owner.get('password'):
                    auth=basic('labtenantadmin@'+domain,owner['password'])
                    report['runtime']['tenants'][brand]=inspect_tenant(api,brand,domain,auth,journals,report)
                else:
                    report['runtime']['tenants'][brand]={'state':'BLOCKED_OWNER_JOURNAL_UNAVAILABLE'}
                    add_issue(report,brand.upper()+'_OWNER_CREDENTIALS_NOT_AVAILABLE')
            report['runtime']['httpGetCount']=api.request_count
        except (InspectionError,OSError,ssl.SSLError) as e:
            add_issue(report,'LIVE_WSO2_READBACK_UNAVAILABLE',detail=str(e) if isinstance(e,InspectionError) else type(e).__name__)
        report['evidenceLimitations'] += [
            'Management GET readbacks do not prove successful browser authentication.',
            'Container image tag does not prove exact WSO2 update level.',
            'Missing API data caused by permissions or unavailable endpoints is BLOCKED, not ABSENT.',
            'MFA, consent behavior and token grants require separate live runtime acceptance.'
        ]
    report['decision'] = ('INCOMPLETE' if report['issues'] else 'READ_ONLY_INSPECTION_COMPLETE_NOT_RUNTIME_CERTIFIED')
    return report, sha

def main():
    p=argparse.ArgumentParser(description='Read-only WSO2 CIAM v10 Git+runtime inventory')
    p.add_argument('--mode',choices=('all','source','runtime'),default='all')
    p.add_argument('--skip-tests',action='store_true')
    p.add_argument('--with-runtime-negative',action='store_true',help='Run existing negative runtime checks (no login)')
    args=p.parse_args()
    os.umask(0o077)
    try:
        report,sha=build_report(args.mode,args.skip_tests,args.with_runtime_negative)
        out=make_output(sha)
        path=write_json(out,'inspection.json',report)
        brief={'commit':sha,'mode':args.mode,'decision':report['decision'],
               'issueCodes':[x['code'] for x in report['issues']], 'fullReport':str(path),
               'privacy':'LOCAL_PRIVATE_REPORT_DO_NOT_COMMIT'}
        write_json(out,'summary.json',brief)
        print(json.dumps(brief,indent=2))
        # Exit code distinguishes success of inspection from incomplete inventory.
        return 0 if not report['issues'] else 2
    except (InspectionError,OSError,ValueError) as e:
        print('CIAM_INSPECT_STOP: '+(str(e) if isinstance(e,InspectionError) else type(e).__name__),file=sys.stderr)
        return 3
if __name__=='__main__':
    sys.exit(main())
