#!/usr/bin/env python3
"""Magalu native-security stage of the EXISTING CIAM v10 bootstrap.

Operations: plan, apply, verify, status. No tenant/app creates, DB writes,
manual Console operations, unsafe TLS or assumptions about remote connector IDs.
Management API write ownership is recorded BEFORE each operation and read back.
A crash or unexpected response leaves the operation uncertain and blocks retries.
"""
from __future__ import annotations
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote
import recaptcha

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10'))).expanduser()
PRIVATE = ROOT / 'private'
JOURNAL = PRIVATE / 'magalu-native-security.private.json'
LOCK = PRIVATE / 'magalu-native-security.lock'
CERT = PRIVATE / 'wso2-9444-leaf.pem'
CREDS = Path(os.environ.get('MAGALU_RECAPTCHA_CREDENTIAL_FILE',
                            str(PRIVATE / 'magalu-recaptcha.private.json'))).expanduser()
DOMAINS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}
CHANNELS = ('web', 'app')
CONFIRM = 'APPLY_MAGALU_NATIVE_SECURITY_TO_EXISTING_GA_V10'
BASE = 'https://localhost:9444'
CONTAINER = 'wso2-ciam-v10-is-1'
VOLUME = 'wso2-ciam-v10_isconf'
REMOTE_CONF = '/home/wso2carbon/wso2is-7.3.0/repository/conf/deployment.toml'
SCHEMA = 'magalu.wso2.native.security.journal.v1'
ID = re.compile(r'^[A-Za-z0-9_+/-]{1,160}={0,2}$')

# These *documented property names* are looked up from live connector responses.
# Connector/category IDs are NEVER hardcoded.
LOCK_KEYS = {
    'account.lock.handler.lock.on.max.failed.attempts.enable': lambda p: 'true' if p['enabled'] else 'false',
    'account.lock.handler.On.Failure.Max.Attempts': lambda p: str(p['maximumFailures']),
    'account.lock.handler.Time': lambda p: str(p['lockMinutes']),
    'account.lock.handler.login.fail.timeout.ratio': lambda p: str(p['durationMultiplier']),
}
BOT_KEYS = {
    'sso.login.recaptcha.enable': lambda p: 'true' if p['enabled'] else 'false',
    'sso.login.recaptcha.enable.always': lambda p: 'true' if p['always'] else 'false',
    'sso.login.recaptcha.on.max.failed.attempts': lambda p: str(p['maximumFailuresBeforeChallenge']),
}

class Refused(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Refused(code)

def canon(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def sha(v):
    return hashlib.sha256((v if isinstance(v, str) else canon(v)).encode()).hexdigest()

def safe_id(v):
    need(isinstance(v, str) and ID.fullmatch(v) is not None, 'UNSAFE_RESOURCE_IDENTIFIER')
    return quote(v, safe='')

def private_json(path):
    need(path.is_file() and not path.is_symlink(), 'PRIVATE_FILE_MISSING_'+path.name)
    st = path.stat()
    need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size < 262144,
         'PRIVATE_FILE_UNSAFE_'+path.name)
    return json.loads(path.read_text(encoding='utf-8'))

def private_dir():
    need(ROOT.is_dir() and not ROOT.is_symlink() and PRIVATE.is_dir() and not PRIVATE.is_symlink(),
         'V10_HOME_NOT_INITIALIZED')
    for p in (ROOT, PRIVATE):
        need(p.stat().st_uid == os.getuid() and not stat.S_IMODE(p.stat().st_mode) & 0o022,
             'PRIVATE_HOME_OWNER_OR_PERMISSIONS_UNSAFE')
    need((ROOT / 'compose.identity.yaml').is_file(), 'GA_V10_COMPOSE_MISSING')

def atomic_json(path, obj):
    private_dir()
    need(path.parent == PRIVATE and not path.is_symlink(), 'UNSAFE_JOURNAL_TARGET')
    fd, tmp = tempfile.mkstemp(prefix='.magalu-journal-', dir=PRIVATE)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(canon(obj)+'\n'); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        pfd = os.open(PRIVATE, os.O_RDONLY)
        try: os.fsync(pfd)
        finally: os.close(pfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def policies():
    result = {}
    for brand, domain in DOMAINS.items():
        p = HERE / 'policy' / (brand+'.json')
        need(p.is_file() and not p.is_symlink(), 'POLICY_FILE_MISSING_'+brand)
        cfg = json.loads(p.read_text(encoding='utf-8'))
        need(cfg.get('schema') == 'magalu.wso2.native.security.v1' and
             cfg.get('brand') == brand and cfg.get('domain') == domain,
             'TENANT_POLICY_IDENTITY_MISMATCH_'+brand)
        a = cfg.get('loginAttempts', {}); b = cfg.get('recaptcha', {})
        need(a.get('enabled') is True and b.get('enabled') is True and type(b.get('always')) is bool,
             'NATIVE_PROTECTION_MUST_BE_ENABLED_'+brand)
        for key, lo, hi in (('maximumFailures', 3, 20), ('lockMinutes', 1, 1440),
                            ('durationMultiplier', 1, 10), ('stepUpAfterFailures', 1, 19)):
            need(type(a.get(key)) is int and lo <= a[key] <= hi, 'INVALID_LOGIN_POLICY_'+brand+'_'+key)
        need(a['stepUpAfterFailures'] < a['maximumFailures'], 'STEPUP_MUST_PRECEDE_LOCK_'+brand)
        need(type(b.get('maximumFailuresBeforeChallenge')) is int and
             1 <= b['maximumFailuresBeforeChallenge'] < a['maximumFailures'],
             'INVALID_BOT_POLICY_'+brand)
        result[brand] = cfg
    return result

def script_for(brand, cfg):
    text = (HERE / 'scripts/magalu-adaptive.js').read_text(encoding='utf-8')
    need(text.count('__MAGALU_THRESHOLD__') == 1 and text.count('__MAGALU_AURORA__') == 1,
         'TEMPLATE_DRIFT')
    text = text.replace('__MAGALU_THRESHOLD__', str(cfg['loginAttempts']['stepUpAfterFailures']))
    text = text.replace('__MAGALU_AURORA__', 'true' if brand == 'aurora' else 'false')
    need('executeStep(1' in text and 'executeStep(2' in text and '..' not in text,
         'ADAPTIVE_SCRIPT_INVALID')
    return text

def owner_context():
    ts = private_json(PRIVATE / 'bootstrap-tenants-v10.private.json')
    apps = private_json(PRIVATE / 'bootstrap-oidc-v10.private.json')
    need(ts.get('schema') == 'identity.wso2.ciam.v10.tenants' and ts.get('base') == BASE and
         ts.get('domains') == DOMAINS and apps.get('schema') == 'identity.wso2.ciam.v10.oidc.v1' and
         apps.get('base') == BASE, 'V10_JOURNALS_NOT_AUTHORITATIVE')
    result = {}
    for brand, domain in DOMAINS.items():
        t = ts['tenants'][brand]
        need(t.get('status') == 'readback-verified' and t.get('domain') == domain and
             t.get('owner', {}).get('username') == 'labtenantadmin' and
             isinstance(t['owner'].get('password'), str) and t['owner']['password'],
             'TENANT_OWNER_INVALID_'+brand)
        nodes = apps['tenants'][brand]['clients']
        for channel in CHANNELS:
            n = nodes[channel]
            need(n.get('state') == 'verified' and ID.fullmatch(str(n.get('id', ''))) and
                 n.get('callback') == f'http://127.0.0.1:4400/auth/{brand}-{channel}/callback' and
                 n.get('clientId') and n.get('name'), 'OIDC_OWNERSHIP_NOT_PROVEN_'+brand+'_'+channel)
        user = t['owner']['username']+'@'+domain
        auth = 'Basic '+base64.b64encode((user+':'+t['owner']['password']).encode()).decode()
        result[brand] = {'domain': domain, 'tenantId': t.get('tenantId'),
                         'auth': auth, 'nodes': nodes}
    need(len({result[b]['tenantId'] for b in DOMAINS}) == 2 and
         None not in {result[b]['tenantId'] for b in DOMAINS}, 'DUPLICATE_OR_MISSING_TENANT_IDS')
    need(len({result[b]['nodes'][c]['id'] for b in DOMAINS for c in CHANNELS}) == 4 and
         len({result[b]['nodes'][c]['clientId'] for b in DOMAINS for c in CHANNELS}) == 4,
         'DUPLICATE_APPLICATION_OR_CLIENT_IDS')
    return result

class WSO2:
    """Pinned CA and hostname checks. No self-signed TLS bypass or redirects."""
    def __init__(self):
        need(CERT.is_file() and not CERT.is_symlink(), 'PINNED_WSO2_CERT_REQUIRED')
        s = CERT.stat()
        need(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o600,
             'PINNED_CERT_UNSAFE')
        self.tls = ssl.create_default_context(cafile=str(CERT))
        self.tls.check_hostname = True
    def call(self, brand, auth, method, path, data=None, etag=None):
        need(brand in DOMAINS and method in ('GET', 'PATCH', 'PUT'), 'HTTP_METHOD_DENIED')
        need(path.startswith('/t/'+DOMAINS[brand]+'/api/server/v1/') and
             '..' not in path and '#' not in path and '\\' not in path and '//' not in path and
             len(path) < 1600, 'CROSS_TENANT_HTTP_PATH_DENIED')
        tail = path.split('/api/server/v1/', 1)[1]
        allowed = bool(tail.startswith('identity-governance') and
                   re.fullmatch(r'identity-governance(?:/[A-Za-z0-9_%+.-]+)*(?:/connectors(?:/[A-Za-z0-9_%+.-]+)?)?', tail))
        allowed |= bool(re.fullmatch(r'applications/[A-Za-z0-9_%=-]+(?:/inbound-protocols/oidc|/authenticationSequence/script)?', tail))
        allowed |= tail in ('authenticators', 'configs/authenticators?type=LOCAL')
        need(bool(allowed), 'UNSUPPORTED_API_PATH')
        if method == 'PATCH':
            need((tail.startswith('identity-governance/') and '/connectors/' in tail and
                  isinstance(data, dict) and data.get('operation') == 'UPDATE' and
                  isinstance(data.get('properties'), list) and len(data['properties']) == 1) or
                 (tail.startswith('applications/') and set(data or {}) == {'authenticationSequence'}),
                 'PATCH_SHAPE_DENIED')
        if method == 'PUT':
            need(tail.endswith('/authenticationSequence/script') and set(data or {}) == {'script'},
                 'PUT_SHAPE_DENIED')
        need(auth.startswith('Basic '), 'TENANT_OWNER_AUTH_REQUIRED')
        headers = {'Authorization': auth, 'Accept': 'application/json'}
        if data is not None: headers['Content-Type'] = 'application/json'
        if etag:
            need(method != 'GET' and len(etag) < 200 and '\n' not in etag and '\r' not in etag,
                 'INVALID_ETAG')
            headers['If-Match'] = etag
        conn = http.client.HTTPSConnection('localhost', 9444, context=self.tls, timeout=15)
        try:
            conn.request(method, path, body=canon(data) if data is not None else None, headers=headers)
            r = conn.getresponse(); raw = r.read(262145)
            need(len(raw) <= 262144 and not 300 <= r.status < 400, 'HTTP_RESPONSE_UNSAFE')
            obj = json.loads(raw) if raw and 'json' in (r.getheader('Content-Type') or '') else None
            need((method == 'GET' and r.status == 200 and isinstance(obj, (dict, list))) or
                 (method != 'GET' and r.status in (200, 204)), 'WSO2_API_'+method+'_HTTP_'+str(r.status))
            return obj, r.getheader('ETag')
        finally: conn.close()

def gather_properties(api, brand, ctx):
    base = '/t/'+DOMAINS[brand]+'/api/server/v1/identity-governance'
    root, _ = api.call(brand, ctx['auth'], 'GET', base)
    cats = root if isinstance(root, list) else root.get('categories', [])
    need(isinstance(cats, list) and 1 <= len(cats) <= 40, 'INVALID_GOVERNANCE_CATEGORY_LIST')
    discovered = {}
    def walk(value, category, connector=None):
        if isinstance(value, list):
            for v in value: walk(v, category, connector)
        elif isinstance(value, dict):
            if isinstance(value.get('properties'), list) and isinstance(value.get('id'), str):
                connector = value['id']
                for p in value['properties']:
                    if isinstance(p, dict) and isinstance(p.get('name'), str):
                        key = p['name']
                        if key in LOCK_KEYS or key in BOT_KEYS:
                            val = p.get('value')
                            entry = {'value':str(val).lower() if isinstance(val, bool) else str(val),
                                     'category':category, 'connector':connector}
                            need(key not in discovered or discovered[key] == entry,
                                 'AMBIGUOUS_GOVERNANCE_PROPERTY_'+key)
                            discovered[key] = entry
            for k in ('categories', 'connectors', 'subCategories', 'items'):
                if k in value: walk(value[k], category, connector)
    for cat in cats:
        need(isinstance(cat, dict), 'GOVERNANCE_CATEGORY_INVALID')
        cid = cat.get('id'); safe_id(cid)
        # Both endpoint layouts are used by GA connectors. Scan all, never infer IDs.
        for suffix in ('/'+safe_id(cid), '/'+safe_id(cid)+'/connectors'):
            try:
                body, _ = api.call(brand, ctx['auth'], 'GET', base+suffix)
            except Refused as e:
                # Refuse if a required endpoint can't be read: do not silently skip.
                raise Refused('GOVERNANCE_DISCOVERY_FAILED_'+brand) from e
            walk(body, cid)
    need(all(k in discovered for k in tuple(LOCK_KEYS)+tuple(BOT_KEYS)),
         'GOVERNANCE_PROPERTY_NOT_DISCOVERED_'+brand+':'+','.join(sorted((set(LOCK_KEYS)|set(BOT_KEYS))-set(discovered))))
    # Connector and category ids MUST originate from the live response.
    return discovered

def totp_capability(api, brand, ctx):
    domain=DOMAINS[brand]
    body=None
    for index, suffix in enumerate(('authenticators', 'configs/authenticators?type=LOCAL')):
        try:
            body,_=api.call(brand,ctx['auth'],'GET',
                            '/t/'+domain+'/api/server/v1/'+suffix)
            break
        except Refused as ex:
            if index == 0 and str(ex) in ('WSO2_API_GET_HTTP_404','WSO2_API_GET_HTTP_501'):
                continue
            raise
    if isinstance(body,list): rows=body
    elif isinstance(body,dict):
        values=[body[k] for k in ('authenticators','items') if k in body]
        need(len(values)==1 and isinstance(values[0],list),'TOTP_AUTHENTICATORS_UNKNOWN_FORMAT')
        rows=values[0]
    else: raise Refused('TOTP_AUTHENTICATOR_API_UNAVAILABLE')
    need(len(rows)<=256 and all(isinstance(row,dict) for row in rows),
         'TOTP_AUTHENTICATOR_RESPONSE_INVALID')
    matching=[x for x in rows if str(x.get('name','')).lower() in ('totp','totpauthenticator')
              or str(x.get('displayName','')).lower() in ('totp','time-based one-time password')]
    need(len(matching)==1 and matching[0].get('isEnabled') is True and
         matching[0].get('type') in (None,'LOCAL'), 'LOCAL_TOTP_NOT_ENABLED_'+brand)
    return True

def app_path(brand, node):
    return '/t/'+DOMAINS[brand]+'/api/server/v1/applications/'+safe_id(node['id'])

def read_apps(api, brand, ctx):
    result = {}
    for channel in CHANNELS:
        node = ctx['nodes'][channel]; path = app_path(brand, node)
        app, etag = api.call(brand, ctx['auth'], 'GET', path)
        proto, _ = api.call(brand, ctx['auth'], 'GET', path+'/inbound-protocols/oidc')
        need(app.get('id') == node['id'] and app.get('name') == node['name'] and
             app.get('associatedRoles', {}).get('allowedAudience') == 'APPLICATION' and
             proto.get('clientId') == node.get('clientId') and
             proto.get('callbackURLs') == [node['callback']] and
             'authorization_code' in proto.get('grantTypes', []) and
             proto.get('pkce', {}).get('mandatory') is True and
             proto.get('pkce', {}).get('supportPlainTransformAlgorithm') is False,
             'FOUR_OIDC_INVARIANTS_FAILED_'+brand+'_'+channel)
        seq = app.get('authenticationSequence')
        need(isinstance(seq, dict) and isinstance(seq.get('steps'), list), 'AUTH_SEQUENCE_MISSING')
        result[channel] = {'app':app, 'proto':proto, 'seq':seq, 'etag':etag, 'path':path, 'node':node}
    return result

def basic_step(seq):
    steps = seq['steps']
    return (len(steps) >= 1 and steps[0].get('id') == 1 and
            steps[0].get('options') == [{'idp':'LOCAL','authenticator':'BasicAuthenticator'}] and
            seq.get('subjectStepId', 1) == 1 and seq.get('attributeStepId', 1) == 1 and
            seq.get('requestPathAuthenticators', []) in ([], None))

def totp_step(seq):
    return len(seq['steps']) == 2 and seq['steps'][1] == {
        'id': 2, 'options':[{'idp':'LOCAL','authenticator':'totp'}]}

def sequence_kind(seq, desired, legacy=None):
    need(basic_step(seq), 'UNOWNED_AUTHENTICATION_SEQUENCE')
    if seq.get('type') == 'DEFAULT' and len(seq['steps']) == 1 and seq.get('script') in (None, ''):
        return 'default'
    need(seq.get('type') == 'USER_DEFINED' and totp_step(seq), 'UNOWNED_AUTHENTICATION_SEQUENCE')
    if seq.get('script') == desired: return 'desired'
    if legacy is not None and seq.get('script') == legacy: return 'legacy-aurora'
    raise Refused('UNOWNED_AUTHENTICATION_SCRIPT')

def desired_seq(seq, script):
    need(basic_step(seq), 'UNOWNED_BASIC_AUTH')
    after = {k:v for k,v in seq.items() if k not in ('type', 'steps', 'script')}
    after.update({'type':'USER_DEFINED', 'steps':[seq['steps'][0],
                   {'id':2,'options':[{'idp':'LOCAL','authenticator':'totp'}]}],
                  'subjectStepId':1, 'attributeStepId':1, 'script':script})
    need(sequence_kind(after, script) == 'desired', 'GENERATED_SEQUENCE_INVALID')
    return after

def app_unrelated(app):
    # Stable fields: WSO2 may legitimately update metadata timestamps on PATCH.
    keys=('id','name','description','associatedRoles','claimConfiguration',
          'advancedConfigurations','provisioningConfigurations',
          'inboundProtocolConfiguration','applicationEnabled','isManagementApp')
    return {k:app.get(k) for k in keys}

def spec_values(cfg):
    result = {k:f(cfg['loginAttempts']) for k,f in LOCK_KEYS.items()}
    result.update({k:f(cfg['recaptcha']) for k,f in BOT_KEYS.items()})
    return result

def legacy_script():
    path = HERE.parent / 'p010/aurora-acr-totp-adaptive.js'
    return path.read_text(encoding='utf-8') if path.is_file() else None

def inventory(api, owners, config):
    data = {}
    for brand in DOMAINS:
        ctx = owners[brand]
        need(totp_capability(api, brand, ctx), 'TOTP_CAPABILITY_REQUIRED_'+brand)
        props = gather_properties(api, brand, ctx)
        apps = read_apps(api, brand, ctx)
        desired = script_for(brand, config[brand])
        result = {'policy': {}, 'apps': {}}
        for name,want in spec_values(config[brand]).items():
            entry = props[name]
            result['policy'][name] = {'before':entry['value'], 'want':want,
                                       'category':entry['category'], 'connector':entry['connector']}
        for channel, obj in apps.items():
            kind = sequence_kind(obj['seq'], desired, legacy_script() if brand == 'aurora' else None)
            result['apps'][channel] = {'kind':kind, 'before':sha(obj['seq']),
                                        'want':sha(desired_seq(obj['seq'], desired)),
                                        'etag':obj['etag'] or ''}
        data[brand] = {'summary':result, 'rawProps':props, 'rawApps':apps}
    return data

def operations(data):
    changes = []
    for brand in DOMAINS:
        for key, v in data[brand]['summary']['policy'].items():
            if v['before'] != v['want']:
                changes.append({'resource':'governance','brand':brand,'key':key,
                                'before':v['before'],'want':v['want'],
                                'category':v['category'],'connector':v['connector']})
        for channel, v in data[brand]['summary']['apps'].items():
            if v['before'] != v['want']:
                changes.append({'resource':'application','brand':brand,'channel':channel,
                                'before':v['before'],'want':v['want'], 'kind':v['kind']})
    return changes

def planned(data, cfg, recaptcha_state):
    summary = {b:data[b]['summary'] for b in DOMAINS}
    # Plan remains safe to print: no owner credentials, client secret or reCAPTCHA keys.
    public = {'schema':SCHEMA, 'target':BASE, 'image':'wso2/wso2is:7.3.0',
              'recaptcha':recaptcha_state, 'policyHashes':{b:sha(cfg[b]) for b in DOMAINS},
              'summary':summary, 'changes':operations(data)}
    public['planSha256'] = sha(public)
    return public

def docker(args, *, capture=True):
    cmd = ['docker']+args
    p = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
    need(p.returncode == 0, 'V10_DOCKER_COMMAND_FAILED')
    return p.stdout if capture else b''

def runtime_guard():
    obj = json.loads(docker(['inspect', CONTAINER]))
    need(len(obj) == 1, 'V10_DOCKER_INSPECT_AMBIGUOUS')
    c = obj[0]
    need(c.get('Name') == '/'+CONTAINER and c.get('Config', {}).get('Image') == 'wso2/wso2is:7.3.0' and
         c.get('State', {}).get('Running') is True and
         c.get('Config', {}).get('Labels', {}).get('com.docker.compose.project') == 'wso2-ciam-v10' and
         any(m.get('Name') == VOLUME and m.get('Destination') == str(Path(REMOTE_CONF).parent)
             for m in c.get('Mounts', [])),
         'NOT_EXACT_RUNNING_GA_V10_CONFIG_VOLUME')
    return c

def remote_toml():
    runtime_guard()
    with tempfile.TemporaryDirectory(prefix='.magalu-stage-', dir=PRIVATE) as folder:
        file = Path(folder)/'current.toml'
        docker(['cp',CONTAINER+':'+REMOTE_CONF,str(file)])
        return file.read_text(encoding='utf-8')

def recaptcha_inventory(credentials):
    stock_file = PRIVATE/'deployment.toml'
    need(stock_file.is_file() and not stock_file.is_symlink() and
         stat.S_IMODE(stock_file.stat().st_mode) == 0o600 and
         stock_file.stat().st_uid == os.getuid(),
         'V10_PRIVATE_TOML_UNSAFE')
    local = stock_file.read_text(encoding='utf-8')
    remote = remote_toml()
    need(local == remote, 'V10_PRIVATE_AND_RUNNING_CONFIG_DRIFT')
    # If already managed, idempotent. If there is another recaptcha block: refuse.
    desired = recaptcha.render(local, credentials)
    return {'currentSha256':sha(local), 'desiredSha256':sha(desired),
            'configured':local == desired, 'restartRequired':local != desired}

def recaptcha_stage(credentials, plan, api, owner):
    status = recaptcha_inventory(credentials)
    need(status == plan, 'RECAPTCHA_PRECONDITION_DRIFT')
    if status['configured']: return status
    need(os.environ.get('MAGALU_SECURITY_ALLOW_RESTART') == 'YES_RESTART_ONLY_V10_GA',
         'EXPLICIT_GA_V10_RESTART_APPROVAL_REQUIRED')
    current = (PRIVATE/'deployment.toml').read_text(encoding='utf-8')
    after = recaptcha.render(current, credentials)
    backup = PRIVATE/'magalu-deployment-before.private.toml'
    need(not backup.exists() and not backup.is_symlink(), 'CONFIG_BACKUP_ALREADY_EXISTS_STOP')
    fd = os.open(backup, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f: f.write(current); f.flush(); os.fsync(f.fileno())
    with tempfile.TemporaryDirectory(prefix='.magalu-stage-', dir=PRIVATE) as folder:
        stage = Path(folder)/'deployment.toml'
        stage.write_text(after, encoding='utf-8'); stage.chmod(0o600)
        docker(['cp',str(stage),CONTAINER+':'+REMOTE_CONF+'.magalu.stage'])
        docker(['exec','-u','0:0',CONTAINER,'/bin/sh','-c',
                'set -eu; p="'+REMOTE_CONF+'"; test -f "$p.magalu.stage"; '
                'chown 802:802 "$p.magalu.stage"; chmod 600 "$p.magalu.stage"; '
                'mv "$p.magalu.stage" "$p"'])
    # Never claim an uncertain server file operation as successfully applied.
    need(sha(remote_toml()) == sha(after), 'REMOTE_TOML_READBACK_FAILED')
    with tempfile.NamedTemporaryFile(prefix='.magalu-local-',dir=PRIVATE,delete=False,mode='w') as f:
        f.write(after);f.flush();os.fsync(f.fileno()); name=f.name
    os.chmod(name,0o600);os.replace(name, PRIVATE/'deployment.toml')
    docker(['compose','-p','wso2-ciam-v10','-f',str(ROOT/'compose.yaml'),
            '-f',str(ROOT/'compose.identity.yaml'),'restart','is'])
    for attempt in range(45):
        try:
            runtime_guard()
            api.call('aurora', owner['auth'], 'GET',
                     '/t/aurora.identity.test/api/server/v1/identity-governance')
            break
        except (Refused, OSError, ssl.SSLError, socket.timeout):
            if attempt == 44: raise Refused('V10_NOT_READY_AFTER_RECAPTCHA_RESTART') from None
            time.sleep(2)
    need(sha(remote_toml()) == sha(after), 'RECAPTCHA_RESTART_READBACK_FAILED')
    return {'currentSha256':sha(after),'desiredSha256':sha(after),
            'configured':True,'restartRequired':False}

def exclusive_lock():
    private_dir()
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(LOCK, flags, 0o600)
    need(stat.S_ISREG(os.fstat(fd).st_mode) and stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
         and os.fstat(fd).st_uid == os.getuid(), 'MAGALU_LOCK_FILE_UNSAFE')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Refused('ANOTHER_MAGALU_SECURITY_PROCESS_RUNNING') from None
    return fd

def installed_journal():
    if not JOURNAL.exists() and not JOURNAL.is_symlink(): return None
    j = private_json(JOURNAL)
    need(j.get('schema') == SCHEMA and isinstance(j.get('operations'),list), 'MAGALU_JOURNAL_INVALID')
    return j

def governance_patch(api, owner, op):
    brand=op['brand']; key=op['key']
    path = '/t/'+DOMAINS[brand]+'/api/server/v1/identity-governance/'+safe_id(op['category'])+ \
           '/connectors/'+safe_id(op['connector'])
    body={'operation':'UPDATE','properties':[{'name':key,'value':op['want']}]}
    api.call(brand, owner['auth'],'PATCH',path,body)
    new = gather_properties(api, brand, owner)
    need(new[key]['value'] == op['want'] and
         new[key]['category'] == op['category'] and new[key]['connector'] == op['connector'],
         'GOVERNANCE_PATCH_READBACK_FAILED')

def app_patch(api, owner, op, cfg):
    brand=op['brand']; channel=op['channel']
    current = read_apps(api,brand,owner)[channel]
    wanted = script_for(brand,cfg)
    need(sha(current['seq']) == op['before'], 'APP_PRECONDITION_DRIFT')
    old_unrelated = app_unrelated(current['app']); old_proto = current['proto']
    if op['kind'] == 'default':
        need(current['etag'] or os.environ.get('MAGALU_SECURITY_ACK_NO_ETAG') ==
             'ACK_NO_HTTP_ETAG_EXCLUSIVE_MAINTENANCE_WINDOW',
             'APP_ETAG_MISSING_EXPLICIT_CONCURRENCY_ACK_REQUIRED')
        api.call(brand,owner['auth'],'PATCH',current['path'],
                 {'authenticationSequence':desired_seq(current['seq'],wanted)},current['etag'])
    else:
        need(op['kind'] in ('legacy-aurora', 'desired'), 'UNOWNED_SCRIPT_UPDATE')
        need(current['etag'] or os.environ.get('MAGALU_SECURITY_ACK_NO_ETAG') ==
             'ACK_NO_HTTP_ETAG_EXCLUSIVE_MAINTENANCE_WINDOW',
             'SCRIPT_ETAG_MISSING_EXPLICIT_CONCURRENCY_ACK_REQUIRED')
        api.call(brand,owner['auth'],'PUT',current['path']+'/authenticationSequence/script',
                 {'script':wanted},current['etag'])
    new = read_apps(api,brand,owner)[channel]
    need(new['proto'] == old_proto and app_unrelated(new['app']) == old_unrelated and
         sha(new['seq']) == op['want'] and sequence_kind(new['seq'],wanted) == 'desired',
         'APPLICATION_PATCH_READBACK_FAILED')

def apply_changes(api, owners, config, ops, journal):
    # Before EACH write, start a durable record; never retry any uncertain write.
    for idx, op in enumerate(ops):
        state = journal['operations'][idx]
        need(state['state'] in ('pending','verified'), 'UNCERTAIN_WRITE_REFUSE_REPLAY')
        if state['state'] == 'verified':
            # Verified earlier writes must remain as intended.
            if op['resource'] == 'governance':
                current = gather_properties(api,op['brand'],owners[op['brand']])[op['key']]['value']
                need(current == op['want'],'VERIFIED_PROPERTY_DRIFT')
            else:
                current = read_apps(api,op['brand'],owners[op['brand']]) [op['channel']]['seq']
                need(sha(current) == op['want'],'VERIFIED_APPLICATION_DRIFT')
            continue
        state['state']='write-started'; atomic_json(JOURNAL,journal)
        try:
            if op['resource'] == 'governance':
                current = gather_properties(api,op['brand'],owners[op['brand']])[op['key']]
                need(current['value'] == op['before'] and current['category'] == op['category'] and
                     current['connector'] == op['connector'], 'GOVERNANCE_PRECONDITION_DRIFT')
                governance_patch(api,owners[op['brand']],op)
            else:
                app_patch(api,owners[op['brand']],op,config[op['brand']])
        except Exception:
            state['state']='uncertain';atomic_json(JOURNAL,journal)
            raise Refused('REMOTE_WRITE_UNCERTAIN_OPERATOR_REVIEW_REQUIRED') from None
        state['state']='verified';atomic_json(JOURNAL,journal)

def verify_all(api, owners, config, journal, credentials, *, require_verified_state=True):
    need(journal is not None and (journal.get('state') == 'verified' if require_verified_state
                                 else journal.get('state') == 'applying'),
         'NO_VERIFIED_OWNERSHIP_JOURNAL')
    need(journal.get('policyHashes') == {b:sha(config[b]) for b in DOMAINS}, 'POLICY_HASH_CHANGED')
    for brand in DOMAINS:
        need(totp_capability(api,brand,owners[brand]),'TOTP_CAPABILITY_REQUIRED_'+brand)
        discovered=gather_properties(api,brand,owners[brand])
        for k,want in spec_values(config[brand]).items():
            need(discovered[k]['value'] == want, 'GOVERNANCE_NOT_EFFECTIVE_'+brand+'_'+k)
        for channel, current in read_apps(api,brand,owners[brand]).items():
            need(sequence_kind(current['seq'],script_for(brand,config[brand])) == 'desired',
                 'APP_SEQUENCE_NOT_EFFECTIVE_'+brand+'_'+channel)
    bot = recaptcha_inventory(credentials)
    need(bot['configured'], 'RECAPTCHA_NOT_STAGED_IN_V10')
    return {'status':'MANAGEMENT_READBACK','nativeAccountLock':'CONFIGURED_READBACK',
            'botDetection':'CONFIG_AND_GOVERNANCE_READBACK_ONLY_NOT_CHALLENGE_TESTED',
            'conditionalTotp':'FOUR_SEQUENCE_READBACK_ONLY_NOT_LIVE_CHALLENGE_TESTED',
            'realAuthenticationTests':'NOT_RUN'}

def preflight_write_authorizations(plan):
    """Reject missing maintenance approvals before the first remote mutation.

    This is deliberately pure so offline tests can prove refusal causes no
    network access or write-ahead journal creation.
    """
    bot = plan.get('recaptcha', {})
    if bot.get('restartRequired'):
        need(os.environ.get('MAGALU_SECURITY_ALLOW_RESTART') ==
             'YES_RESTART_ONLY_V10_GA',
             'EXPLICIT_GA_V10_RESTART_APPROVAL_REQUIRED_BEFORE_WRITE')
    for op in plan.get('changes', []):
        if op['resource'] != 'application':
            continue
        app = plan['summary'][op['brand']]['apps'][op['channel']]
        need(app['before'] == op['before'] and app['want'] == op['want'],
             'APPLICATION_PLAN_SUMMARY_INCONSISTENT')
        if not app.get('etag'):
            need(os.environ.get('MAGALU_SECURITY_ACK_NO_ETAG') ==
                 'ACK_NO_HTTP_ETAG_EXCLUSIVE_MAINTENANCE_WINDOW',
                 'APPLICATION_ETAG_MISSING_ACK_REQUIRED_BEFORE_ANY_WRITE')

# A verified GA installation can have an application-script runtime bug even
# after Management API readback. Repair the four scripts under the SAME v10
# bootstrap owner; never replay the original governance or reCAPTCHA writes.
REPAIR_JOURNAL = PRIVATE / 'magalu-adaptive-runtime-repair.private.json'
REPAIR_SCHEMA = 'magalu.wso2.adaptive.repair.v1'
REPAIR_CONFIRM = 'REPAIR_OWNED_MAGALU_AUTH_SCRIPTS_ONLY'


def repair_journal():
    if not REPAIR_JOURNAL.exists() and not REPAIR_JOURNAL.is_symlink():
        return None
    j = private_json(REPAIR_JOURNAL)
    need(j.get('schema') == REPAIR_SCHEMA and isinstance(j.get('operations'),list),
         'ADAPTIVE_REPAIR_JOURNAL_INVALID')
    return j


def original_app_write(journal, brand, channel):
    need(journal is not None and journal.get('schema') == SCHEMA and
         journal.get('state') == 'verified', 'ORIGINAL_SECURITY_INSTALL_NOT_VERIFIED')
    matches = [r for r in journal['operations']
               if r.get('op',{}).get('resource') == 'application' and
               r['op'].get('brand') == brand and r['op'].get('channel') == channel]
    need(len(matches) == 1 and matches[0].get('state') == 'verified' and
         re.fullmatch(r'[a-f0-9]{64}',str(matches[0]['op'].get('want',''))),
         'ORIGINAL_APP_WRITE_OWNERSHIP_NOT_PROVEN_'+brand+'_'+channel)
    return matches[0]['op']['want']


def adaptive_repair_inventory(api, owners, config, original, done):
    need(isinstance(original, dict) and original.get('state') == 'verified',
         'ORIGINAL_SECURITY_INSTALL_NOT_VERIFIED')
    need(original.get('policyHashes') == {b:sha(config[b]) for b in DOMAINS},
         'ORIGINAL_POLICY_CHANGED_REFUSE_REPAIR')
    need(original.get('botState') == 'verified', 'ORIGINAL_BOT_STAGE_NOT_VERIFIED')
    if done is not None:
        need(done.get('state') == 'verified',
             'UNCERTAIN_OR_PARTIAL_ADAPTIVE_REPAIR_STOP')
    ops = []
    for brand in DOMAINS:
        props = gather_properties(api,brand,owners[brand])
        for key,want in spec_values(config[brand]).items():
            need(props[key]['value'] == want,
                 'SECURITY_GOVERNANCE_DRIFT_REFUSE_REPAIR_'+brand)
        for channel, app in read_apps(api,brand,owners[brand]).items():
            before = original_app_write(original, brand, channel)
            current = app['seq']
            script = script_for(brand,config[brand])
            after = {**current,'script':script}
            # Ownership comes from the existing journal AND the full live
            # auth-sequence hash, not from matching app names alone.
            need(basic_step(current) and totp_step(current) and
                 current.get('type') == 'USER_DEFINED',
                 'APP_SEQUENCE_CHANGED_REFUSE_REPAIR_'+brand+'_'+channel)
            current_hash = sha(current)
            desired_hash = sha(after)
            need(current_hash == before or
                 (done is not None and current_hash == desired_hash),
                 'APP_SCRIPT_DRIFT_REFUSE_REPAIR_'+brand+'_'+channel)
            need(sequence_kind(after,script) == 'desired',
                 'REPAIR_SCRIPT_SHAPE_INVALID')
            if done is not None:
                rec = [r for r in done['operations'] if
                       r.get('brand') == brand and r.get('channel') == channel]
                need(len(rec) == 1 and rec[0].get('state') == 'verified' and
                     rec[0].get('before') == before and
                     rec[0].get('after') == desired_hash and
                     current_hash == desired_hash,
                     'REPAIR_JOURNAL_OR_READBACK_DRIFT_'+brand+'_'+channel)
            else:
                need(current_hash == before and current_hash != desired_hash,
                     'UNOWNED_OR_NOOP_ADAPTIVE_REPAIR_REFUSED_'+brand+'_'+channel)
            ops.append({'resource':'application-script','brand':brand,
                        'channel':channel,'before':before,'after':desired_hash,
                        'etag':app['etag'] or ''})
    return ops


def adaptive_repair(mode, api, owners, config, credentials, original):
    done = repair_journal()
    ops = adaptive_repair_inventory(api, owners, config, original, done)
    need(recaptcha_inventory(credentials)['configured'], 'RECAPTCHA_STAGE_NOT_VERIFIED')
    public = {'schema':REPAIR_SCHEMA,'target':BASE,'image':'wso2/wso2is:7.3.0',
              'sourceInstallationSha256':sha(original),
              'operations':ops if done is None else [],
              'state':'PENDING' if done is None else 'VERIFIED'}
    public['planSha256']=sha(public)
    if mode == 'repair-plan':
        public['stage']='MAGALU_ADAPTIVE_RUNTIME_REPAIR_PLAN_READ_ONLY'
        return public
    if mode == 'repair-verify':
        need(done is not None and done.get('state') == 'verified',
             'NO_VERIFIED_ADAPTIVE_REPAIR_JOURNAL')
        out=verify_all(api,owners,config,original,credentials)
        return {'stage':'MAGALU_ADAPTIVE_RUNTIME_REPAIR',
                'status':'MANAGEMENT_READBACK_NOT_LIVE_LOGIN_TESTED',
                'applicationScripts':4,'nativeSecurity':out}
    if done is not None:
        need(done.get('state') == 'verified', 'UNCERTAIN_ADAPTIVE_REPAIR_REFUSE_REPLAY')
        return adaptive_repair('repair-verify',api,owners,config,credentials,original)
    need(os.environ.get('MAGALU_SECURITY_REPAIR_CONFIRM') == REPAIR_CONFIRM,
         'ADAPTIVE_REPAIR_EXPLICIT_CONFIRMATION_REQUIRED')
    need(os.environ.get('MAGALU_SECURITY_REPAIR_PLAN_SHA256') == public['planSha256'],
         'ADAPTIVE_REPAIR_PLAN_HASH_MISMATCH')
    # Verify every concurrency acknowledgement BEFORE first write.
    for op in ops:
        if not op['etag']:
            need(os.environ.get('MAGALU_SECURITY_ACK_NO_ETAG') ==
                 'ACK_NO_HTTP_ETAG_EXCLUSIVE_MAINTENANCE_WINDOW',
                 'ADAPTIVE_REPAIR_NO_ETAG_ACK_REQUIRED_BEFORE_WRITE')
    work = {'schema':REPAIR_SCHEMA,'state':'applying','sourcePlanSha256':public['planSha256'],
            'operations':[{**op,'state':'pending'} for op in ops]}
    atomic_json(REPAIR_JOURNAL,work)
    for i,op in enumerate(ops):
        entry=work['operations'][i]
        entry['state']='write-started';atomic_json(REPAIR_JOURNAL,work)
        try:
            brand=op['brand'];channel=op['channel']
            before=read_apps(api,brand,owners[brand])[channel]
            need(sha(before['seq']) == op['before'],
                 'REMOTE_SCRIPT_CHANGED_DURING_REPAIR')
            path=before['path']
            new_script=script_for(brand,config[brand])
            api.call(brand,owners[brand]['auth'],'PUT',
                     path+'/authenticationSequence/script',
                     {'script':new_script},before['etag'])
            after=read_apps(api,brand,owners[brand])[channel]
            need(sha(after['seq']) == op['after'] and
                 after['proto'] == before['proto'] and
                 app_unrelated(after['app']) == app_unrelated(before['app']) and
                 sequence_kind(after['seq'],new_script) == 'desired',
                 'ADAPTIVE_REPAIR_REMOTE_READBACK_MISMATCH')
        except Exception:
            entry['state']='uncertain';atomic_json(REPAIR_JOURNAL,work)
            raise Refused('ADAPTIVE_REPAIR_WRITE_UNCERTAIN_STOP_NO_RETRY') from None
        entry['state']='verified';atomic_json(REPAIR_JOURNAL,work)
    # If verification fails, do not mark journal verified.
    need(verify_all(api,owners,config,original,credentials)['status'] == 'MANAGEMENT_READBACK',
         'ADAPTIVE_REPAIR_FINAL_READBACK_FAILED')
    work['state']='verified';atomic_json(REPAIR_JOURNAL,work)
    return {'stage':'MAGALU_ADAPTIVE_RUNTIME_REPAIR','status':'MANAGEMENT_READBACK',
            'applicationScripts':4,'realLoginTests':'NOT_RUN'}

def run(mode):
    need(mode in ('plan','apply','verify','status','repair-plan','repair-apply','repair-verify','repair-status'), 'BAD_COMMAND')
    private_dir()
    if mode == 'repair-status':
        j=repair_journal()
        return {'stage':'MAGALU_ADAPTIVE_RUNTIME_REPAIR','state':j.get('state') if j else 'NOT_INSTALLED',
                'writeStates':[r.get('state') for r in j['operations']] if j else []}
    if mode == 'status':
        j=installed_journal()
        return {'stage':'MAGALU_NATIVE_V10','state':j.get('state') if j else 'NOT_INSTALLED',
                'writeStates':[x['state'] for x in j['operations']] if j else [],
                'liveReadback':'NOT_RUN'}
    config=policies()
    # A fresh-bootstrap may supply a pre-created private credential path outside
    # the repository, since CIAM_V10_HOME does not exist before prepare().
    repo=HERE.parents[2].resolve()
    need(not CREDS.resolve().is_relative_to(repo), 'RECAPTCHA_SECRETS_INSIDE_REPOSITORY_REFUSED')
    credentials=recaptcha.load_credentials(CREDS)
    owners=owner_context()
    runtime_guard()  # Read-only GA/version/volume check BEFORE any management API write.
    api=WSO2()
    if mode in ('repair-plan','repair-apply','repair-verify'):
        return adaptive_repair(mode,api,owners,config,credentials,installed_journal())
    bot = recaptcha_inventory(credentials)
    data=inventory(api,owners,config)
    plan=planned(data,config,bot)
    j=installed_journal()
    if mode == 'plan':
        plan['stage']='MAGALU_SECURITY_PLAN_READ_ONLY'
        plan['ownershipJournalState']=j.get('state') if j else 'NOT_PRESENT'
        return plan
    if mode == 'verify':
        return verify_all(api,owners,config,j,credentials)
    need(os.environ.get('MAGALU_SECURITY_CONFIRM') == CONFIRM, 'APPLY_CONFIRMATION_MISSING')
    # Repeat bootstrap is verify-only if this installer already owns the current state.
    if j is not None and j.get('state') == 'verified' and not plan['changes'] and bot['configured']:
        return verify_all(api,owners,config,j,credentials)
    need(os.environ.get('MAGALU_SECURITY_PLAN_SHA256') == plan['planSha256'],
         'PLAN_DIGEST_NOT_APPROVED_OR_REMOTE_DRIFT')
    # All required approvals must be checked BEFORE creating a journal,
    # staging reCAPTCHA, restarting WSO2, or issuing governance/API writes.
    preflight_write_authorizations(plan)
    # The no-op case must still be owned. Never silently adopt a preexisting setup.
    if j is None:
        need(all(v['kind'] != 'desired' for b in DOMAINS for v in data[b]['summary']['apps'].values()),
             'UNOWNED_ALREADY_CONFIGURED_SEQUENCE_REFUSED')
        # The P0.10 Aurora scripts are an exception only if its private journal proves ownership.
        if any(v['kind'] == 'legacy-aurora' for v in data['aurora']['summary']['apps'].values()):
            p010 = private_json(PRIVATE/'p010-aurora-mfa-policy.private.json')
            need(p010.get('schema') == 'ciam.p010.aurora.mfa.v1' and
                 all(p010.get('roles',{}).get(c,{}).get('state') == 'verified' for c in CHANNELS),
                 'LEGACY_AURORA_SEQUENCE_NOT_OWNED')
        need(all(not (v['before'] == v['want'] and v['before'] != 'false')
                 for b in DOMAINS for k,v in data[b]['summary']['policy'].items()
                 if k in ('account.lock.handler.lock.on.max.failed.attempts.enable','sso.login.recaptcha.enable')),
             'UNOWNED_POLICY_ALREADY_ENABLED')
        j={'schema':SCHEMA,'state':'applying','planSha256':plan['planSha256'],
           'policyHashes':{b:sha(config[b]) for b in DOMAINS},
           'botState':'pending','operations':[{'state':'pending','op':op} for op in plan['changes']]}
        atomic_json(JOURNAL,j)
    else:
        need(j.get('state') == 'verified' and j.get('planSha256') == plan['planSha256'] and
             all(x['state'] == 'verified' for x in j['operations']),
             'PRIOR_JOURNAL_NOT_SAFE_TO_REPLAY_OR_PLAN_CHANGED')
        return verify_all(api,owners,config,j,credentials)
    if not bot['configured']:
        j['botState']='write-started';atomic_json(JOURNAL,j)
        try:recaptcha_stage(credentials,bot,api,owners['aurora'])
        except Exception:
            j['botState']='uncertain';atomic_json(JOURNAL,j)
            raise Refused('RECAPTCHA_STAGE_UNCERTAIN_OPERATOR_REVIEW_REQUIRED') from None
        j['botState']='verified';atomic_json(JOURNAL,j)
    else:
        j['botState']='verified';atomic_json(JOURNAL,j)
    apply_changes(api,owners,config,plan['changes'],j)
    # Final readback first; never mark a partial or uncertain installation verified.
    verified = verify_all(api,owners,config,j,credentials, require_verified_state=False)
    j['state']='verified';atomic_json(JOURNAL,j)
    return verified

if __name__ == '__main__':
    lock_fd = None
    try:
        if len(sys.argv) != 2: raise Refused('USAGE_security_[plan|apply|verify|status|repair-plan|repair-apply|repair-verify|repair-status]')
        lock_fd = exclusive_lock()
        print(json.dumps(run(sys.argv[1]),indent=2,sort_keys=True))
    except (Refused,ValueError,KeyError,TypeError,OSError,ssl.SSLError,subprocess.TimeoutExpired) as ex:
        # Never emit sensitive exception bodies or HTTP responses.
        print('MAGALU_SECURITY_REFUSED: '+(str(ex) if isinstance(ex,Refused) else type(ex).__name__),file=sys.stderr)
        sys.exit(2)
    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
