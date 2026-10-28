#!/usr/bin/env python3
"""WSO2 IS 7.3 CIAM v5: guarded audiences for Aurora App, Brisa Web, Brisa App.

Execute from the repository root:
  python3 /path/to/ciam-v5-three-client-audiences-bootstrap.py plan
  WSO2_CIAM_V5_AUDIENCES_CONFIRM=ADD_EXISTING_PROFILE_AND_BUSINESS_AUDIENCES python3 /path/to/ciam-v5-three-client-audiences-bootstrap.py run
  python3 /path/to/ciam-v5-three-client-audiences-bootstrap.py verify

Each client has a separate private before-image and journal entry. Never retry
an uncertain PUT. The existing HTTPS client source and application roles remain unchanged.
"""
import ast
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import runpy
import sys
import textwrap
import time
import types

ROOT = Path.cwd().resolve()
PROFILE = 'https://api.ciam-v10.test/profile'
BUSINESS = 'urn:ciampoc:service-requests:v1'
CONFIRM = 'ADD_EXISTING_PROFILE_AND_BUSINESS_AUDIENCES'
TARGETS = (('aurora', 'app'), ('brisa', 'web'), ('brisa', 'app'))
ALLOW_PUT_FIELDS = {
    'clientId', 'grantTypes', 'callbackURLs', 'allowedOrigins', 'publicClient',
    'pkce', 'accessToken', 'hybridFlow', 'refreshToken', 'subjectToken', 'idToken',
    'logout', 'validateRequestObjectSignature', 'scopeValidators',
    'clientAuthentication', 'requestObject', 'pushAuthorizationRequest',
    'subject', 'isFAPIApplication', 'cibaAuthenticationRequest'
}
SECRET_KEYS = {'clientSecret', 'clientSecretExpiresAt'}
SCHEMA = 'ciampoc.v5.three-client-oidc-audiences.v1'

class Stop(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Stop(code)


def digest(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def stable(x):
    require(isinstance(x, dict), 'OIDC_RESPONSE_NOT_OBJECT')
    return {k: v for k, v in x.items() if k not in SECRET_KEYS and k != 'state'}


def secret_sha(x):
    v = x.get('clientSecret')
    return hashlib.sha256(v.encode()).hexdigest() if isinstance(v, str) and v and set(v) != {'*'} else None


def audiences_equal(observed, expected):
    """Only a unique, exact string set qualifies; ordering is immaterial."""
    return (isinstance(observed, list) and isinstance(expected, list)
            and all(isinstance(s, str) for s in observed + expected)
            and len(observed) == len(expected)
            and len(observed) == len(set(observed))
            and len(expected) == len(set(expected))
            and set(observed) == set(expected))


def same_except_audience(original, actual, desired):
    require(isinstance(actual.get('idToken'), dict), 'OIDC_ID_TOKEN_SCHEMA_DRIFT')
    require(audiences_equal(actual['idToken'].get('audience'), desired),
            'OIDC_AUDIENCE_SET_DRIFT')
    expected = copy.deepcopy(original)
    expected['idToken']['audience'] = list(desired)
    normalized = copy.deepcopy(actual)
    normalized['idToken']['audience'] = list(desired)
    require(stable(normalized) == stable(expected), 'OIDC_REMOTE_CONFIGURATION_DRIFT')
    a, b = secret_sha(original), secret_sha(actual)
    require(not (a and b and a != b), 'OIDC_CLIENT_SECRET_CHANGED')
    require(bool(original.get('clientSecret')) == bool(actual.get('clientSecret')),
            'OIDC_SECRET_VISIBILITY_CHANGED')


def prepare_protocol(before, client_id):
    require(isinstance(before, dict) and before.get('clientId') == client_id, 'OIDC_CLIENT_ID_DRIFT')
    require(isinstance(before.get('accessToken'), dict) and before['accessToken'].get('type') == 'JWT',
            'ACCESS_TOKEN_NOT_JWT')
    require('authorization_code' in before.get('grantTypes', []), 'OIDC_AUTH_CODE_GRANT_MISSING')
    require(before.get('publicClient') is False, 'BFF_APP_UNEXPECTED_PUBLIC_CLIENT')
    require(isinstance(before.get('callbackURLs'), list) and bool(before['callbackURLs']),
            'OIDC_CALLBACKS_MISSING')
    token = before.get('idToken')
    require(isinstance(token, dict) and isinstance(token.get('audience'), list), 'OIDC_AUDIENCE_SCHEMA')
    audience = token['audience']
    require(all(isinstance(v, str) for v in audience) and len(audience) == len(set(audience)),
            'OIDC_EXISTING_AUDIENCE_INVALID')
    require(set(audience).issubset({PROFILE, BUSINESS}), 'OIDC_UNKNOWN_EXISTING_AUDIENCE_STOP')
    unknown = set(before) - ALLOW_PUT_FIELDS - SECRET_KEYS - {'state'}
    require(not unknown, 'OIDC_UNKNOWN_CONFIG_FIELDS_STOP')
    # Profile is authorized in the existing v10 foundation. Check that through
    # the management API before choosing this target, rather than assuming it.
    desired = [PROFILE, BUSINESS]
    payload = {k: copy.deepcopy(v) for k, v in before.items() if k in ALLOW_PUT_FIELDS}
    payload['idToken']['audience'] = desired
    return payload, desired


def atomic_json(path, value, exclusive=False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    if exclusive:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        target = path
    else:
        target = path.with_name('.' + path.name + '.' + str(os.getpid()) + '.tmp')
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        if not exclusive:
            os.replace(target, path)
    finally:
        if not exclusive and target.exists():
            target.unlink()


def load_json(path):
    require(path.is_file(), 'PRIVATE_STATE_FILE_MISSING')
    return json.loads(path.read_text())


def restricted_put(resources, exact_path):
    """One in-memory instance with PUT only for the exact already-verified OIDC endpoint.

    Original TLS pinning, path checks, authentication, encoding and response limits
    remain unchanged. This is the same strategy proven by v4.4 on Aurora Web.
    """
    require(re.fullmatch(
        r'/t/(?:aurora|brisa)\.identity\.test/api/server/v1/applications/[A-Za-z0-9-]{8,128}/inbound-protocols/oidc',
        exact_path) is not None, 'OIDC_WRITE_PATH_INVALID')
    obj = resources.HTTPS()
    func = type(obj).call
    require(inspect.isfunction(func) and func.__closure__ is None, 'HTTPS_METHOD_UNEXPECTED')
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    require(len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef), 'HTTPS_AST_UNEXPECTED')
    fn = tree.body[0]
    require(fn.name == 'call' and not fn.decorator_list, 'HTTPS_METHOD_DRIFT')
    require(not any(isinstance(n, (ast.Global, ast.Nonlocal, ast.Await)) for n in ast.walk(fn)),
            'HTTPS_METHOD_SIDE_EFFECT_UNEXPECTED')
    guard_candidates = []
    for ix, stmt in enumerate(fn.body):
        if isinstance(stmt, ast.If) and any(
            isinstance(n, ast.Constant) and n.value == 'UNSAFE_HTTP_REQUEST'
            for n in ast.walk(ast.Module(body=stmt.body, type_ignores=[]))
        ):
            guard_candidates.append((ix, stmt))
    require(len(guard_candidates) == 1, 'HTTPS_UNSAFE_GUARD_NOT_UNIQUE')
    index, guard = guard_candidates[0]
    require(not any(isinstance(n, ast.Call) for stmt in fn.body[:index] for n in ast.walk(stmt)),
            'HTTPS_GUARD_NOT_BEFORE_NETWORK')
    original = ast.unparse(guard.test)
    expected = ("method not in ('GET', 'POST') or not path.startswith('/') "
                "or path.startswith('//') or ('\\\\' in path) "
                "or ('..' in path) or ('#' in path)")
    require(original == expected, 'HTTPS_SAFETY_PREDICATES_CHANGED')
    tuples = []
    for n in ast.walk(guard.test):
        if (isinstance(n, ast.Compare) and isinstance(n.left, ast.Name)
            and n.left.id == 'method' and len(n.ops) == 1 and isinstance(n.ops[0], ast.NotIn)
            and len(n.comparators) == 1 and isinstance(n.comparators[0], ast.Tuple)
            and [v.value for v in n.comparators[0].elts if isinstance(v, ast.Constant)] == ['GET', 'POST']):
            tuples.append(n.comparators[0])
    require(len(tuples) == 1, 'HTTPS_METHOD_ALLOWLIST_CHANGED')
    tuples[0].elts.append(ast.Constant(value='PUT'))
    require(ast.unparse(guard.test).replace("('GET', 'POST', 'PUT')", "('GET', 'POST')") == original,
            'HTTPS_PATH_GUARD_CHANGED')
    ast.fix_missing_locations(tree)
    namespace = {}
    exec(compile(tree, '<ciam-v5-oidc-put-with-pinned-https>', 'exec'), func.__globals__, namespace)
    adapted = namespace['call']
    require(inspect.signature(adapted) == inspect.signature(func), 'HTTPS_METHOD_SIGNATURE_DRIFT')
    def only_put(method, path, **kwargs):
        require(method == 'PUT' and path == exact_path, 'OUT_OF_SCOPE_HTTP_WRITE_REFUSED')
        return types.MethodType(adapted, obj)(method, path, **kwargs)
    return only_put


def read_oidc(mod, resources, tenant_state, item):
    brand, channel, app = item
    path = (mod['api_base'](brand) + '/applications/' + app['id'] + '/inbound-protocols/oidc')
    cred = mod['auth'](tenant_state, brand)
    status, data = mod['call'](resources.HTTPS(), 'GET', path, cred)
    require(status == 200 and isinstance(data, dict), 'OIDC_GET_FAILED_' + brand + '_' + channel)
    return path, cred, data


def validate_api_links(mod, resources, tenant_state, item, spec):
    brand, channel, app = item
    cred = mod['auth'](tenant_state, brand)
    path = mod['api_base'](brand) + '/applications/' + app['id'] + '/authorized-apis'
    status, entries = mod['call'](resources.HTTPS(), 'GET', path, cred)
    require(status == 200 and isinstance(entries, list), 'AUTHORIZED_API_READ_FAILED_' + brand + '_' + channel)
    expected = {
        PROFILE: {'ciam:profile:read'},
        BUSINESS: {x['name'] for x in spec['businessApi']['scopes']}
    }
    for identifier, needed in expected.items():
        matching = [x for x in entries if isinstance(x, dict) and x.get('identifier') == identifier]
        require(len(matching) == 1, 'AUTHORIZED_API_NOT_UNIQUE_' + brand + '_' + channel)
        rec = matching[0]
        require(rec.get('policyId', rec.get('policyIdentifier')) == 'RBAC',
                'AUTHORIZED_API_NOT_RBAC_' + brand + '_' + channel)
        got = {s.get('name') for s in rec.get('authorizedScopes', []) if isinstance(s, dict)}
        if identifier == BUSINESS:
            require(got == needed, 'BUSINESS_SCOPES_DRIFT_' + brand + '_' + channel)
        else:
            require(needed.issubset(got), 'PROFILE_SCOPE_MISSING_' + brand + '_' + channel)


def init_context():
    path = ROOT / 'deploy/ciam-v10/phase4/business-bootstrap.py'
    server = ROOT / 'services/identity-bff/src/server.js'
    require(path.is_file() and server.is_file() and 'CIAM_V5_LIVE_LAB' in server.read_text(),
            'V5_REPO_AND_LAB_REQUIRED')
    mod = runpy.run_path(str(path))
    check = mod['execute']('verify')
    require(check.get('readback') == 'VERIFIED', 'BUSINESS_FOUNDATION_NOT_VERIFIED')
    spec, tenants, oidc, _ = mod['context']()
    resources = mod['resources']
    apps = []
    for b, c in TARGETS:
        app = oidc['tenants'][b]['clients'][c]
        require(app.get('state') == 'verified' and isinstance(app.get('id'), str),
                'OIDC_CLIENT_JOURNAL_NOT_VERIFIED_' + b + '_' + c)
        apps.append((b, c, app))
    return mod, resources, spec, tenants, oidc, apps


def paths(resources):
    private = resources.ROOT / 'private'
    return (private / 'bootstrap-v5-three-client-audiences.private.json',
            private / 'oidc-v5-before-audience')


def get_plan(mod, resources, spec, tenants, oidc, apps):
    journal, backups = paths(resources)
    states = load_json(journal) if journal.exists() else None
    if states is not None:
        require(states.get('schema') == SCHEMA and isinstance(states.get('clients'), dict),
                'AUDIENCE_JOURNAL_SCHEMA_UNEXPECTED')
    aura = ('aurora', 'web', oidc['tenants']['aurora']['clients']['web'])
    validate_api_links(mod, resources, tenants, aura, spec)
    _, _, aurora = read_oidc(mod, resources, tenants, aura)
    require((aurora.get('idToken') or {}).get('audience') == [PROFILE, BUSINESS],
            'AURORA_WEB_PROVEN_BASELINE_DRIFT')
    prepared = []
    for item in apps:
        b, c, app = item
        key = b + '-' + c
        validate_api_links(mod, resources, tenants, item, spec)
        path, credential, observed = read_oidc(mod, resources, tenants, item)
        payload, target = prepare_protocol(observed, app['clientId'])
        entry = (states or {}).get('clients', {}).get(key)
        if entry:
            require(entry.get('appId') == app['id'] and entry.get('state') in ('prepared', 'put-started', 'verified'),
                    'PRIVATE_JOURNAL_APP_OR_STATE_DRIFT_' + key)
            before = load_json(backups / (key + '.private.json'))
            require(entry.get('beforeSha256') == digest(before), 'PRIVATE_OIDC_BACKUP_INTEGRITY_' + key)
            expected_payload, desired = prepare_protocol(before, app['clientId'])
            require(entry.get('targetSha256') == digest(expected_payload), 'PRIVATE_OIDC_TARGET_INTEGRITY_' + key)
            if audiences_equal(observed['idToken']['audience'], target):
                same_except_audience(before, observed, desired)
            else:
                same_except_audience(before, observed, before['idToken']['audience'])
            prepared.append((item, path, credential, observed, before, expected_payload, desired, entry))
        else:
            require(observed['idToken']['audience'] != target, 'UNJOURNALED_ALREADY_CONFIGURED_' + key)
            prepared.append((item, path, credential, observed, observed, payload, target, None))
    return states, prepared


def execute(mode):
    require(mode in ('plan','run','verify'), 'USAGE_PLAN_RUN_VERIFY')
    mod, resources, spec, tenants, oidc, apps = init_context()
    states, prepared = get_plan(mod, resources, spec, tenants, oidc, apps)
    journal, backups = paths(resources)
    report = {'stage':'CIAM_V5_THREE_CLIENT_OIDC_AUDIENCES', 'mode':mode,
              'remoteWrites':0, 'auroraWeb':'UNCHANGED_ALREADY_VERIFIED', 'clients':{}}
    for (b,c,_), _,_,observed,_,_,target,entry in prepared:
        report['clients'][b+'-'+c] = {
            'oldOrCurrentAudiences': observed['idToken']['audience'],
            'targetAudiences': target,
            'businessAudienceConfigured': BUSINESS in observed['idToken']['audience'],
            'journalState': entry.get('state') if entry else 'absent'
        }
    if mode == 'plan':
        return report
    if mode == 'verify':
        require(states is not None, 'AUDIENCE_JOURNAL_ABSENT')
        for (b,c,_), _,_,observed,_,_,target,entry in prepared:
            require(entry is not None and entry.get('state') == 'verified'
                    and audiences_equal(observed['idToken']['audience'], target),
                    'AUDIENCE_NOT_VERIFIED_' + b + '_' + c)
        report['readback']='VERIFIED'
        report['positiveTokenEvidence']='FRESH_BROWSER_LOGINS_REQUIRED'
        return report
    require(os.environ.get('WSO2_CIAM_V5_AUDIENCES_CONFIRM') == CONFIRM,
            'EXPLICIT_V5_AUDIENCE_CHANGE_CONFIRMATION_REQUIRED')
    if states is None:
        # Preflight above read every client before preparing any writes.
        for (b,c,_), _,_,observed,_,_,target,_ in prepared:
            key=b+'-'+c
            require(not (backups/(key+'.private.json')).exists(),
                    'UNJOURNALED_PRIVATE_BACKUP_EXISTS_'+key)
        for (b,c,_), _,_,observed,_,_,_,_ in prepared:
            atomic_json(backups/(b+'-'+c+'.private.json'), observed, exclusive=True)
        states={'schema':SCHEMA, 'clients':{}}
        for (b,c,app), _,_,observed,_,payload,_,_ in prepared:
            states['clients'][b+'-'+c]={'state':'prepared','appId':app['id'],
                'beforeSha256':digest(observed), 'targetSha256':digest(payload)}
        atomic_json(journal, states, exclusive=True)
    sent = 0
    for item, path, cred, observed, _, _, target, _ in prepared:
        b,c,app=item; key=b+'-'+c
        entry=states['clients'][key]
        baseline=load_json(backups/(key+'.private.json'))
        payload, _ = prepare_protocol(baseline, app['clientId'])
        if audiences_equal(observed['idToken']['audience'], target):
            same_except_audience(baseline, observed, target)
            if entry['state'] == 'put-started':
                _, _, reread = read_oidc(mod, resources, tenants, item)
                same_except_audience(baseline, reread, target)
                require(stable(reread) == stable(observed),
                        'UNCERTAIN_PUT_READBACK_UNSTABLE_' + key)
            entry['state']='verified'
            atomic_json(journal, states)
            continue
        require(entry['state']=='prepared', 'UNCERTAIN_PREVIOUS_PUT_NO_RETRY_'+key)
        same_except_audience(baseline, observed, baseline['idToken']['audience'])
        # Recheck immediately before a remote write. Refuse if another actor modified it.
        _, _, fresh = read_oidc(mod, resources, tenants, item)
        same_except_audience(baseline, fresh, baseline['idToken']['audience'])
        put = restricted_put(resources, path)
        entry['state']='put-started'
        atomic_json(journal, states)
        sent += 1
        status=None; failure=None
        try:
            status, _, _ = put('PUT',path,auth=cred,data=payload)
        except Exception as e:
            failure=type(e).__name__
        try:
            _, _, after=read_oidc(mod, resources, tenants, item)
            _, _, after2=read_oidc(mod, resources, tenants, item)
        except Exception:
            raise Stop('POST_PUT_READBACK_UNAVAILABLE_NO_RETRY_'+key)
        if (audiences_equal(after['idToken']['audience'], target)
                and audiences_equal(after2['idToken']['audience'], target)):
            same_except_audience(baseline, after, target)
            same_except_audience(baseline, after2, target)
            entry['state']='verified'
            atomic_json(journal, states)
        else:
            same_except_audience(baseline, after, baseline['idToken']['audience'])
            same_except_audience(baseline, after2, baseline['idToken']['audience'])
            raise Stop('OIDC_PUT_NOT_PERSISTED_NO_RETRY_'+key+'_HTTP_'+str(status)+'_'+str(failure))
    # Read all four again using the separate audit tool.
    from subprocess import run
    p=ROOT/'scripts/ciam-v5-four-client-readback.py'
    if p.is_file():
        proc=run([sys.executable,str(p)],cwd=ROOT,capture_output=True,text=True)
        require(proc.returncode==0,'FOUR_CLIENT_READBACK_SCRIPT_FAILED')
        audit=json.loads(proc.stdout)
        require(all(row.get('businessAudienceConfigured') and row.get('profileAudienceConfigured')
                    for row in audit['clients'].values()), 'FOUR_CLIENT_AUDIENCE_READBACK_NOT_COMPLETE')
    report['remoteWrites']=sent
    report['readback']='VERIFIED'
    report['positiveTokenEvidence']='FRESH_BROWSER_LOGINS_REQUIRED'
    return report


if __name__ == '__main__':
    try:
        require(len(sys.argv)==2, 'USAGE_plan_run_verify')
        print(json.dumps(execute(sys.argv[1]), indent=2))
    except Stop as e:
        print('REFUSED: '+str(e), file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        # No response bodies, tokens, or secrets in diagnostic output.
        print('REFUSED: UNEXPECTED_'+type(e).__name__+'_NO_BLIND_RETRY',file=sys.stderr)
        sys.exit(2)
