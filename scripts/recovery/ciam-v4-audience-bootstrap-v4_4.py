#!/usr/bin/env python3
"""Guarded WSO2 IS 7.3 Aurora Web HTTPS transport remediation, v4.4.

Usage (from repository root):
  python3 /path/to/ciam-v4-audience-bootstrap.py plan
  python3 /path/to/ciam-v4-audience-bootstrap.py run
  python3 /path/to/ciam-v4-audience-bootstrap.py verify

No tenant resets, role or API resource creation, token inspection, fake claims or manual Console edits.
"""
import ast
import copy
import inspect
import hashlib
import json
import re
import os
from pathlib import Path
import runpy
import signal
import textwrap
import types
import subprocess
import sys
import time
from urllib import error, request

REPO = Path.cwd().resolve()
BUSINESS_BOOTSTRAP = REPO / 'deploy/ciam-v10/phase4/business-bootstrap.py'
SERVER = REPO / 'services/identity-bff/src/server.js'
AUTHORITY = REPO / 'services/identity-bff/src/wso2-authority.js'
PROFILE = 'https://api.ciam-v10.test/profile'
BUSINESS = 'urn:ciampoc:service-requests:v1'
BRAND = 'aurora'
CHANNEL = 'web'

OLD_SCOPE = """        scope: process.env.WSO2_CASES_SCOPES_ENABLED === '1' && process.env.WSO2_CASES_API_AUDIENCE ? 
          `${c.scope} ciam:cases:create ciam:cases:read ciam:cases:review ciam:cases:approve` : c.scope"""
NEW_SCOPE = """        // Temporary Aurora Web only: isolate the service-request API audience.
        scope: process.env.WSO2_AURORA_CASES_ONLY_DIAG === '1' && key === 'aurora-web'
          ? 'openid ciam:cases:read'
          : (process.env.WSO2_CASES_SCOPES_ENABLED === '1' && process.env.WSO2_CASES_API_AUDIENCE
              ? `${c.scope} ciam:cases:create ciam:cases:read ciam:cases:review ciam:cases:approve`
              : c.scope)"""

# Conservative allowlist: WSO2 application-management OIDC GET fields that are also
# documented as PUT fields. Never submit read-only metadata or secret rotation fields.
OIDC_PUT_FIELDS = {
    'clientId', 'grantTypes', 'callbackURLs', 'allowedOrigins', 'publicClient',
    'pkce', 'accessToken', 'hybridFlow', 'refreshToken', 'subjectToken', 'idToken',
    'logout', 'validateRequestObjectSignature', 'scopeValidators',
    'clientAuthentication', 'requestObject', 'pushAuthorizationRequest',
    'subject', 'isFAPIApplication', 'cibaAuthenticationRequest'
}
SECRET_KEYS = {'clientSecret', 'clientSecretExpiresAt'}

class Stop(Exception):
    pass


PHASE = 'initialization'


def phase(name):
    global PHASE
    PHASE = name


def safe_refuse_code(exc):
    """Expose only a machine-readable refusal code, never private response text."""
    code = str(exc).strip()
    if re.fullmatch(r'[A-Z][A-Z0-9_]{0,159}', code):
        return code
    # Existing business bootstrap can attach a REST URL to a GET_FAILED code.
    # Emit its prefix but never credentials, query strings or the response body.
    if code.startswith('GET_FAILED_'):
        head = code.split('/', 1)[0].rstrip('_')
        if re.fullmatch(r'[A-Z][A-Z0-9_]{0,159}', head):
            return head + '_PATH_REDACTED'
    return 'DETAILS_REDACTED'


def refusal_message(exc):
    """Classify external bootstrap refusals without printing private payloads."""
    if type(exc).__name__ == 'Refuse':
        return 'WSO2_' + PHASE + '_' + safe_refuse_code(exc) + '_STOP_NO_RETRY'
    return 'UNEXPECTED_' + type(exc).__name__ + '_AT_' + PHASE + '_STOP_NO_RETRY'


def journal_state_hint():
    # Read only a fixed, local, protected journal path; never display its content.
    path = Path.home() / 'wso2-ciam-v10/private/aurora-web-audience-recovery-v4.private.json'
    if not path.exists():
        return 'ABSENT'
    try:
        state = json.loads(path.read_text()).get('state')
        if state in ('put-started', 'recovery-started', 'verified'):
            return state.upper().replace('-', '_')
        return 'UNRECOGNIZED'
    except (OSError, ValueError, TypeError):
        return 'UNREADABLE'


def require(condition, message):
    if not condition:
        raise Stop(message)


def secure_write_exclusive(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def sha256(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare_oidc_payload(original, app_client_id):
    require(isinstance(original, dict), 'OIDC_GET_SCHEMA')
    require(original.get('clientId') == app_client_id, 'CLIENT_ID_MISMATCH')
    require(original.get('accessToken', {}).get('type') == 'JWT', 'ACCESS_TOKEN_NOT_JWT')
    require(isinstance(original.get('grantTypes'), list) and
            'authorization_code' in original['grantTypes'], 'GRANT_TYPES_UNEXPECTED')
    require(isinstance(original.get('idToken'), dict), 'ID_TOKEN_SCHEMA')
    aud = original['idToken'].get('audience')
    require(isinstance(aud, list) and all(isinstance(x, str) for x in aud),
            'OIDC_AUDIENCE_SCHEMA')
    require(len(aud) == len(set(aud)), 'DUPLICATE_EXISTING_AUDIENCE')
    require(set(aud) in ({PROFILE}, {PROFILE, BUSINESS}),
            'AUDIENCE_BASELINE_DRIFT_STOP')
    require(isinstance(original.get('callbackURLs'), list) and original['callbackURLs'],
            'CALLBACK_URLS_MISSING')
    require(original.get('publicClient') is False, 'AURORA_WEB_UNEXPECTED_PUBLIC_CLIENT')
    unknown = set(original) - OIDC_PUT_FIELDS - SECRET_KEYS - {'state'}
    require(not unknown, 'UNKNOWN_OIDC_FIELDS_STOP_' + ','.join(sorted(unknown)))
    # Do not PUT clientSecret even if the read API provides it: that field is
    # optional, and sending it might accidentally rotate credentials. After PUT,
    # verify secrets and every other returned stable setting did not drift.
    payload = {k: copy.deepcopy(v) for k, v in original.items() if k in OIDC_PUT_FIELDS}
    payload['idToken']['audience'] = [PROFILE, BUSINESS]
    return payload, BUSINESS in aud


def normalized_config(cfg):
    # Compare every non-secret field, including any fields WSO2 adds after update.
    return {k: v for k, v in cfg.items() if k not in SECRET_KEYS and k != 'state'}


def secret_fingerprint(cfg):
    value = cfg.get('clientSecret')
    if not isinstance(value, str) or not value or set(value) == {'*'}:
        return None
    return hashlib.sha256(value.encode()).hexdigest()


def check_remote_after(before, after, expected_payload):
    require(isinstance(after, dict), 'POST_UPDATE_GET_INVALID')
    expected = copy.deepcopy(before)
    expected['idToken']['audience'] = expected_payload['idToken']['audience']
    require(normalized_config(after) == normalized_config(expected),
            'POST_UPDATE_OIDC_CONFIG_DRIFT_STOP_NO_AUTOMATIC_RETRY')
    old_fpr, new_fpr = secret_fingerprint(before), secret_fingerprint(after)
    if old_fpr and new_fpr:
        require(old_fpr == new_fpr, 'CLIENT_SECRET_CHANGED_STOP')
    elif bool(before.get('clientSecret')) != bool(after.get('clientSecret')):
        raise Stop('CLIENT_SECRET_VISIBILITY_CHANGED_STOP')


def check_remote_unchanged(baseline, observed):
    """Fail closed unless the original OIDC configuration is still effective."""
    require(isinstance(observed, dict), 'RECOVERY_REMOTE_NOT_OBJECT')
    require(normalized_config(observed) == normalized_config(baseline),
            'RECOVERY_REMOTE_NOT_BASELINE_STOP')
    before_secret, after_secret = secret_fingerprint(baseline), secret_fingerprint(observed)
    if before_secret and after_secret:
        require(before_secret == after_secret, 'RECOVERY_CLIENT_SECRET_CHANGED_STOP')
    elif bool(baseline.get('clientSecret')) != bool(observed.get('clientSecret')):
        raise Stop('RECOVERY_SECRET_VISIBILITY_DRIFT_STOP')


def build_temporary_put_transport(resources, exact_path):
    """Extend a *single client instance* to support one exact HTTPS OIDC PUT.

    Only the original method guard's allowed verbs change, using a verified AST
    transformation. The existing pinned TLS, authentication, request encoding,
    response handling, and all path-safety checks remain the original code.
    The globally shared HTTPS class and its source file are never patched.
    """
    require(re.fullmatch(
        r'/t/aurora\.identity\.test/api/server/v1/applications/[A-Za-z0-9-]{8,128}/inbound-protocols/oidc',
        exact_path) is not None, 'PUT_PATH_NOT_EXACT_AURORA_OIDC')
    obj = resources.HTTPS()
    method_func = type(obj).call
    require(inspect.isfunction(method_func) and method_func.__closure__ is None,
            'HTTPS_CLIENT_METHOD_UNEXPECTED')
    try:
        source = textwrap.dedent(inspect.getsource(method_func))
        tree = ast.parse(source)
    except (OSError, TypeError, SyntaxError, ValueError):
        raise Stop('HTTPS_CLIENT_SOURCE_UNAVAILABLE')
    require(len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef),
            'HTTPS_CLIENT_SOURCE_UNEXPECTED')
    method_tree = tree.body[0]
    require(method_tree.name == 'call' and not method_tree.decorator_list,
            'HTTPS_CLIENT_DECORATOR_OR_NAME_UNEXPECTED')
    require(not any(isinstance(x, (ast.Nonlocal, ast.Global, ast.Await))
                    for x in ast.walk(method_tree)), 'HTTPS_CLIENT_CONTROL_UNEXPECTED')

    candidates = []
    for i, stmt in enumerate(method_tree.body):
        if not isinstance(stmt, ast.If):
            continue
        if not any(isinstance(n, ast.Constant) and n.value == 'UNSAFE_HTTP_REQUEST'
                   for n in ast.walk(ast.Module(body=stmt.body, type_ignores=[]))):
            continue
        candidates.append((i, stmt))
    require(len(candidates) == 1, 'HTTPS_CLIENT_UNSAFE_GUARD_UNRECOGNIZED')
    idx, guard = candidates[0]
    # Prove the guard is evaluated before any network-initiating function call.
    require(not any(isinstance(n, ast.Call)
                    for stmt in method_tree.body[:idx] for n in ast.walk(stmt)),
            'HTTPS_CLIENT_GUARD_NOT_FIRST_SIDE_EFFECT')

    # The original condition must retain all path safety predicates verbatim.
    original_test = ast.unparse(guard.test)
    exact_guard = (
        "method not in ('GET', 'POST') or not path.startswith('/') "
        "or path.startswith('//') or ('\\\\' in path) "
        "or ('..' in path) or ('#' in path)"
    )
    require(original_test == exact_guard,
            'HTTPS_CLIENT_METHOD_OR_PATH_GUARD_CHANGED')
    target_nodes = []
    for cmp in ast.walk(guard.test):
        if (isinstance(cmp, ast.Compare) and isinstance(cmp.left, ast.Name)
            and cmp.left.id == 'method' and len(cmp.ops) == 1
            and isinstance(cmp.ops[0], ast.NotIn) and len(cmp.comparators) == 1
            and isinstance(cmp.comparators[0], (ast.Tuple, ast.List))
            and [x.value for x in cmp.comparators[0].elts if isinstance(x, ast.Constant)]
                == ['GET', 'POST'] and len(cmp.comparators[0].elts) == 2):
            target_nodes.append(cmp.comparators[0])
    require(len(target_nodes) == 1, 'HTTPS_CLIENT_METHOD_ALLOWLIST_UNEXPECTED')
    target_nodes[0].elts.append(ast.Constant(value='PUT'))
    # Fail if the original path guards were not preserved as an unchanged suffix.
    updated_test = ast.unparse(guard.test)
    require(updated_test.replace("('GET', 'POST', 'PUT')", "('GET', 'POST')")
            == original_test, 'HTTPS_CLIENT_PATH_GUARD_CHANGED')

    ast.fix_missing_locations(tree)
    namespace = {}
    exec(compile(tree, '<restricted_https_put_in_memory>', 'exec'),
         method_func.__globals__, namespace)
    adapted = namespace['call']
    require(inspect.signature(adapted) == inspect.signature(method_func),
            'HTTPS_CLIENT_SIGNATURE_DRIFT')

    def restricted_call(method, path, **kwargs):
        require(method == 'PUT' and path == exact_path,
                'HTTPS_CLIENT_PUT_ONLY_EXACT_PATH')
        return types.MethodType(adapted, obj)(method, path, **kwargs)

    return restricted_call


def protected_oidc_put(mod, resources, path, credential, payload):
    # Preserve the existing helper's pinned certificate and request behavior.
    write = build_temporary_put_transport(resources, path)
    status, body, _headers = write('PUT', path, auth=credential, data=payload)
    return status, body


def guarded_put_with_reconciliation(mod, resources, tenants, app, path, credential,
                                    original_saved, payload, journal_path, record,
                                    attempt_kind):
    """One recorded PUT only; reconcile even if HTTP call raises or returns an error.

    No automatic repeat once this helper starts. A later run may reconcile a
    successful write through exact readback, but must not send another PUT.
    """
    require(attempt_kind in ('initial', 'recovery', 'transport-remediation'), 'INVALID_ATTEMPT_KIND')
    # Validate the one-off transport before recording a new write attempt.
    if attempt_kind == 'transport-remediation':
        build_temporary_put_transport(resources, path)
    record['state'] = {'initial':'put-started', 'recovery':'recovery-started',
                       'transport-remediation':'transport-remediation-started'}[attempt_kind]
    record['attempts'] = {'initial':1, 'recovery':2, 'transport-remediation':3}[attempt_kind]
    record['lastAttempt'] = attempt_kind
    write_state(journal_path, record)

    phase('OIDC_' + attempt_kind.upper().replace('-', '_') + '_PUT')
    status = None
    failure = None
    try:
        status, _ = protected_oidc_put(mod, resources, path, credential, payload)
    except Exception as exc:
        # WSO2's resources.Refuse can include internal HTTP details; sanitize.
        failure = ('WSO2_' + safe_refuse_code(exc)) if type(exc).__name__ == 'Refuse' \
            else 'TRANSPORT_' + type(exc).__name__

    phase('OIDC_' + attempt_kind.upper().replace('-', '_') + '_POST_WRITE_READBACK')
    try:
        _, _, observed = remote_get(mod, resources, tenants, app)
    except Exception:
        raise Stop('OIDC_POST_WRITE_READBACK_UNAVAILABLE_NO_RETRY')

    # A completed write is accepted only if every stable OIDC setting, client
    # secret fingerprint where visible, and expected audience match exactly.
    if isinstance(observed, dict) and BUSINESS in observed.get('idToken', {}).get('audience', []):
        check_remote_after(original_saved, observed, payload)
        # Confirm the target remains stable across a second independent GET.
        try:
            time.sleep(.2)
            _, _, second = remote_get(mod, resources, tenants, app)
        except Exception:
            raise Stop('OIDC_TARGET_SECOND_READBACK_UNAVAILABLE_NO_RETRY')
        check_remote_after(original_saved, second, payload)
        require(normalized_config(second) == normalized_config(observed),
                'OIDC_TARGET_READBACKS_DISAGREE_NO_RETRY')
        record['state'] = 'verified'
        record['lastResult'] = 'TARGET_READBACK_VERIFIED'
        write_state(journal_path, record)
        return 'verified'

    # Failure path is no longer ambiguous if remote still equals original;
    # never auto-retry this attempt or weaken JWT audience enforcement.
    check_remote_unchanged(original_saved, observed)
    if failure:
        raise Stop('OIDC_' + attempt_kind.upper().replace('-', '_') + '_PUT_' + failure + '_REMOTE_BASELINE_NO_RETRY')
    if status not in (200, 201, 204):
        raise Stop('OIDC_' + attempt_kind.upper().replace('-', '_') + '_PUT_HTTP_' + str(status) + '_REMOTE_BASELINE_NO_RETRY')
    raise Stop('OIDC_' + attempt_kind.upper().replace('-', '_') + '_PUT_2XX_NOT_PERSISTED_NO_RETRY')


def local_restore_plan():
    require(SERVER.exists() and AUTHORITY.exists(), 'BFF_SOURCE_MISSING')
    source = SERVER.read_text()
    backup_file = SERVER.with_name('server.js.pre-aurora-scope-diagnostic.bak')
    if source.count('WSO2_AURORA_CASES_ONLY_DIAG') == 0:
        require(source.count(OLD_SCOPE) == 1, 'NORMAL_SCOPE_CODE_UNRECOGNIZED')
        server_action = 'already-normal'
        server_original = source
    else:
        require(backup_file.exists(), 'SCOPE_BACKUP_MISSING')
        server_original = backup_file.read_text()
        require(server_original.count(OLD_SCOPE) == 1 and
                source == server_original.replace(OLD_SCOPE, NEW_SCOPE),
                'SCOPE_DIAGNOSTIC_SOURCE_DRIFT')
        server_action = 'restore-normal-scope'

    authority_source = AUTHORITY.read_text()
    authority_backup = AUTHORITY.with_name('wso2-authority.js.pre-audience-diag.bak')
    if 'WSO2_BUSINESS_AUDIENCE_REJECTED' not in authority_source:
        authority_action = 'already-normal'
        authority_original = authority_source
    else:
        require(authority_backup.exists(), 'AUTHORITY_DIAG_BACKUP_MISSING')
        authority_original = authority_backup.read_text()
        anchor = '  if (audience !== null && ('
        suffix_anchor = '  return { active: true, scopes, exp: data.exp };'
        require(authority_source.count(anchor) == 1 and authority_original.count(anchor) == 1,
                'AUTHORITY_DIAG_ANCHOR_DRIFT')
        require(authority_source.count(suffix_anchor) == 1 and
                authority_original.count(suffix_anchor) == 1,
                'AUTHORITY_DIAG_SUFFIX_DRIFT')
        src_prefix, src_mid = authority_source.split(anchor, 1)
        old_prefix, old_mid = authority_original.split(anchor, 1)
        src_tail = src_mid.split(suffix_anchor, 1)[1]
        old_tail = old_mid.split(suffix_anchor, 1)[1]
        require(src_prefix == old_prefix and src_tail == old_tail and
                'WSO2_BUSINESS_AUDIENCE_REJECTED' in src_mid and
                'jwtAudienceDiagnostic' in src_mid,
                'AUTHORITY_DIAG_OUTSIDE_EXPECTED_REGION')
        authority_action = 'restore-original-authority'

    return {
        'server': (server_action, server_original),
        'authority': (authority_action, authority_original)
    }


def load_context():
    phase('FOUNDATION_VERIFY')
    require(BUSINESS_BOOTSTRAP.is_file(), 'RUN_FROM_EXISTING_REPOSITORY_ROOT')
    mod = runpy.run_path(str(BUSINESS_BOOTSTRAP))
    check = mod['execute']('verify')
    require(isinstance(check, dict) and check.get('readback') == 'VERIFIED',
            'BUSINESS_FOUNDATION_NOT_VERIFIED')
    phase('FOUNDATION_CONTEXT')
    resources = mod['resources']
    _, tenants, oidc, _ = mod['context']()
    app = oidc['tenants'][BRAND]['clients'][CHANNEL]
    require(app['state'] == 'verified', 'AURORA_WEB_NOT_VERIFIED')
    require(isinstance(app.get('clientId'), str) and app['clientId'], 'MISSING_CLIENT_ID')
    return mod, resources, tenants, app


def remote_get(mod, resources, tenants, app):
    app_id = app['id']
    path = (mod['api_base'](BRAND) + '/applications/' + app_id +
            '/inbound-protocols/oidc')
    credential = mod['auth'](tenants, BRAND)
    status, response = mod['call'](resources.HTTPS(), 'GET', path, credential)
    require(status == 200 and isinstance(response, dict), 'OIDC_GET_FAILED_' + str(status))
    return path, credential, response


def write_state(path, record):
    # Atomic save via existing v10 resource helper, same as business journal.
    # Do not print or expose the private OIDC backup.
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.parent / ('.' + path.name + '.' + str(os.getpid()) + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(record, f, sort_keys=True, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def verified_business_api(mod, resources, tenants, app):
    credential = mod['auth'](tenants, BRAND)
    appid = app['id']
    path = mod['api_base'](BRAND) + '/applications/' + appid + '/authorized-apis'
    code, records = mod['call'](resources.HTTPS(), 'GET', path, credential)
    require(code == 200 and isinstance(records, list), 'BUSINESS_API_AUTH_READ_FAILED')
    matching = [x for x in records if isinstance(x, dict) and x.get('identifier') == BUSINESS]
    require(len(matching) == 1, 'BUSINESS_AUTHORIZATION_NOT_UNIQUE')
    node = matching[0]
    require(node.get('policyId', node.get('policyIdentifier')) == 'RBAC',
            'BUSINESS_AUTH_POLICY_NOT_RBAC')
    scopes = {x.get('name') for x in node.get('authorizedScopes', []) if isinstance(x, dict)}
    require({'ciam:cases:read', 'ciam:cases:create'}.issubset(scopes),
            'BUSINESS_SCOPES_NOT_AUTHORIZED')


def safe_local_restore(plan):
    for filepath, key in ((SERVER, 'server'), (AUTHORITY, 'authority')):
        action, original = plan[key]
        if action.startswith('restore-'):
            filepath.write_text(original)
            filepath.chmod(0o600)
    # Fail if syntax is broken; no server restart in that case.
    for filepath in (SERVER, AUTHORITY):
        cmd = subprocess.run(['node', '--check', str(filepath)], capture_output=True, text=True)
        require(cmd.returncode == 0, 'NODE_SYNTAX_CHECK_FAILED_' + filepath.name)


def exec_cmd(argv, env=None):
    result = subprocess.run(argv, cwd=REPO, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        raise Stop('COMMAND_FAILED_' + argv[-1] + '_RC_' + str(result.returncode) + '\n' +
                   (result.stdout + result.stderr)[-1600:])
    return result.stdout


def port_pids():
    proc = subprocess.run(['lsof', '-nP', '-tiTCP:4400', '-sTCP:LISTEN'],
                          capture_output=True, text=True)
    require(proc.returncode in (0, 1), 'LSOF_UNAVAILABLE')
    return {int(x) for x in proc.stdout.splitlines() if x.isdigit()}


def restart_bff(resources):
    # Refuse to signal processes not positively identified as our BFF.
    pids = port_pids()
    require(len(pids) <= 1, 'MULTIPLE_LISTENERS_REFUSED')
    if pids:
        pid = next(iter(pids))
        desc = exec_cmd(['ps', '-p', str(pid), '-o', 'command=']).strip()
        require('node' in desc and 'services/identity-bff/src/server.js' in desc,
                'UNEXPECTED_PROCESS_PORT_4400')
        os.kill(pid, signal.SIGTERM)
        for _ in range(40):
            if not port_pids():
                break
            time.sleep(0.25)
        require(not port_pids(), 'BFF_STOP_TIMEOUT')

    env = dict(os.environ)
    env.pop('WSO2_AURORA_CASES_ONLY_DIAG', None)
    env.pop('WSO2_AUDIENCE_DIAG_FILE', None)
    env['WSO2_CASES_API_AUDIENCE'] = BUSINESS
    env['WSO2_CASES_SCOPES_ENABLED'] = '1'
    data_dir = resources.ROOT / 'private/business-cases-v4'
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    data_dir.chmod(0o700)
    env['CIAM_BUSINESS_DATA_DIR'] = str(data_dir)
    script = str(REPO / 'scripts/ciam-v10.sh')
    diagnose_output = exec_cmd([script, 'bff-diagnose'], env=env)
    try:
        diagnosis = json.loads(diagnose_output)
    except json.JSONDecodeError:
        raise Stop('BFF_DIAGNOSE_OUTPUT_UNEXPECTED')
    require(diagnosis.get('port4400Listening') is False, 'BFF_PORT_NOT_FREE')
    if diagnosis.get('pidState') == 'STALE':
        env['WSO2_CIAM_V10_STALE_PID_CONFIRM'] = 'CLEAR_DEAD_PID_ONLY'
        exec_cmd([script, 'bff-clear-stale'], env=env)
        env.pop('WSO2_CIAM_V10_STALE_PID_CONFIRM', None)
    elif diagnosis.get('pidState') not in ('ABSENT', 'NONE', 'MISSING'):
        raise Stop('BFF_PID_STATE_NOT_SAFE_TO_START_' + str(diagnosis.get('pidState')))

    exec_cmd([script, 'bff-start'], env=env)
    ready = False
    for _ in range(25):
        try:
            diag = json.loads(exec_cmd([script, 'bff-diagnose'], env=env))
        except (Stop, json.JSONDecodeError):
            diag = {}
        if diag.get('stage') in ('BFF_READY', 'CIAM_V10_BFF_DIAGNOSE_READ_ONLY') and \
           diag.get('port4400Listening') is True and \
           diag.get('sessionProbe', {}).get('http') == 200:
            ready = True
            break
        time.sleep(.2)
    require(ready, 'BFF_NOT_READY_AFTER_RESTART')

    statuses = {}
    for name, uri, expected in (
        ('auroraPortal', 'http://127.0.0.1:4400/portal/aurora', 200),
        ('brisaPortal', 'http://127.0.0.1:4400/portal/brisa', 200),
        ('anonymousAuroraCases', 'http://127.0.0.1:4400/api/brands/aurora/cases?client=aurora-web', 401),
        ('anonymousAuroraProfile', 'http://127.0.0.1:4400/api/protected/profile?client=aurora-web', 401),
    ):
        try:
            with request.urlopen(uri, timeout=6) as response:
                status = response.status
        except error.HTTPError as exc:
            status = exc.code
        statuses[name] = status
        require(status == expected, 'HTTP_NEGATIVE_OR_PORTAL_GATE_FAILED_' + name)
    return statuses


def execute(mode):
    require(mode in ('plan', 'run', 'verify'), 'USAGE: plan|run|verify')
    mod, resources, tenants, app = load_context()
    phase('AURORA_AUTHORIZED_API_READBACK')
    verified_business_api(mod, resources, tenants, app)
    phase('LOCAL_DIAGNOSTIC_RESTORE_PREFLIGHT')
    local_plan = local_restore_plan()
    phase('OIDC_GET_BASELINE')
    path, credential, original = remote_get(mod, resources, tenants, app)
    phase('OIDC_PAYLOAD_VALIDATION')
    target, is_target = prepare_oidc_payload(original, app['clientId'])
    journal = resources.ROOT / 'private/aurora-web-audience-recovery-v4.private.json'
    backup = resources.ROOT / 'private/aurora-web-oidc-before-audience-v4.private.json'
    phase('RECOVERY_JOURNAL_PREFLIGHT')
    current = json.loads(journal.read_text()) if journal.exists() else None
    recoverable_baseline = False
    original_saved = None
    expected_saved = None
    if current:
        require(current.get('schema') == 'ciampoc.v4.audience-recovery.v1' and
                current.get('appId') == app['id'] and
                current.get('businessAudience') == BUSINESS and backup.is_file(),
                'RECOVERY_JOURNAL_INVALID')
        original_saved = json.loads(backup.read_text())
        require(sha256(original_saved) == current['originalSha256'], 'OIDC_BACKUP_INTEGRITY_FAILED')
        expected_saved, _ = prepare_oidc_payload(original_saved, app['clientId'])
        if is_target:
            check_remote_after(original_saved, original, expected_saved)
        else:
            check_remote_unchanged(original_saved, original)
            # Two independent GETs, both equal to the persisted original, before
            # accepting a bounded recovery of the previous uncertain PUT.
            phase('RECOVERY_SECOND_BASELINE_READBACK')
            time.sleep(.5)
            _, _, repeated = remote_get(mod, resources, tenants, app)
            check_remote_unchanged(original_saved, repeated)
            recoverable_baseline = (current.get('state') == 'recovery-started' and
                                    current.get('attempts') == 2 and
                                    current.get('lastAttempt') == 'recovery' and
                                    current.get('lastResult') is None)
            require(recoverable_baseline,
                    'AUDIENCE_TRANSPORT_REMEDIATION_NOT_ELIGIBLE_NO_PUT')
            phase('RECOVERY_JOURNAL_PREFLIGHT')
    elif is_target:
        raise Stop('UNJOURNALED_BUSINESS_AUDIENCE_STOP')

    info = {
        'stage': 'CIAM_V4_AURORA_WEB_AUDIENCE', 'mode': mode,
        'businessApiAuthorization': 'RBAC_VERIFIED',
        'oidcClient': 'aurora-web',
        'accessTokenType': 'JWT',
        'profileAudiencePreserved': PROFILE in original['idToken']['audience'],
        'businessAudienceConfigured': is_target,
        'normalLoginScopes': local_plan['server'][0],
        'authorityDiagnostics': local_plan['authority'][0],
        'remoteWrites': 0,
        'recoveryEligibleByReadback': recoverable_baseline,
        'recoveryJournalState': current.get('state') if current else 'absent',
    }
    if mode == 'plan':
        return info
    if mode == 'verify':
        require(is_target and current is not None and current.get('state') == 'verified',
                'AUDIENCE_NOT_COMPLETELY_VERIFIED')
        return {**info, 'readback': 'VERIFIED',
                'runtimeTokenAudience': 'NOT_TESTED_NEW_LOGIN_REQUIRED'}

    remote_writes = 0
    if not current:
        raise Stop('TRANSPORT_REMEDIATION_REQUIRES_EXISTING_JOURNAL')
    elif is_target:
        # Recover from a previously successful PUT, including a lost response.
        require(current.get('state') in ('verified', 'put-started', 'recovery-started',
                                         'transport-remediation-started'),
                'AUDIENCE_JOURNAL_BAD_STATE')
        current['state'] = 'verified'
        current['lastResult'] = 'TARGET_READBACK_VERIFIED'
        write_state(journal, current)
    else:
        require(recoverable_baseline, 'AUDIENCE_TRANSPORT_REMEDIATION_NOT_SAFE')
        # Explicitly bounded: the prior attempt must be journaled, remote must
        # still be identical to the saved baseline, and recovery can run ONCE.
        guarded_put_with_reconciliation(mod, resources, tenants, app, path,
                                        credential, original_saved, expected_saved,
                                        journal, current, 'transport-remediation')
        remote_writes = 1

    phase('BFF_LOCAL_SOURCE_RESTORE')
    safe_local_restore(local_plan)
    phase('BFF_RESTART_AND_NEGATIVE_GATES')
    statuses = restart_bff(resources)
    return {
        **info,
        'businessAudienceConfigured': True,
        'remoteWrites': 'ONE_BOUNDED_TRANSPORT_REMEDIATION_PUT' if remote_writes else 0,
        'readback': 'VERIFIED',
        'bff': 'RESTARTED',
        'anonymousRuntimeChecks': statuses,
        'positiveUserTokenAudience': 'NOT_VERIFIED_NEW_LOGIN_REQUIRED',
    }


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise Stop('Usage: python3 ciam-v4-audience-bootstrap.py plan|run|verify')
        print(json.dumps(execute(sys.argv[1]), indent=2))
    except (Stop, KeyError, ValueError, TypeError, AssertionError, FileNotFoundError) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        # Don't expose raw WSO2 HTTP bodies, secrets, or session data.
        print('REFUSED: ' + refusal_message(exc), file=sys.stderr)
        print('AURORA_AUDIENCE_RECOVERY_JOURNAL: ' + journal_state_hint(),
              file=sys.stderr)
        sys.exit(2)
