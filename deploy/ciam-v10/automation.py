#!/usr/bin/env python3
"""Validated, explicitly authorized, source-controlled CIAM v10 bootstrap stages.

No local or synthetic IAM state. No remote replay after ambiguous WSO2 writes.
The authority bootstrap owns its own write-ahead journal and locking.
"""
import json
import socket
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROLE_ENV = 'WSO2_CIAM_V10_ROLE_API'
V2_ENV = 'WSO2_CIAM_V10_ROLE_V2_CONFIRM'
V2_APPROVAL = 'USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES'
AUTH_ENV = 'WSO2_CIAM_V10_AUTHORITY_CONFIRM'
AUTH_APPROVAL = 'AUTHORIZE_EXISTING_V10_OIDC_AND_ASSIGN_SCIM_USERS'
DEPLOY_ENV = 'WSO2_CIAM_V10_DEPLOY_CONFIRM'
DEPLOY_APPROVAL = 'BOOTSTRAP_RECORDED_LAB_RESOURCES'
FRESH_ENV = 'WSO2_CIAM_V10_FRESH_CONFIRM'
FRESH_APPROVAL = 'CREATE_NEW_ISOLATED_PERSISTENT_LAB'
BRANDS = ('aurora', 'brisa')
CHANNELS = ('web', 'app')

class Refuse(Exception):
    pass


def verify_intent(env, *, fresh=False):
    """Validate every user choice before any provisioning stage or Docker action."""
    if env.get(DEPLOY_ENV) != DEPLOY_APPROVAL:
        raise Refuse('EXPLICIT_BOOTSTRAP_CONFIRMATION_REQUIRED')
    if fresh and env.get(FRESH_ENV) != FRESH_APPROVAL:
        raise Refuse('EXPLICIT_FRESH_CONFIRMATION_REQUIRED')
    version = env.get(ROLE_ENV)
    if version not in ('v2', 'v3'):
        raise Refuse('SELECT_ROLE_API_EXPLICITLY_V2_OR_V3_NO_FALLBACK')
    if version == 'v2' and env.get(V2_ENV) != V2_APPROVAL:
        raise Refuse('EXPLICIT_DEPRECATED_ROLES_V2_SELECTION_REQUIRED')
    return version


def _json_command(script, command, *, cwd, env, executor=subprocess.run):
    """Machine-validate the stage; do not print authentication data or raw errors."""
    result = executor([sys.executable, str(script), command], cwd=str(cwd),
                      env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Refuse('STAGE_'+command.upper().replace('-', '_')+
                     '_FAILED_INSPECT_PRIVATE_JOURNAL_NO_BLIND_RETRY')
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise Refuse('STAGE_'+command.upper().replace('-', '_')+'_NOT_JSON') from None
    if not isinstance(data, dict):
        raise Refuse('STAGE_RESULT_NOT_OBJECT')
    return data


def verify_plan(result, role_api):
    if (result.get('stage') != 'CIAM_V10_AUTHORITY' or
        result.get('mode') != 'GET_ONLY' or result.get('remoteWrites') != 0 or
        result.get('roleApiVersion') != role_api or result.get('safeToApply') is not True):
        raise Refuse('AUTHORIZATION_PLAN_UNSAFE_NO_WRITES')
    tenants = result.get('tenants')
    if not isinstance(tenants, dict) or set(tenants) != set(BRANDS):
        raise Refuse('AUTHORIZATION_PLAN_TENANT_SET_DRIFT')
    for brand in BRANDS:
        row = tenants[brand]
        if not isinstance(row, dict) or set(row.get('channels', {})) != set(CHANNELS):
            raise Refuse('AUTHORIZATION_PLAN_CHANNEL_SET_DRIFT_'+brand)


def verify_apply(result, role_api):
    if (result.get('stage') != 'CIAM_V10_AUTHORITY' or result.get('mode') != 'APPLY' or
        result.get('roleApiVersion') != role_api or
        result.get('status') != 'PROVISIONING_READBACK_VERIFIED_BROWSER_NOT_TESTED'):
        raise Refuse('AUTHORIZATION_APPLY_NOT_VERIFIED_NO_BLIND_RETRY')
    if set(result.get('tenants', {})) != set(BRANDS):
        raise Refuse('AUTHORIZATION_APPLY_TENANT_DRIFT')
    for brand in BRANDS:
        row = result['tenants'][brand]
        if set(row) != set(CHANNELS):
            raise Refuse('AUTHORIZATION_APPLY_CHANNEL_DRIFT_'+brand)
        for channel in CHANNELS:
            value = row[channel]
            if (value.get('authorizedScope') != 'READBACK_VERIFIED' or
                value.get('roleAndUser') != 'READBACK_VERIFIED'):
                raise Refuse('AUTHORIZATION_APPLY_INCOMPLETE_'+brand+'_'+channel)


def verify_reconcile(result, role_api):
    if (result.get('stage') != 'CIAM_V10_AUTHORITY' or
        result.get('mode') != 'READ_ONLY_RECONCILIATION' or
        result.get('remoteWrites') != 0 or result.get('roleApiVersion') != role_api or
        result.get('safeToApply') is not True):
        raise Refuse('AUTHORIZATION_RECONCILIATION_UNVERIFIED')
    tenants = result.get('tenants', {})
    if set(tenants) != set(BRANDS):
        raise Refuse('AUTHORIZATION_RECONCILIATION_TENANT_DRIFT')
    for brand in BRANDS:
        row = tenants[brand]
        if row.get('businessAPI') != 'PRESENT_SCOPE_VERIFIED' or set(row.get('channels', {})) != set(CHANNELS):
            raise Refuse('AUTHORIZATION_RECONCILIATION_RESOURCE_DRIFT_'+brand)
        for channel in CHANNELS:
            entry = row['channels'][channel]
            if entry.get('apiAuthorization') != 'SCOPE_VERIFIED' or entry.get('role') != 'PRESENT':
                raise Refuse('AUTHORIZATION_RECONCILIATION_CHANNEL_DRIFT_'+brand+'_'+channel)


def verify_status(result, role_api):
    if (result.get('stage') != 'CIAM_V10_AUTHORITY_STATUS' or
        result.get('remoteWrites') != 0 or result.get('roleApiVersion') != role_api or
        result.get('acceptance') != 'API_ROLES_AND_ASSIGNMENTS_READBACK_VERIFIED_BROWSERS_NOT_TESTED'):
        raise Refuse('AUTHORITY_JOURNAL_ACCEPTANCE_UNVERIFIED')
    if set(result.get('tenants', {})) != set(BRANDS):
        raise Refuse('AUTHORITY_JOURNAL_TENANTS_DRIFT')
    for brand in BRANDS:
        row = result['tenants'][brand]
        if (row.get('resource') != 'verified' or
            row.get('authorizedChannels') != {c: 'verified' for c in CHANNELS} or
            row.get('roleChannels') != {c: 'verified' for c in CHANNELS}):
            raise Refuse('AUTHORITY_JOURNAL_READBACK_UNVERIFIED_'+brand)


def authorization_pipeline(authority, root, env, *, executor=subprocess.run):
    """Read-only preflight -> one authorized apply -> authoritative readback.

    Existing authority script implements per-write journal/readback and refusal
    to repeat interrupted or ambiguous network writes. Never retry a failed step.
    """
    role_api = verify_intent(env)
    plan = _json_command(authority, 'authorization-plan', cwd=root, env=env, executor=executor)
    verify_plan(plan, role_api)
    authorized_env = dict(env)
    authorized_env[AUTH_ENV] = AUTH_APPROVAL  # Covered by explicit complete-bootstrap consent
    applied = _json_command(authority, 'authorization-apply', cwd=root, env=authorized_env, executor=executor)
    verify_apply(applied, role_api)
    reconciled = _json_command(authority, 'authorization-reconcile', cwd=root, env=env, executor=executor)
    verify_reconcile(reconciled, role_api)
    status = _json_command(authority, 'authority-status', cwd=root, env=env, executor=executor)
    verify_status(status, role_api)
    return {'stage':'CIAM_V10_AUTHORIZATION_BOOTSTRAP', 'status':'READBACK_VERIFIED',
            'roleApiVersion':role_api, 'tenants':list(BRANDS),
            'browserAuthentication':'NOT_VERIFIED', 'revocation':'NOT_VERIFIED_LIVE'}


def verify_anonymous_acceptance(result):
    if (result.get('stage') != 'CIAM_V10_ANONYMOUS_NEGATIVE_ACCEPTANCE' or
        result.get('status') != 'NEGATIVE_HTTP_GATES_PASSED' or
        result.get('remoteWrites') != 0 or result.get('credentialsUsed') is not False or
        result.get('runtimeEvidence') != 'LIVE_INTROSPECTION_PER_REQUEST'):
        raise Refuse('BFF_NEGATIVE_RUNTIME_ACCEPTANCE_FAILED')
    expected = {'anonymousIdentity':200, 'auroraWebWithoutSession':401,
                'auroraAppWithoutSession':401, 'brisaWebWithoutSession':401,
                'brisaAppWithoutSession':401, 'syntheticConsentDisabled':503,
                'syntheticScenarioDisabled':503, 'syntheticRetailDisabled':503}
    data = result.get('results', {})
    if set(data) != set(expected):
        raise Refuse('BFF_NEGATIVE_RUNTIME_GATE_SET_DRIFT')
    for gate, code in expected.items():
        if not isinstance(data[gate], dict) or data[gate].get('http') != code or data[gate].get('pass') is not True:
            raise Refuse('BFF_NEGATIVE_RUNTIME_GATE_FAILED_'+gate)


def consent_capability(authority, root, env, *, executor=subprocess.run):
    """Explicitly report blocked v2 consent; never silently provision substitute consent."""
    report = _json_command(authority, 'consent-plan', cwd=root, env=env, executor=executor)
    if report.get('remoteWrites') != 0:
        raise Refuse('CONSENT_PLAN_MUST_NOT_WRITE')
    if report.get('status') == 'BLOCKED' and report.get('noLocalConsentFallback') is True:
        return 'BLOCKED_WSO2_V2_UPDATE_AND_API_CONTRACT'
    # Even when future consent-plan is available, this bootstrap cannot invent
    # consent write confirmation/consent grants. Keep it distinct and fail closed.
    return 'NOT_PROVISIONED_REQUIRES_VERIFIED_CONSENT_LIFECYCLE'


def fresh_destination_preflight(root, *, executor=subprocess.run, port_probe=None):
    """Refuse to adopt existing state before running `fresh` in a new lab.

    Only a truly empty runtime may be initialized. Unlike a source checkout,
    existing Docker state can outlive a runtime home and must not be adopted.
    """
    root = Path(root).expanduser()
    if root.exists() or root.is_symlink():
        raise Refuse('FRESH_RUNTIME_ALREADY_EXISTS_NO_REINITIALIZATION')
    if port_probe is None:
        def port_probe(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                return sock.connect_ex(('127.0.0.1', port)) == 0
    for port in (9444, 4400):
        if port_probe(port):
            raise Refuse('FRESH_PORT_'+str(port)+'_ALREADY_IN_USE')
    commands = (
        (['docker','ps','-a','--filter','label=com.docker.compose.project=wso2-ciam-v10',
          '--format','{{.ID}}'], 'FRESH_V10_COMPOSE_CONTAINERS_EXIST'),
        (['docker','volume','ls','--filter','name=wso2-ciam-v10_',
          '--format','{{.Name}}'], 'FRESH_V10_DOCKER_VOLUMES_EXIST'),
    )
    for cmd, reason in commands:
        try:
            result=executor(cmd, capture_output=True, text=True, check=False, timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            raise Refuse('FRESH_DOCKER_STATE_NOT_VERIFIABLE') from None
        if result.returncode != 0:
            raise Refuse('FRESH_DOCKER_STATE_NOT_VERIFIABLE')
        names=[x.strip() for x in result.stdout.splitlines() if x.strip()]
        if reason=='FRESH_V10_DOCKER_VOLUMES_EXIST':
            names=[x for x in names if x.startswith('wso2-ciam-v10_')]
        if names:
            raise Refuse(reason)


def wait_for_https(host='localhost', port=9444, *, attempts=100, pause=3,
                   probe=None, sleep=time.sleep):
    """Unauthenticated GET readiness check, not authentication or API authorization."""
    if probe is None:
        def probe():
            # This is an unauthenticated local readiness probe only. Use the
            # local certificate as trust anchor; later authenticated stages
            # verify WSO2 identity and tenant-specific credentials separately.
            try:
                certificate = ssl.get_server_certificate((host, port), timeout=4)
                context = ssl.create_default_context(cadata=certificate)
                context.check_hostname = False  # Local self-signed WSO2 cert
                req = urllib.request.Request(
                    'https://localhost:9444/api/server/v1/tenants?limit=1',method='GET')
                try:
                    with urllib.request.urlopen(req, timeout=4, context=context) as r:
                        return r.status in (200,401,403)
                except urllib.error.HTTPError as e:
                    return e.code in (200,401,403)
            except (OSError, ssl.SSLError, TimeoutError):
                return False
    if host != 'localhost' or port != 9444:
        raise Refuse('READY_CHECK_ONLY_LOCAL_WSO2_V10_9444')
    for attempt in range(attempts):
        if probe(): return
        if attempt + 1 != attempts: sleep(pause)
    raise Refuse('WSO2_9444_NOT_READY_NO_MANAGEMENT_WRITES')


def negative_runtime_acceptance(script, root, env, *, executor=subprocess.run):
    result = executor([sys.executable, str(script)], cwd=str(root), env=env,
                      capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Refuse('BFF_RUNTIME_ACCEPTANCE_FAILED')
    try:
        obj = json.loads(result.stdout)
    except (TypeError, ValueError):
        raise Refuse('BFF_RUNTIME_ACCEPTANCE_NOT_JSON') from None
    verify_anonymous_acceptance(obj)
    return {'status':'NEGATIVE_HTTP_GATES_PASSED',
            'positiveAuthorization':'NOT_VERIFIED_LIVE',
            'fourBrowserLogins':'NOT_VERIFIED_LIVE'}
