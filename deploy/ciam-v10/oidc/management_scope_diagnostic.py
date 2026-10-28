#!/usr/bin/env python3
"""Read-only WSO2 v10 Aurora management-client OAuth scope diagnostic.

Accepts no command-line options, never performs management GET/PUT or edits files.
Uses the existing, SHA-pinned audience_plan.py exclusively for v10 safety and
private journal loading. Requests tenant-local management client-credentials
OAuth tokens; outputs ONLY known scope names / HTTP codes, never token data.
"""
import hashlib
import http.client
import importlib.util
import json
import pathlib
import ssl
import sys
import urllib.parse

DOMAIN = 'aurora.identity.test'
SERVER_HOST = 'localhost'
SERVER_PORT = 9444
SCOPES = (
    'internal_application_mgt_view',
    'internal_application_mgt_update',
    'internal_application_mgt_client_secret_view',
)
PLAN_SHA256 = '104702e05bd926d730227fdc0b2bfd432c640d3ef54cba7d0bc22741c3301a94'
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PLAN_PATH = SCRIPT_DIR / 'audience_plan.py'

class ProbeRefusal(Exception):
    pass


def load_plan():
    if not PLAN_PATH.is_file() or PLAN_PATH.is_symlink():
        raise ProbeRefusal('PINNED_AUDIENCE_PLAN_NOT_FOUND')
    if hashlib.sha256(PLAN_PATH.read_bytes()).hexdigest() != PLAN_SHA256:
        raise ProbeRefusal('AUDIENCE_PLAN_CHECKSUM_MISMATCH')
    spec = importlib.util.spec_from_file_location('ciam_v10_audience_plan_scope_probe', PLAN_PATH)
    if spec is None or spec.loader is None:
        raise ProbeRefusal('PLAN_IMPORT_UNAVAILABLE')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def classify_response(status, body, requested):
    """Never return any token, other claims, or untrusted remote error text."""
    if status != 200:
        return {'outcome': f'TOKEN_HTTP_{status}', 'granted': [],
                'missing': list(requested)}
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError, TypeError):
        return {'outcome': 'INVALID_TOKEN_RESPONSE', 'granted': [], 'missing': list(requested)}
    if (not isinstance(data, dict) or
        not isinstance(data.get('access_token'), str) or not data['access_token'] or
        str(data.get('token_type', '')).lower() != 'bearer' or
        not isinstance(data.get('scope'), str)):
        return {'outcome': 'TOKEN_RESPONSE_UNUSABLE', 'granted': [], 'missing': list(requested)}
    received = set(data['scope'].split())
    # Do not output any unexpected server-returned string.
    granted = [s for s in requested if s in received]
    missing = [s for s in requested if s not in received]
    return {'outcome': 'TOKEN_ISSUED', 'granted': granted, 'missing': missing}


def token_probe(ctx, management, basic, requested):
    if not requested or any(s not in SCOPES for s in requested):
        raise ProbeRefusal('UNEXPECTED_SCOPE_REQUEST')
    if not isinstance(management.get('clientId'), str) or not isinstance(management.get('clientSecret'), str):
        raise ProbeRefusal('MANAGEMENT_CREDENTIALS_UNAVAILABLE')
    auth = basic(management['clientId'], management['clientSecret'])
    form = urllib.parse.urlencode({'grant_type': 'client_credentials', 'scope': ' '.join(requested)})
    conn = http.client.HTTPSConnection(SERVER_HOST, SERVER_PORT, context=ctx, timeout=15)
    try:
        conn.request('POST', f'/t/{DOMAIN}/oauth2/token', body=form,
                     headers={'Authorization': auth,
                              'Accept': 'application/json',
                              'Content-Type': 'application/x-www-form-urlencoded'})
        res = conn.getresponse()
        data = res.read(65537)
        if len(data) > 65536:
            raise ProbeRefusal('TOKEN_RESPONSE_EXCEEDS_SIZE_LIMIT')
        return classify_response(res.status, data, requested)
    finally:
        conn.close()


def diagnostic(probe):
    """Call combined only when sufficient, then individual checks when blocked."""
    combined = probe(SCOPES)
    # If all three were granted, no additional token requests are needed.
    if combined['outcome'] == 'TOKEN_ISSUED' and not combined['missing']:
        return {'combined': combined, 'individual': {}, 'tokenRequests': 1,
                'reason': 'ALL_REQUIRED_SCOPES_GRANTED'}
    individual = {scope: probe((scope,)) for scope in SCOPES}
    return {'combined': combined, 'individual': individual, 'tokenRequests': 4,
            'reason': 'COMBINED_REQUEST_MISSING_OR_REJECTED_SCOPE'}


def main():
    if len(sys.argv) != 1:
        raise ProbeRefusal('NO_ARGUMENTS_PERMITTED')
    plan = load_plan()
    plan.ensure_repo()
    plan.ensure_target()
    resources = plan.load_module('ciam_v10_scope_diagnostic_resources', plan.RESOURCE_SOURCE)
    authority = plan.load_module('ciam_v10_scope_diagnostic_authority', plan.AUTH_SOURCE)
    _, rs, saved = authority.private_context()
    node = saved['tenants']['aurora']['clients']['web']
    if not (node.get('state') == 'verified' and node.get('domain') == DOMAIN and
            node.get('name') == 'Identity Lab v10 Aurora Web'):
        raise ProbeRefusal('AURORA_WEB_JOURNAL_IDENTITY_MISMATCH')
    management = rs['tenants']['aurora']['management']
    ctx = plan.https_client_context()
    result = diagnostic(lambda requested: token_probe(ctx, management, resources.basic, requested))
    # Differentiate missing combined scopes from individual unsupported ones.
    data = {'stage': 'CIAM_V10_AURORA_MANAGEMENT_SCOPE_DIAGNOSTIC',
            'status': 'VERIFIED_READBACK' if result['combined']['outcome'] == 'TOKEN_ISSUED' else 'NOT_VERIFIED',
            'reason': result['reason'],
            'tenant': DOMAIN, 'dockerTarget': 'VERIFIED_V10_9444_ONLY',
            'managementOAuthTokenRequests': result['tokenRequests'],
            'managementResourceWrites': 0, 'managementGetRequests': 0,
            'dockerOrConfigurationWrites': 0, 'browserLogins': 0,
            'appChanges': 0, 'freshTokenAcceptance': 'BLOCKED', 'consentV2': 'BLOCKED',
            'combinedRequest': result['combined'], 'individualRequests': result['individual'],
            'nextAction': ('RERUN_AUDIENCE_APPLY_PLAN_ONLY' if result['reason'] == 'ALL_REQUIRED_SCOPES_GRANTED'
                           else 'REVIEW_MISSING_SCOPES_AND_EXISTING_MANAGEMENT_APP_AUTHORIZATION_NO_AUTO_GRANT')}
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ProbeRefusal, OSError, ValueError, KeyError, TypeError, AttributeError,
            ssl.SSLError, http.client.HTTPException) as exc:
        name = str(exc) if isinstance(exc, ProbeRefusal) else type(exc).__name__
        print(json.dumps({'stage': 'CIAM_V10_AURORA_MANAGEMENT_SCOPE_DIAGNOSTIC',
                          'status': 'NOT_VERIFIED', 'reason': name,
                          'managementResourceWrites': 0, 'dockerOrConfigurationWrites': 0,
                          'nextAction': 'NO_APPLY'}))
        sys.exit(1)
