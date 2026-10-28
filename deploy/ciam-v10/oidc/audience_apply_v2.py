#!/usr/bin/env python3
"""Guarded, single-application v10 Aurora Web audience update v2.

Default is plan (remote reads only). Apply is an explicit, one-shot transaction:
preflight -> two access-level readbacks -> 0600 immutable backup -> write-ahead
journal -> one PUT -> strict readback. No automatic retry or rollback.

Do not run apply until its specific dry-run output and scope access are reviewed.
No changes to Docker, the original :9443, other applications, private OIDC
journals, client secrets, or WSO2 user/role/scope data are permitted.
"""
import argparse
import copy
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import re
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.parse

EXPECTED_APP_SHA = 'cfe9d0b5e3f69e85a0470826e76010f2f504ed66a79dcb6fc0481264d41732e7'
EXPECTED_OIDC_SHA = '71c84fa9138ab5fee976e46ba785dad5c8b4ab9dc3f8bee0ede2fc87e3394c53'
EXPECTED_PLAN_SOURCE_SHA = '104702e05bd926d730227fdc0b2bfd432c640d3ef54cba7d0bc22741c3301a94'
APPROVE = 'I_AUTHORIZE_V10_AURORA_WEB_AUDIENCE_ONLY'
DOMAIN = 'aurora.identity.test'
AUDIENCE = 'https://api.ciam-v10.test/profile'
# OIDC REST API update request members documented by WSO2. Unknown fields
# deliberately block applying: never silently strip a new security setting.
UPDATE_MEMBERS = frozenset({
    'clientId', 'clientSecret', 'grantTypes', 'callbackURLs', 'allowedOrigins',
    'publicClient', 'pkce', 'accessToken', 'hybridFlow', 'refreshToken', 'subjectToken',
    'idToken', 'logout', 'validateRequestObjectSignature', 'scopeValidators',
    'clientAuthentication', 'requestObject', 'pushAuthorizationRequest',
    'subject', 'isFAPIApplication',
})
# Metadata included in OIDC GET, but not used as mutable update members.
# The exact secret expiry must be proven non-expiring before omission from PUT.
READ_ONLY_MEMBERS = frozenset({'clientSecretExpiresAt', 'multipleClientSecretsConfigured', 'state'})
SCOPES = ('internal_application_mgt_view', 'internal_application_mgt_update',
          'internal_application_mgt_client_secret_view')
BASE_DIR = Path(__file__).resolve().parent
PUT_STARTED = False
PLAN_SOURCE = BASE_DIR / 'audience_plan.py'

class Refuse(Exception):
    pass

def require(condition, code):
    if not condition:
        raise Refuse(code)

def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':')).encode('utf-8')

def sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def load_plan():
    require(PLAN_SOURCE.is_file() and not PLAN_SOURCE.is_symlink(), 'PINNED_PLAN_SCRIPT_MISSING')
    require(hashlib.sha256(PLAN_SOURCE.read_bytes()).hexdigest() == EXPECTED_PLAN_SOURCE_SHA,
            'PLAN_SCRIPT_CHECKSUM_CHANGED_REFUSE')
    spec = importlib.util.spec_from_file_location('ciam_v10_audience_plan_pinned', PLAN_SOURCE)
    require(spec is not None and spec.loader is not None, 'PINNED_PLAN_MODULE_UNAVAILABLE')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def safe_private_dir(root):
    """Use only existing owner-controlled v10 private directory; create new 0700 subdir."""
    private = root / 'private'
    require(not private.is_symlink() and private.is_dir(), 'PRIVATE_DIRECTORY_MISSING_OR_SYMLINK')
    st = private.stat()
    require(st.st_uid == os.getuid() and not stat.S_IMODE(st.st_mode) & 0o077,
            'PRIVATE_DIRECTORY_NOT_OWNER_ONLY')
    target = private / 'audience-aurora-web-v1'
    if target.is_symlink():
        raise Refuse('AUDIENCE_PRIVATE_DIRECTORY_SYMLINK')
    if not target.exists():
        target.mkdir(mode=0o700)
    st = target.stat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
            stat.S_IMODE(st.st_mode) == 0o700, 'AUDIENCE_PRIVATE_DIRECTORY_UNSAFE')
    return target

def read_private_json(path):
    require(not path.is_symlink() and path.is_file(), 'PRIVATE_BACKUP_MISSING_OR_SYMLINK')
    st = path.stat()
    require(st.st_uid == os.getuid() and stat.S_ISREG(st.st_mode) and
            stat.S_IMODE(st.st_mode) == 0o600, 'PRIVATE_FILE_MODE_UNSAFE')
    require(st.st_size <= 1000000, 'PRIVATE_FILE_TOO_LARGE')
    with path.open('rb') as fh:
        return json.loads(fh.read())

def exclusive_json(path, obj):
    """Never replace a backup. fsync file and directory before PUT."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(canonical(obj) + b'\n')
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        # Preserve the partial file to block any retries; operators reconcile.
        raise
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

def atomic_journal(path, data):
    """Journal update allowed only for an existing safe 0600 journal."""
    read_private_json(path)
    fd, tmp = tempfile.mkstemp(prefix='.audience-journal-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(canonical(data) + b'\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def without_secret(value):
    require(isinstance(value, dict), 'OIDC_GET_NOT_OBJECT')
    clone = copy.deepcopy(value)
    clone.pop('clientSecret', None)
    clone.pop('clientSecretExpiresAt', None)
    return clone

def validate_secret(oidc, journal_node):
    secret = oidc.get('clientSecret')
    expected = journal_node.get('clientSecret')
    require(isinstance(secret, str) and isinstance(expected, str) and
            len(secret) >= 12 and len(expected) >= 12 and
            not set(secret) == {'*'} and 'REDACTED' not in secret.upper(),
            'OIDC_CLIENT_SECRET_UNAVAILABLE_OR_MASKED')
    require(hmac.compare_digest(secret, expected), 'OIDC_CLIENT_SECRET_JOURNAL_MISMATCH')

def prepare_payload(privileged_oidc, journal_node):
    require(isinstance(privileged_oidc, dict), 'OIDC_GET_NOT_OBJECT')
    unknown = set(privileged_oidc) - UPDATE_MEMBERS - READ_ONLY_MEMBERS
    require(not unknown, 'OIDC_UNDOCUMENTED_GET_FIELDS_REFUSE')
    # API GET includes metadata that does not belong in an OIDC PUT. Refuse
    # states in which dropping that metadata could change secret lifecycle or
    # operate on a revoked/inactive/multi-secret application.
    if 'state' in privileged_oidc:
        require(privileged_oidc['state'] == 'ACTIVE', 'OIDC_CLIENT_STATE_NOT_ACTIVE')
    if 'multipleClientSecretsConfigured' in privileged_oidc:
        require(privileged_oidc['multipleClientSecretsConfigured'] is False,
                'MULTIPLE_CLIENT_SECRETS_REQUIRE_SEPARATE_REVIEW')
    if 'clientSecretExpiresAt' in privileged_oidc:
        require(type(privileged_oidc['clientSecretExpiresAt']) is int and
                privileged_oidc['clientSecretExpiresAt'] == 0,
                'EXPIRING_CLIENT_SECRET_REQUIRES_SEPARATE_REVIEW')
    if 'hybridFlow' in privileged_oidc:
        hybrid = privileged_oidc['hybridFlow']
        require(isinstance(hybrid, dict) and
                not (set(hybrid) - {'enable', 'responseType'}),
                'HYBRID_FLOW_STRUCTURE_UNEXPECTED')
        require(('enable' not in hybrid or type(hybrid['enable']) is bool) and
                ('responseType' not in hybrid or isinstance(hybrid['responseType'], str)),
                'HYBRID_FLOW_STRUCTURE_UNEXPECTED')
    require('clientSecret' in privileged_oidc, 'CLIENT_SECRET_VIEW_SCOPE_INEFFECTIVE')
    validate_secret(privileged_oidc, journal_node)
    require(privileged_oidc.get('clientId') == journal_node.get('clientId'),
            'CLIENT_ID_JOURNAL_MISMATCH')
    require(isinstance(privileged_oidc.get('grantTypes'), list) and
            'authorization_code' in privileged_oidc['grantTypes'], 'GRANT_TYPES_UNSAFE')
    require(privileged_oidc.get('callbackURLs') == [journal_node.get('callback')],
            'CALLBACK_CHANGED')
    require(privileged_oidc.get('publicClient') is False, 'NOT_CONFIDENTIAL_CLIENT')
    tok = privileged_oidc.get('idToken')
    require(isinstance(tok, dict) and tok.get('audience') == [],
            'OIDC_CUSTOM_AUDIENCE_ALREADY_CHANGED')
    require(privileged_oidc.get('pkce', {}).get('mandatory') is True and
            privileged_oidc.get('accessToken', {}).get('type') == 'JWT',
            'OIDC_SECURITY_SETTINGS_CHANGED')
    candidate = {key: copy.deepcopy(val) for key, val in privileged_oidc.items()
                 if key in UPDATE_MEMBERS}
    candidate['idToken']['audience'] = [AUDIENCE]
    # Compare only updateable members here; preserve GET-only metadata separately
    # through strict before/after management GET readback.
    comparable_before = without_secret(privileged_oidc)
    for readonly in READ_ONLY_MEMBERS:
        comparable_before.pop(readonly, None)
    require(is_only_audience_delta(comparable_before, without_secret(candidate)),
            'DIFF_NOT_LIMITED_TO_AUDIENCE')
    require(all(key in candidate for key in ('clientId', 'clientSecret', 'grantTypes')),
            'PUT_REQUIRED_MEMBERS_MISSING')
    return candidate

def is_only_audience_delta(before, after):
    a = copy.deepcopy(before)
    b = copy.deepcopy(after)
    if not isinstance(a.get('idToken'), dict) or not isinstance(b.get('idToken'), dict):
        return False
    if a['idToken'].get('audience') != [] or b['idToken'].get('audience') != [AUDIENCE]:
        return False
    a['idToken']['audience'] = [AUDIENCE]
    return a == b

def verify_after(before_app, before_view_oidc, app_after, view_after, privileged_after,
                 journal_node):
    # Strict: if WSO2 updates application metadata, mark as not yet verified.
    require(app_after == before_app, 'APPLICATION_GET_CHANGED_REQUIRES_REVIEW')
    require(is_only_audience_delta(without_secret(before_view_oidc),
                                   without_secret(view_after)),
            'OIDC_READBACK_CHANGED_OTHER_FIELDS')
    require(is_only_audience_delta(without_secret(before_view_oidc),
                                   without_secret(privileged_after)),
            'PRIVILEGED_OIDC_READBACK_DRIFT')
    validate_secret(privileged_after, journal_node)
    # clientSecretExpiresAt is intentionally omitted from update payload and
    # from ordinary comparison because view and secret-view responses can
    # differ. It MUST still be non-expiring after the write when returned.
    if 'clientSecretExpiresAt' in privileged_after:
        require(type(privileged_after['clientSecretExpiresAt']) is int and
                privileged_after['clientSecretExpiresAt'] == 0,
                'CLIENT_SECRET_EXPIRY_CHANGED_AFTER_PUT')
    for meta, allowed in [('state', 'ACTIVE'), ('multipleClientSecretsConfigured', False)]:
        if meta in privileged_after:
            require(privileged_after[meta] == allowed and
                    type(privileged_after[meta]) is type(allowed),
                    'OIDC_CLIENT_METADATA_UNSAFE_AFTER_PUT')
    return True

def request_put(ctx, path, auth, payload):
    """Only one permitted mutation: Aurora Web OIDC PUT. Never follow redirects."""
    require(bool(re.fullmatch(
        r'/t/aurora\.identity\.test/api/server/v1/applications/[A-Za-z0-9_-]{5,256}/inbound-protocols/oidc',
        path)), 'UNSAFE_MUTATING_URL')
    require(isinstance(payload, dict), 'INVALID_MUTATING_BODY')
    conn = http.client.HTTPSConnection('localhost', 9444, context=ctx, timeout=20)
    try:
        conn.request('PUT', path, body=canonical(payload), headers={
            'Authorization': auth, 'Accept': 'application/json',
            'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read(131073)
        require(len(raw) <= 131072, 'PUT_RESPONSE_TOO_LARGE_OUTCOME_UNKNOWN')
        require(response.status in (200, 201, 204), 'PUT_HTTP_' + str(response.status) + '_OUTCOME_UNKNOWN')
        # No need to parse or display a write response; read back via GET.
    finally:
        conn.close()

def acquire_token(plan, ctx, management, scopes):
    form = {'grant_type': 'client_credentials', 'scope': ' '.join(scopes)}
    result = plan.api_call(ctx, 'POST', '/t/' + DOMAIN + '/oauth2/token',
                           plan.load_module('aud_apply_resources', plan.RESOURCE_SOURCE).basic(
                               management['clientId'], management['clientSecret']),
                           form=form)
    require(result.get('token_type', '').lower() == 'bearer' and
            isinstance(result.get('access_token'), str) and result['access_token'] and
            set(scopes).issubset(set(str(result.get('scope', '')).split())),
            'MANAGEMENT_REQUIRED_SCOPES_NOT_GRANTED')
    return 'Bearer ' + result['access_token']

def read_pair(plan, ctx, root, token):
    app = plan.api_call(ctx, 'GET', root, token)
    oidc = plan.api_call(ctx, 'GET', root + '/inbound-protocols/oidc', token)
    return app, oidc

def check_baseline(plan, app, oidc, node, app_id):
    result = plan.make_plan(app, oidc, node, app_id, node['name'])
    require(result['applicationGetFingerprintSha256'] == EXPECTED_APP_SHA,
            'APP_FINGERPRINT_DRIFT_REPLAN')
    require(result['oidcGetFingerprintSha256'] == EXPECTED_OIDC_SHA,
            'OIDC_FINGERPRINT_DRIFT_REPLAN')

def report(stage, status, **kw):
    fields = {'stage': stage, 'status': status, 'tenant': DOMAIN,
              'channel': 'aurora-web', 'dockerOrConfigurationWrites': 0,
              'otherApplicationWrites': 0, 'browserLogins': 0,
              'consentV2': 'BLOCKED', 'freshTokenAcceptance': 'BLOCKED'}
    fields.update(kw)
    print(json.dumps(fields, indent=2, sort_keys=True))

def main():
    parser = argparse.ArgumentParser(description='Guarded Aurora Web audience change')
    parser.add_argument('mode', nargs='?', choices=('plan', 'apply', 'reconcile'), default='plan')
    parser.add_argument('--approve', default='')
    parser.add_argument('--expected-app-sha', default='')
    parser.add_argument('--expected-oidc-sha', default='')
    args = parser.parse_args()
    if args.mode == 'apply':
        require(args.approve == APPROVE and args.expected_app_sha == EXPECTED_APP_SHA and
                args.expected_oidc_sha == EXPECTED_OIDC_SHA,
                'EXPLICIT_APPLY_APPROVAL_AND_BOTH_FINGERPRINTS_REQUIRED')
    else:
        require(not args.approve and not args.expected_app_sha and not args.expected_oidc_sha,
                'APPROVAL_FLAGS_ONLY_ALLOWED_FOR_APPLY')
    plan = load_plan()
    plan.ensure_repo()
    plan.ensure_target()
    resources = plan.load_module('audience_apply_resources_context', plan.RESOURCE_SOURCE)
    authority = plan.load_module('audience_apply_authority_context', plan.AUTH_SOURCE)
    _, rs, saved = authority.private_context()
    node = saved['tenants']['aurora']['clients']['web']
    require(node.get('state') == 'verified' and node.get('domain') == DOMAIN and
            node.get('name') == 'Identity Lab v10 Aurora Web', 'OIDC_JOURNAL_IDENTITY_UNVERIFIED')
    app_id = node.get('id')
    require(bool(resources.ID.fullmatch(str(app_id))), 'OIDC_APP_ID_INVALID')
    root = '/t/' + DOMAIN + '/api/server/v1/applications/' + app_id
    private_base = resources.ROOT / 'private'
    store = private_base / 'audience-aurora-web-v1'
    journal_file = store / 'write-journal.json'
    backup_file = store / 'before-put.private.json'
    if args.mode == 'apply':
        require(not journal_file.exists() and not journal_file.is_symlink() and
                not backup_file.exists() and not backup_file.is_symlink(),
                'PRIOR_AUDIENCE_WRITE_ATTEMPT_REFUSE_RECONCILE')
    ctx = plan.https_client_context()
    management = rs['tenants']['aurora']['management']
    view_auth = acquire_token(plan, ctx, management, ('internal_application_mgt_view',))
    view_app, view_oidc = read_pair(plan, ctx, root, view_auth)
    # For reconcile, the original baseline has intentionally already changed.
    if args.mode != 'reconcile':
        check_baseline(plan, view_app, view_oidc, node, app_id)
    elevated = acquire_token(plan, ctx, management, SCOPES)
    full_app, full_oidc = read_pair(plan, ctx, root, elevated)
    if args.mode != 'reconcile':
        require(full_app == view_app, 'ELEVATED_GET_APP_REPRESENTATION_CHANGED')
        require(without_secret(full_oidc) == without_secret(view_oidc),
                'OIDC_ACCESS_LEVEL_REPRESENTATION_CHANGED')
        candidate = prepare_payload(full_oidc, node)
    else:
        require(store.is_dir() and not store.is_symlink(), 'NO_PRIOR_WRITE_STATE')
        backup = read_private_json(backup_file)
        journal = read_private_json(journal_file)
        require(journal.get('schema') == 'ciam.v10.audience.aurora-web.v1' and
                journal.get('preOidcSha') == EXPECTED_OIDC_SHA and
                journal.get('preAppSha') == EXPECTED_APP_SHA and
                backup.get('preOidcSha') == EXPECTED_OIDC_SHA,
                'RECOVERY_JOURNAL_INCONSISTENT')
        require(sha(backup.get('viewOidc')) == EXPECTED_OIDC_SHA and
                sha(backup.get('viewApp')) == EXPECTED_APP_SHA,
                'RECOVERY_BACKUP_CORRUPTED')
        try:
            verify_after(backup['viewApp'], backup['viewOidc'], view_app, view_oidc, full_oidc, node)
            disposition = 'EXPECTED_AUDIENCE_READBACK_VERIFIED'
        except Refuse:
            disposition = ('UNCHANGED' if view_app == backup['viewApp'] and
                           view_oidc == backup['viewOidc'] else 'DRIFT_OR_AMBIGUOUS_MANUAL_REVIEW')
        report('CIAM_V10_AURORA_WEB_AUDIENCE_RECONCILE', 'VERIFIED_READBACK',
               disposition=disposition, journalState=journal.get('state'),
               managementResourceWrites=0,
               note='Read-only reconciliation; never automatically repeats PUT')
        return
    if args.mode == 'plan':
        require(not journal_file.exists() and not journal_file.is_symlink() and
                not backup_file.exists() and not backup_file.is_symlink(),
                'PREVIOUS_AUDIENCE_WRITE_STATE_PRESENT')
        report('CIAM_V10_AURORA_WEB_AUDIENCE_APPLY_PREFLIGHT', 'VERIFIED_READBACK',
               confirmedScopes=list(SCOPES), managementResourceWrites=0,
               previousAppSha=EXPECTED_APP_SHA, previousOidcSha=EXPECTED_OIDC_SHA,
               proposedChange={'path':'/idToken/audience','from':[], 'to':[AUDIENCE]},
               clientSecret='CONFIRMED_MATCHES_PRIVATE_JOURNAL_NOT_PRINTED',
               updateSemantics='FULL_DOCUMENT_PUT_ONLY_WITH_STRICT_READBACK',
               safeForAutomaticApply=False,
               warning='PUT_NOT_YET_TESTED_LIVE; explicit apply can have unknown outcome')
        return
    # Explicit apply: construct entire update from current verified full GET;
    # only then create immutable private backup and write-ahead journal.
    store = safe_private_dir(resources.ROOT)
    lock_file = store / 'write.lock'
    fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        os.write(fd, b'one-shot v10 Aurora Web audience update\n')
        os.fsync(fd)
        require(not journal_file.exists() and not journal_file.is_symlink() and
                not backup_file.exists() and not backup_file.is_symlink(),
                'PREVIOUS_WRITE_RECORD_EXISTS_NO_RETRY')
        # Refresh all remote GETs AFTER obtaining the lock: no stale preflight write.
        fresh_view_app, fresh_view_oidc = read_pair(plan, ctx, root, view_auth)
        fresh_full_app, fresh_full_oidc = read_pair(plan, ctx, root, elevated)
        require(fresh_view_app == view_app and fresh_view_oidc == view_oidc and
                fresh_full_app == full_app and fresh_full_oidc == full_oidc,
                'REMOTE_DRIFT_INSIDE_LOCK_REFUSE')
        require(prepare_payload(fresh_full_oidc, node) == candidate,
                'PAYLOAD_CHANGED_INSIDE_LOCK_REFUSE')
        exclusive_json(backup_file, {
            'schema':'ciam.v10.audience.aurora-web.backup.v1',
            'preAppSha':EXPECTED_APP_SHA, 'preOidcSha': EXPECTED_OIDC_SHA,
            'viewApp':view_app, 'viewOidc':view_oidc,
            'privilegedApp':full_app, 'privilegedOidc':full_oidc,
            'candidatePut':candidate,
        })
        journal = {'schema':'ciam.v10.audience.aurora-web.v1',
                   'preAppSha':EXPECTED_APP_SHA, 'preOidcSha':EXPECTED_OIDC_SHA,
                   'state':'PUT_MAY_HAVE_STARTED_OUTCOME_UNKNOWN',
                   'attemptCount':1, 'application':'aurora-web',
                   'intendedAudience':AUDIENCE}
        exclusive_json(journal_file, journal)
        # Exactly ONE remote PUT is possible. Do not retry even on timeout.
        global PUT_STARTED
        PUT_STARTED = True
        request_put(ctx, root + '/inbound-protocols/oidc', elevated, candidate)
        app_after, oidc_after = read_pair(plan, ctx, root, view_auth)
        _, privileged_after = read_pair(plan, ctx, root, elevated)
        verify_after(view_app, view_oidc, app_after, oidc_after, privileged_after, node)
        journal['state'] = 'MANAGEMENT_READBACK_VERIFIED_LIVE_TOKEN_PENDING'
        atomic_journal(journal_file, journal)
        report('CIAM_V10_AURORA_WEB_AUDIENCE_APPLY', 'VERIFIED_READBACK',
               managementResourceWrites=1,
               oidcAudience='VERIFIED_READBACK',
               clientSecret='PRESERVED_VERIFIED_READBACK_NOT_PRINTED',
               protectedProfileHttp200='BLOCKED_PENDING_FRESH_BROWSER_LOGIN')
    finally:
        os.close(fd)
        # Never delete the journal or backup, even after successful verification.
        try:
            lock_file.unlink()
        except OSError:
            pass

if __name__ == '__main__':
    try:
        main()
    except (Refuse, OSError, KeyError, TypeError, AttributeError, ValueError,
            ssl.SSLError, http.client.HTTPException, subprocess.TimeoutExpired):
        err = sys.exc_info()[1]
        code = str(err) if isinstance(err, Refuse) else type(err).__name__
        report('CIAM_V10_AURORA_WEB_AUDIENCE_APPLY', 'NOT_VERIFIED',
               reason=code,
               managementResourceWrites=('OUTCOME_UNKNOWN_DO_NOT_RETRY' if PUT_STARTED else 0),
               action='DO_NOT_REPEAT_APPLY_IF_JOURNAL_EXISTS; reconcile read-only')
        sys.exit(1)
