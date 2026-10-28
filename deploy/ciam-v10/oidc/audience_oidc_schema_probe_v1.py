#!/usr/bin/env python3
"""Read-only, tenant-scoped analysis of unexpected Aurora Web OIDC GET field names.

No management PUT/PATCH, local files, Docker changes, secrets or token output.
Requires the exact previously reviewed audience_apply_v2.py and audience_plan.py.
Never prints field values, IDs, URLs, scopes from response or client secrets.
"""
import hashlib
import importlib.util
import json
import re
import ssl
import http.client
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
V2 = ROOT / 'deploy/ciam-v10/oidc/audience_apply_v2.py'
EXPECTED_V2_SHA = 'e438622108ca11e93fe868751dff738e43f6a4408d4c7da132fda0ec6bc7b0d5'
EXACT_DOMAIN = 'aurora.identity.test'
EXPECTED_APP_NAME = 'Identity Lab v10 Aurora Web'
SAFE_FIELD = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z', flags=re.ASCII)

class Refuse(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Refuse(reason)


def load_v2():
    require(V2.is_file() and not V2.is_symlink(), 'PINNED_V2_SOURCE_MISSING')
    require(hashlib.sha256(V2.read_bytes()).hexdigest() == EXPECTED_V2_SHA,
            'V2_SOURCE_CHANGED_STOP_FOR_REVIEW')
    spec = importlib.util.spec_from_file_location('ciam_v10_oidc_schema_probe_pinned_v2', V2)
    require(spec is not None and spec.loader is not None, 'V2_SOURCE_NOT_LOADABLE')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def render_field_names(oidc, v2):
    """Pure summary of property names ONLY; untrusted names must be bounded."""
    require(type(oidc) is dict, 'OIDC_RESPONSE_NOT_OBJECT')
    unknown = set(oidc.keys()) - v2.UPDATE_MEMBERS - v2.READ_ONLY_MEMBERS
    require(len(unknown) <= 32, 'TOO_MANY_UNKNOWN_FIELDS_NO_NAMES_REPORTED')
    require(all(type(key) is str and SAFE_FIELD.fullmatch(key) for key in unknown),
            'UNSAFE_FIELD_NAME_NO_NAMES_REPORTED')
    return {
        'unrecognizedFieldNames': sorted(unknown),
        'unrecognizedFieldCount': len(unknown),
        'knownWritableFieldCount': len(set(oidc) & v2.UPDATE_MEMBERS),
        'knownGetOnlyFieldNames': sorted(set(oidc) & v2.READ_ONLY_MEMBERS),
        'allFieldNamesSha256': hashlib.sha256(json.dumps(
            sorted(oidc), ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest(),
    }


def schema_diff(view_oidc, elevated_oidc, v2):
    require(type(view_oidc) is dict and type(elevated_oidc) is dict,
            'OIDC_RESPONSE_NOT_OBJECT')
    require(v2.without_secret(view_oidc) == v2.without_secret(elevated_oidc),
            'VIEW_AND_PRIVILEGED_METADATA_DIFFER_STOP')
    view = render_field_names(view_oidc, v2)
    elevated = render_field_names(elevated_oidc, v2)
    require(view['unrecognizedFieldNames'] == elevated['unrecognizedFieldNames'],
            'ACCESS_LEVEL_UNKNOWN_FIELDS_DIFFER_STOP')
    return {
        'viewOnly': view,
        'privileged': elevated,
        'unknownFieldSetsMatch': True,
    }


def report(status, **details):
    result = {
        'stage': 'CIAM_V10_AURORA_WEB_OIDC_FIELD_SCHEMA_PROBE_V1',
        'status': status,
        'mode': 'READ_ONLY_GET_FIELD_NAMES_ONLY',
        'tenant': EXACT_DOMAIN,
        'channel': 'aurora-web',
        'managementResourceWrites': 0,
        'dockerOrConfigurationWrites': 0,
        'privateJournalWrites': 0,
        'browserLogins': 0,
        'freshTokenAcceptance': 'BLOCKED',
        'consentV2': 'BLOCKED',
    }
    result.update(details)
    print(json.dumps(result, indent=2, sort_keys=True))


def main():
    require(len(sys.argv) == 1, 'NO_ARGUMENTS_ACCEPTED')
    v2 = load_v2()
    plan = v2.load_plan()
    plan.ensure_repo()
    plan.ensure_target()
    resources = plan.load_module('ciam_oidc_field_probe_resources', plan.RESOURCE_SOURCE)
    authority = plan.load_module('ciam_oidc_field_probe_authority', plan.AUTH_SOURCE)
    _, rs, saved = authority.private_context()
    node = saved['tenants']['aurora']['clients']['web']
    require(node.get('state') == 'verified' and node.get('domain') == EXACT_DOMAIN
            and node.get('name') == EXPECTED_APP_NAME, 'PRIVATE_APP_JOURNAL_IDENTITY_CHANGED')
    app_id = node.get('id')
    require(isinstance(app_id, str) and resources.ID.fullmatch(app_id),
            'JOURNALED_APP_ID_INVALID')
    path = '/t/' + EXACT_DOMAIN + '/api/server/v1/applications/' + app_id
    context = plan.https_client_context()
    management = rs['tenants']['aurora']['management']
    view_auth = v2.acquire_token(plan, context, management, ('internal_application_mgt_view',))
    view_app, view_oidc = v2.read_pair(plan, context, path, view_auth)
    # Verify exact prior unchanged GET representation, including opaque digest.
    v2.check_baseline(plan, view_app, view_oidc, node, app_id)
    elevated_auth = v2.acquire_token(plan, context, management, v2.SCOPES)
    full_app, full_oidc = v2.read_pair(plan, context, path, elevated_auth)
    require(view_app == full_app, 'APP_REPRESENTATION_CHANGED_AT_PRIVILEGED_LEVEL')
    outcome = schema_diff(view_oidc, full_oidc, v2)
    report('VERIFIED_READBACK',
           appFingerprintSha256=v2.EXPECTED_APP_SHA,
           oidcViewFingerprintSha256=v2.EXPECTED_OIDC_SHA,
           managementOAuthTokenRequests=2,
           managementGetRequests=4,
           **outcome,
           nextAction=('REVIEW_UNRECOGNIZED_GET_KEYS_AGAINST_INSTALLED_WSO2_API_SCHEMA; '
                       'DO_NOT_APPLY_OIDC_PUT'))


if __name__ == '__main__':
    try:
        main()
    except (Refuse, OSError, ValueError, KeyError, TypeError, AttributeError,
            ssl.SSLError, http.client.HTTPException, subprocess.TimeoutExpired) as error:
        # Never expose exception messages from network responses or secret loading.
        reason = str(error) if isinstance(error, Refuse) else type(error).__name__
        report('NOT_VERIFIED', reason=reason,
               nextAction='STOP_NO_CHANGES_AND_REVIEW_FAILURE')
        sys.exit(1)
