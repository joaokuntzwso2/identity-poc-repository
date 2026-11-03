#!/usr/bin/env python3
"""Read-only, sanitized Phase 4 business role evidence; no grants or journal writes.

Expected scope names are nonsecret known Phase 4 contract values. This program
never prints remote permission IDs outside that allowlist, users, tokens, role
IDs, HTTP paths, private journals, or raw exceptions.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import urllib.parse

BUSINESS_SOURCE = Path('deploy/ciam-v10/phase4/business-bootstrap.py')
RESOURCES_SOURCE = Path('deploy/ciam-v10/resources/bootstrap.py')
BUSINESS_SHA = '2e519c7239d6a638a9622bff7638e3d8e09b6524ef00f740b62080d96eb773c4'
RESOURCES_SHA = 'c53e50f270acf83b7f3126bdd85ac945001323752218005f5b97df74fd5ecae1'
CANONICAL_SCOPES = frozenset({
    'ciam:cases:create', 'ciam:cases:read', 'ciam:cases:review', 'ciam:cases:approve'
})
ROLE_KINDS = frozenset({'customer', 'seller', 'administrator'})


def permission_view(role, expected):
    """Only known names/counts and booleans; never echo other scope values."""
    if not isinstance(role, dict):
        return {'schema': 'NOT_OBJECT', 'exact': False}
    if 'permissions' not in role:
        return {'schema': 'ABSENT', 'exact': False}
    entries = role['permissions']
    if not isinstance(entries, list):
        return {'schema': 'NOT_ARRAY', 'exact': False}
    observed = set()
    unexpected_values = set()
    display_matches = set()
    noncanonical = 0
    missing_value = 0
    for item in entries:
        if not isinstance(item, dict):
            noncanonical += 1
            continue
        v = item.get('value')
        if not isinstance(v, str):
            missing_value += 1
        else:
            observed.add(v)
            if v not in CANONICAL_SCOPES:
                unexpected_values.add(v)
        d = item.get('display')
        if isinstance(d, str) and d in expected:
            display_matches.add(d)
    return {
        'schema': 'SCIM_PERMISSION_OBJECT_ARRAY',
        'count': len(entries),
        'exact': observed == expected and not noncanonical and not missing_value and len(entries) == len(observed),
        'expected': sorted(expected),
        'presentExpected': sorted(observed & expected),
        'missingExpected': sorted(expected - observed),
        'otherKnownScopes': sorted((observed & CANONICAL_SCOPES) - expected),
        'unknownPermissionValueCount': len(unexpected_values),
        'entriesWithoutStringValue': missing_value,
        'nonObjectEntries': noncanonical,
        'expectedNamesInDisplayField': sorted(display_matches),
        'duplicateValueEntries': max(0, len(entries) - len(observed) - missing_value - noncanonical),
    }


def self_test():
    e = {'ciam:cases:create', 'ciam:cases:read'}
    d = permission_view({'permissions': [{'value': 'ciam:cases:create'}, {'value': 'ciam:cases:read'}]}, e)
    assert d['exact'] is True and not d['missingExpected']
    d = permission_view({'permissions': [{'value': 'ciam:cases:create'}, {'value': 'SENSITIVE_ACTUAL_SCOPE'}]}, e)
    assert d['exact'] is False and d['missingExpected'] == ['ciam:cases:read']
    assert d['unknownPermissionValueCount'] == 1
    assert 'SENSITIVE' not in json.dumps(d)
    d = permission_view({'permissions': [{'value': 'opaque-permission-id', 'display': 'ciam:cases:read'}]}, e)
    assert d['expectedNamesInDisplayField'] == ['ciam:cases:read']
    assert d['unknownPermissionValueCount'] == 1
    assert permission_view({}, e)['schema'] == 'ABSENT'
    assert permission_view({'permissions': None}, e)['schema'] == 'NOT_ARRAY'
    d = permission_view({'permissions': [{'value': 'ciam:cases:read'}, {'value': 'ciam:cases:read'}]}, {'ciam:cases:read'})
    assert d['exact'] is False and d['duplicateValueEntries'] == 1
    print('SELF_TEST_PASS: six analyses; unexpected scope values remain redacted')


def exact_source(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 150000:
        return False
    return hashlib.sha256(path.read_bytes()).hexdigest() == expected


def audit():
    if not exact_source(BUSINESS_SOURCE, BUSINESS_SHA) or not exact_source(RESOURCES_SOURCE, RESOURCES_SHA):
        return {'diagnostic': 'CIAM_PHASE4_ROLE_EVIDENCE_V1', 'result': 'REFUSED_SOURCE_CHANGED'}
    spec = importlib.util.spec_from_file_location('phase4_readonly_audit_source', BUSINESS_SOURCE.resolve())
    phase4 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(phase4)
    desired, tenants, oidc, identities = phase4.context()
    state = phase4.resources.private_read(phase4.JOURNAL)
    if (not isinstance(state, dict) or state.get('schema') != 'ciampoc.v4.business-journal.v1' or
            state.get('specSha256') != hashlib.sha256(phase4.SPEC_FILE.read_bytes()).hexdigest()):
        return {'diagnostic': 'CIAM_PHASE4_ROLE_EVIDENCE_V1', 'result': 'REFUSED_JOURNAL_CONTEXT'}
    api = desired.get('businessApi', {})
    if api.get('identifier') != 'urn:ciampoc:service-requests:v1':
        return {'diagnostic': 'CIAM_PHASE4_ROLE_EVIDENCE_V1', 'result': 'REFUSED_SPEC_IDENTIFIER'}
    rp = api.get('rolePermissions', {})
    if (not isinstance(rp, dict) or not set(rp).issubset(ROLE_KINDS) or
            any(not isinstance(v, list) or not set(v).issubset(CANONICAL_SCOPES) for v in rp.values())):
        return {'diagnostic': 'CIAM_PHASE4_ROLE_EVIDENCE_V1', 'result': 'REFUSED_SPEC_SCOPE_SET'}
    remote = phase4.resources.HTTPS()
    rows = []
    for brand in ('aurora', 'brisa'):
        credentials = phase4.auth(tenants, brand)
        journal_roles = state['tenants'][brand]['roles']
        users = identities['tenants'][brand]['users']
        for channel in ('web', 'app'):
            app_id = oidc['tenants'][brand]['clients'][channel]['id']
            for kind, scope_list in rp.items():
                members = {x['id'] for x in users.values() if x['kind'] == kind}
                if not members:
                    continue
                expected = set(scope_list)
                row = {'tenant': brand, 'channel': channel, 'roleKind': kind}
                journal = journal_roles.get(channel + ':' + kind, {})
                role_id = journal.get('id')
                if (journal.get('state') != 'verified' or not isinstance(role_id, str) or
                        not phase4.resources.ID.fullmatch(role_id)):
                    row['result'] = 'JOURNAL_ROLE_NOT_VERIFIED'
                    rows.append(row)
                    continue
                url = phase4.role_base(brand) + '/' + role_id
                code, obj = phase4.call(remote, 'GET', url, credentials)
                row['roleGetHttp'] = code
                if code != 200:
                    row['result'] = 'ROLE_GET_FAILED'
                    rows.append(row)
                    continue
                if not isinstance(obj, dict):
                    row['result'] = 'ROLE_RESPONSE_NOT_OBJECT'
                    rows.append(row)
                    continue
                row['roleIdentityMatches'] = obj.get('id') == role_id and obj.get('displayName') == (
                    'CIAM Business ' + kind.title() + ' ' + channel.upper())
                row['audienceMatches'] = obj.get('audience', {}).get('value') == app_id if isinstance(obj.get('audience'), dict) else False
                present_members = obj.get('users')
                row['membersMatch'] = (
                    isinstance(present_members, list) and
                    all(isinstance(x, dict) for x in present_members) and
                    {x.get('value') for x in present_members} == members and
                    len(present_members) == len(members)
                )
                row['expectedMemberCount'] = len(members)
                row['observedMemberCount'] = len(present_members) if isinstance(present_members, list) else None
                direct = permission_view(obj, expected)
                row['directPermissions'] = direct
                if direct['exact']:
                    row['result'] = ('ROLE_PERMISSIONS_MATCH' if row['roleIdentityMatches'] and
                                     row['audienceMatches'] and row['membersMatch'] else
                                     'ROLE_METADATA_OR_MEMBERS_DRIFT')
                else:
                    # Explicit SCIM attributes query is also GET-only, never POST/PUT.
                    suffix = '?' + urllib.parse.urlencode({'attributes': 'permissions'})
                    projected_code, projected_obj = phase4.call(remote, 'GET', url + suffix, credentials)
                    row['projectionGetHttp'] = projected_code
                    if projected_code == 200:
                        projection = permission_view(projected_obj, expected)
                        row['projectedPermissions'] = projection
                        row['result'] = ('PERMISSIONS_ONLY_IN_EXPLICIT_PROJECTION' if projection['exact'] else
                                         'ROLE_PERMISSIONS_MISMATCH_CONFIRMED')
                    else:
                        row['result'] = 'ROLE_PERMISSIONS_MISMATCH_PROJECTION_UNAVAILABLE'
                rows.append(row)
    mismatch_count = sum(r.get('result') != 'ROLE_PERMISSIONS_MATCH' for r in rows)
    if not rows:
        return {'diagnostic': 'CIAM_PHASE4_ROLE_EVIDENCE_V1',
                'result': 'REFUSED_NO_APPLICABLE_ROLES', 'sourceDigestsVerified': True}
    return {
        'diagnostic': 'CIAM_PHASE4_ROLE_EVIDENCE_V1',
        'result': 'ALL_ROLES_MATCH' if mismatch_count == 0 else 'ROLE_DRIFT_NEEDS_REVIEW',
        'method': 'GET_ONLY', 'sourceDigestsVerified': True, 'roleApiVersion': 'v2',
        'rolesChecked': len(rows), 'rolesNotMatching': mismatch_count,
        'rows': rows,
        'privacy': 'No URLs, role IDs, user IDs, raw role data, tokens, credentials or unknown permission names are printed.'
    }


def main():
    if sys.argv[1:] == ['--self-test']:
        self_test()
        return
    if sys.argv[1:]:
        print('Usage: cd REPO && python3 ~/Downloads/scripts/ciam-phase4-role-readback.py')
        sys.exit(2)
    try:
        result = audit()
    except Exception as e:
        # Never interpolate a remote error or journal detail into the report.
        result = {
            'diagnostic': 'CIAM_PHASE4_ROLE_EVIDENCE_V1',
            'result': 'REFUSED_OR_REMOTE_ERROR',
            'errorClass': type(e).__name__ if type(e).__name__ in (
                'Refuse', 'KeyError', 'ValueError', 'TypeError', 'OSError',
                'SSLError', 'JSONDecodeError', 'HTTPException', 'TimeoutError') else 'OTHER',
            'detail': 'No raw exception or remote response is displayed.'
        }
    print(json.dumps(result, indent=2, sort_keys=False))
    if result.get('result') != 'ALL_ROLES_MATCH':
        sys.exit(2)


if __name__ == '__main__':
    main()
