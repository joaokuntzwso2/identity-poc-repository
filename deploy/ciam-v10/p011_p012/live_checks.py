"""Independent, READ-ONLY Cases configuration and durable event verification.

Configuration readback is intentionally separate from historical ownership provenance:
no missing provisioning journal is created, inferred, or declared verified.
"""
from __future__ import annotations
import importlib.util
import ast
import json
import os
from pathlib import Path
import re
import stat

UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
HASH = re.compile(r'^[a-f0-9]{64}$')
PINNED_IDENTIFIER = 'urn:ciampoc:service-requests:v1'
# Existing-resource contract (not the separate create-new-resource bootstrap).
PINNED_RESOURCE_NAME = 'CIAM Service Requests API'

class Blocked(Exception):
    """Safe, predefined failure codes only (never include remote values)."""


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def verify_role_detail(detail, *, role_id, name, app_id, expected_users, expected_scopes):
    require(isinstance(detail, dict), 'ROLE_DETAIL_INVALID')
    audience = detail.get('audience')
    require(isinstance(audience, dict) and audience.get('type') == 'application' and
            audience.get('value') == app_id, 'ROLE_AUDIENCE_MISMATCH')
    require(detail.get('id') == role_id and detail.get('displayName') == name,
            'ROLE_ID_OR_NAME_MISMATCH')
    for field, expected in (('users', expected_users), ('permissions', expected_scopes)):
        rows = detail.get(field)
        require(isinstance(rows, list) and all(isinstance(x,dict) and isinstance(x.get('value'),str) for x in rows),
                'ROLE_'+field.upper()+'_SHAPE')
        values = [x['value'] for x in rows]
        require(len(values) == len(set(values)) and set(values) == set(expected),
                'ROLE_'+field.upper()+'_MISMATCH')
    return True


def verify_resource_detail(item, detail, scopes, *, identifier, name, resource_id_validator):
    require(isinstance(item, dict) and isinstance(detail, dict), 'RESOURCE_NOT_OBJECT')
    rid = item.get('id')
    require(isinstance(rid, str) and resource_id_validator.fullmatch(rid), 'RESOURCE_ID_INVALID')
    require(detail.get('id') == rid, 'RESOURCE_ID_MISMATCH')
    require(detail.get('identifier') == identifier, 'RESOURCE_IDENTIFIER_MISMATCH')
    require(detail.get('name') == name, 'RESOURCE_NAME_MISMATCH')
    require(detail.get('requiresAuthorization') is True,
            'RESOURCE_REQUIRES_AUTHORIZATION_MISMATCH')
    # Existing live APIs have independent provisioning history. A new-resource
    # ownerMarker cannot be demanded from or inferred about that resource.
    # Description is non-authoritative metadata, not a grant or ownership proof.
    require(detail.get('description') is None or isinstance(detail.get('description'), str),
            'RESOURCE_DESCRIPTION_SHAPE_INVALID')
    require(isinstance(scopes, list) and all(isinstance(x, str) for x in scopes) and
            len(scopes) == len(set(scopes)), 'RESOURCE_SCOPE_SHAPE')
    return rid


def verify_existing_resource_contract(repo):
    """Statically pin the existing-resource stage, without executing its code.

    Any change in its pinned audience or name must be explicitly reviewed.
    """
    path = Path(repo) / 'deploy/ciam-v10/cases-rbac/existing_roles.py'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 200000,
            'EXISTING_RESOURCE_CONTRACT_UNAVAILABLE')
    try:
        tree = ast.parse(path.read_text(encoding='utf-8'))
    except (SyntaxError, UnicodeError, OSError):
        raise Blocked('EXISTING_RESOURCE_CONTRACT_UNREADABLE') from None
    fields = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ('IDENTIFIER', 'RESOURCE_NAME') and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                require(node.targets[0].id not in fields, 'EXISTING_RESOURCE_CONTRACT_AMBIGUOUS')
                fields[node.targets[0].id] = node.value.value
    require(fields == {'IDENTIFIER': PINNED_IDENTIFIER, 'RESOURCE_NAME': PINNED_RESOURCE_NAME},
            'EXISTING_RESOURCE_CONTRACT_DRIFT')
    return True

# The established live business-role contract predates the separate, guarded
# six-role "CIAM v10 Cases ..." creation stage. Never make new role names or
# provision permissions merely to satisfy a read-only acceptance gate.
def existing_business_role_specs(c, oidc, identities, seed, brand):
    require(brand in ('aurora', 'brisa'), 'TENANT_NOT_IN_ROLE_CONTRACT')
    roles=[]
    for channel in ('web', 'app'):
        app=oidc['tenants'][brand]['clients'][channel]
        require(isinstance(app.get('id'), str) and c.resources.ID.fullmatch(app['id']),
                'ORIGINAL_ROLE_APP_ID_INVALID')
        for kind in ('customer', 'seller', 'administrator'):
            users=c.memberships(identities, seed, brand, kind)
            if not users:
                continue
            require(isinstance(users, list) and len(users)==len(set(users)) and
                    all(isinstance(x,str) and c.resources.ID.fullmatch(x) for x in users),
                    'ORIGINAL_ROLE_MEMBERSHIP_INVALID')
            perms=(c.CUSTOMER_SCOPES if kind=='customer' else
                   c.SELLER_SCOPES if kind=='seller' else
                   ('ciam:cases:read', 'ciam:cases:review'))
            name=f'CIAM Business {kind.title()} {channel.upper()}'
            roles.append((channel,kind,app['id'],name,users,tuple(perms)))
    require(len(roles)==(6 if brand=='aurora' else 4), 'ORIGINAL_ROLE_COUNT_MISMATCH')
    return roles


def verify_no_extra_case_roles(c, client, brand, auth, version, expected_ids):
    """Exhaustive SCIM list, then exact readbacks; fail closed on unexpected grants."""
    from urllib.parse import urlencode
    case_scopes=set(c.SCOPES)
    seen=set()
    present=set()
    total=None
    for _ in range(55):
        url=c.path(brand, '/scim2/'+version+'/Roles')+'?'+urlencode(
            {'startIndex': len(seen)+1, 'count': 100})
        page=c.read(client,url,auth)
        require(isinstance(page,dict) and type(page.get('totalResults')) is int and
                0<=page['totalResults']<=5000, 'ROLE_INVENTORY_COUNT_UNVERIFIED')
        if total is None:total=page['totalResults']
        require(total==page['totalResults'], 'ROLE_INVENTORY_CHANGED')
        rows=c.list_items(page,'Resources','resources')
        require(isinstance(rows,list) and len(rows)<=100 and
                (rows or len(seen)==total), 'ROLE_INVENTORY_PAGE_UNVERIFIED')
        for row in rows:
            require(isinstance(row,dict) and isinstance(row.get('id'),str) and
                    c.resources.ID.fullmatch(row['id']) and row['id'] not in seen and
                    isinstance(row.get('displayName'),str),
                    'ROLE_INVENTORY_DUPLICATE_OR_INVALID')
            seen.add(row['id'])
            if row['displayName'] in expected_ids:
                require(row['id']==expected_ids[row['displayName']],
                        'EXPECTED_ROLE_INVENTORY_MISMATCH')
                present.add(row['displayName'])
                continue
            detail=c.read(client,c.path(brand, '/scim2/'+version+'/Roles/'+row['id']),auth)
            require(isinstance(detail,dict) and detail.get('id')==row['id'] and
                    detail.get('displayName')==row['displayName'] and
                    isinstance(detail.get('permissions'),list),
                    'UNEXPECTED_ROLE_DETAIL_UNVERIFIED')
            permissions=detail['permissions']
            require(all(isinstance(x,dict) and isinstance(x.get('value'),str)
                        for x in permissions), 'UNEXPECTED_ROLE_PERMISSIONS_INVALID')
            require(not ({x['value'] for x in permissions} & case_scopes),
                    'UNEXPECTED_ROLE_HAS_CASES_PERMISSION')
        require(len(seen)<=total,'ROLE_INVENTORY_COUNT_OVERFLOW')
        if len(seen)==total:
            require(present==set(expected_ids), 'EXPECTED_ROLE_MISSING_FROM_INVENTORY')
            return len(seen)
    raise Blocked('ROLE_INVENTORY_PAGINATION_LIMIT')


def independent_rbac_readback(case_module, client, context, identifier=PINNED_IDENTIFIER):
    """Check live WSO2 resource, grants, SCIM roles & users; NEVER assume ownership.

    All requests go through the preexisting TLS-validated GET-only client.
    The returned dictionary is allowlisted counts/statuses, never IDs/credentials.
    """
    c = case_module
    ts, oidc, _authority, identities, seed, version = context
    require(identifier == PINNED_IDENTIFIER, 'UNSUPPORTED_CASES_AUDIENCE')
    require(version in ('v2','v3'), 'ROLE_API_VERSION_UNSUPPORTED')
    result = {}
    for brand, domain in c.DOMAINS.items():
        auth = c.resources.basic(c.resources.OWNER+'@'+domain,ts['tenants'][brand]['owner']['password'])
        item = c.exact_resource(client,brand,auth,identifier)
        require(item is not None, 'CASE_RESOURCE_MISSING_'+brand.upper())
        rid = item.get('id')
        detail = c.read(client,c.path(brand,'/api/server/v1/api-resources/'+str(rid)),auth)
        s = c.read(client,c.path(brand,'/api/server/v1/api-resources/'+str(rid)+'/scopes'),auth)
        rows = c.list_items(s,'scopes')
        names = [x if isinstance(x,str) else x.get('name') if isinstance(x,dict) else None for x in rows]
        verify_resource_detail(item,detail,names,identifier=identifier,name=PINNED_RESOURCE_NAME,
                               resource_id_validator=c.resources.ID)
        require(set(names) == set(c.SCOPES), 'RESOURCE_SCOPES_MISMATCH')
        roles_checked = 0
        verified_role_ids={}
        for channel in ('web','app'):
            app = oidc['tenants'][brand]['clients'][channel]
            app_id=app['id']
            actual_app=c.read(client,c.path(brand,'/api/server/v1/applications/'+app_id),auth)
            require(actual_app.get('id')==app_id and actual_app.get('name')==app['name'] and
                    (actual_app.get('associatedRoles') or {}).get('allowedAudience')=='APPLICATION',
                    'APP_AUDIENCE_OR_NAME_MISMATCH')
            grant=c.read_authorization(client,brand,auth,app_id,rid)
            require(grant is not None, 'APP_AUTHORIZATION_MISSING')
            require(c.permission_list(grant)==set(c.SCOPES),'APP_SCOPE_AUTHORIZATION_MISMATCH')
            declared=[grant[k] for k in ('policyId','policyIdentifier') if k in grant]
            require(declared and all(type(x) is str and x=='RBAC' for x in declared),
                    'APP_RBAC_POLICY_NOT_ATTESTED')
        original_roles=existing_business_role_specs(c,oidc,identities,seed,brand)
        for channel, kind, app_id, role_name, users, perms in original_roles:
            for uid in users:
                person=c.read(client,c.path(brand,'/scim2/Users/'+uid),auth)
                require(person.get('id')==uid and person.get('active') is not False,
                        'ROLE_MEMBER_MISSING_OR_INACTIVE')
            role=c.exact_role(client,brand,auth,version,role_name)
            require(role is not None, 'CASE_ROLE_MISSING')
            role_id=role.get('id')
            require(isinstance(role_id,str) and c.resources.ID.fullmatch(role_id), 'ROLE_ID_INVALID')
            role_detail=c.read(client,c.path(brand,'/scim2/'+version+'/Roles/'+role_id),auth)
            verify_role_detail(role_detail,role_id=role_id,name=role_name,app_id=app_id,
                               expected_users=users,expected_scopes=perms)
            roles_checked+=1
            verified_role_ids[role_name]=role_id
        enumerated=verify_no_extra_case_roles(c,client,brand,auth,version,
                                              verified_role_ids)
        result[brand]={'resource':'PASS','scopes':'PASS','authorizedApplications':2,
                       'scimRolesVerified':roles_checked,'allScimRolesEnumerated':enumerated,
                       'membership':'PASS_DIRECT_ONLY',
                       'groupInheritance':'NOT_ATTESTED'}
    require(len(result)==2 and all(v['scimRolesVerified']>0 for v in result.values()),
            'CASES_ROLE_COVERAGE_INCOMPLETE')
    return {'outcome':'PASS','evidenceClass':'LIVE_READBACK','tenants':result,
            'historicalOwnership':'BLOCKED_MISSING_JOURNAL',
            'runtimeAuthorization':'NOT_TESTED_BY_MANAGEMENT_READBACK',
            'businessRoleContract':'ESTABLISHED_TEN_ROLE_CONTRACT',
            'groupInheritance':'NOT_ATTESTED'}


def load_cases_module(repo):
    source=Path(repo)/'deploy/ciam-v10/cases-rbac/bootstrap.py'
    require(source.is_file() and not source.is_symlink(), 'CASES_SOURCE_UNAVAILABLE')
    spec=importlib.util.spec_from_file_location('ciam_p011_cases_readback',source)
    require(spec is not None and spec.loader is not None,'CASES_IMPORT_UNAVAILABLE')
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_cases_readback(repo):
    """All exceptions are sanitized at the caller; no raw WSO2 responses logged."""
    try:
        verify_existing_resource_contract(repo)
        c=load_cases_module(repo)
        # No private journal of Cases ownership is needed for configuration verification.
        context=c.context()
        client=c.resources.HTTPS()
        return independent_rbac_readback(c,client,context)
    except Blocked as exc:
        code=str(exc)
        mismatch=any(word in code for word in ('MISMATCH','MISSING','INVALID','INACTIVE'))
        return {'outcome':'NOT_READY' if mismatch else 'BLOCKED','reason':code}
    except Exception:
        return {'outcome':'BLOCKED','reason':'LIVE_RBAC_READBACK_UNAVAILABLE_OR_MISMATCH'}


def verify_case_events(entries, case_id, *, brand='aurora'):
    """Verify the persisted, app-owned create→approve transition without exposing PII."""
    require(UUID.fullmatch(str(case_id)) is not None,'CASE_ID_INVALID')
    require(isinstance(entries,list) and len(entries)<=200000,'LEDGER_SHAPE_INVALID')
    selected=[]
    for row in entries:
        require(isinstance(row,dict) and row.get('brand')==brand and row.get('action') in ('created','approved'),
                'LEDGER_CORRUPT_OR_CROSSTENANT')
        if row.get('id')==case_id:selected.append(row)
    require(len(selected)==2,'CASE_AUDIT_EVENTS_INCOMPLETE')
    created,approved=selected
    require(created['action']=='created' and approved['action']=='approved','CASE_AUDIT_EVENT_ORDER_INVALID')
    require(isinstance(created.get('actor'),str) and HASH.fullmatch(created['actor']) and
            isinstance(approved.get('actor'),str) and HASH.fullmatch(approved['actor']) and
            created['actor']!=approved['actor'],'CASE_AUDIT_ACTOR_BINDING_INVALID')
    require(approved.get('assurance')=='WSO2_SIGNED_TOTP_STEP_UP' and
            type(approved.get('authTime')) is int and approved['authTime']>0,
            'CASE_AUDIT_ASSURANCE_INVALID')
    from datetime import datetime,timezone
    try:
        times=[datetime.fromisoformat(x['at'].replace('Z','+00:00')) for x in selected]
        require(all(t.tzinfo is not None for t in times) and times[0]<=times[1],
                'CASE_AUDIT_TIME_INVALID')
    except (TypeError,KeyError,ValueError,AttributeError):
        raise Blocked('CASE_AUDIT_TIME_INVALID') from None
    return {'outcome':'PASS','eventCount':2,'transition':'OPEN_TO_APPROVED',
            'actorBinding':'DISTINCT_HASHED_SUBJECTS','assurance':'WSO2_SIGNED_TOTP_STEP_UP',
            'evidenceClass':'LIVE_READBACK'}


def read_ledger(root, brand='aurora'):
    root=Path(root)
    require(root.is_dir() and not root.is_symlink(),'LEDGER_DIRECTORY_UNAVAILABLE')
    path=root/('requests-'+brand+'.jsonl')
    require(not path.is_symlink() and path.is_file(),'LEDGER_FILE_UNAVAILABLE')
    st=path.stat()
    require(st.st_uid==os.getuid() and stat.S_ISREG(st.st_mode) and
            (stat.S_IMODE(st.st_mode)&0o077)==0 and st.st_size<=10*1024*1024,
            'LEDGER_FILE_UNSAFE')
    try:
        return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines() if x]
    except (ValueError,UnicodeError,OSError):
        raise Blocked('LEDGER_CORRUPT') from None


def discover_ledger(home, explicit=None):
    """Bounded, no-symlink search of the existing private runtime (no credentials read)."""
    home=Path(home)
    require(home.is_dir() and not home.is_symlink(),'PRIVATE_RUNTIME_UNAVAILABLE')
    if explicit:
        path=Path(explicit)
        require(path.is_absolute() and not path.is_symlink(), 'LEDGER_OVERRIDE_UNSAFE')
        return path
    candidates=[];count=0
    for current, dirs, files in os.walk(home,followlinks=False):
        count+=1
        if count>500:raise Blocked('LEDGER_DISCOVERY_LIMIT')
        rel=Path(current).relative_to(home)
        if len(rel.parts)>=5:dirs[:]=[]
        else:dirs[:]=[d for d in dirs if not (Path(current)/d).is_symlink()]
        if 'requests-aurora.jsonl' in files:
            candidates.append(Path(current))
    require(len(candidates)==1,'LEDGER_DIRECTORY_NOT_UNAMBIGUOUS')
    return candidates[0]
