#!/usr/bin/env python3
"""P2.24 v47: version-pinned, read-only readiness assessment for delegated admin.

No WSO2 configuration, SCIM, role, journal or git writes. One OAuth token POST
issues a short-lived access token; only GETs are sent with that token.
This does not claim to have provisioned a human administrator or the UI.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import sys
import urllib.error
import urllib.request

TENANT = 'aurora.identity.test'
V46_SHA = '1532362736215824dfb730f76863f2d90c6b0c7a1837c40979359a0f50e9ce92'
GOOD_DENIAL = {401, 403}
APPROVED_FRAMEWORKS = ('react','vite','next','express','fastify','koa','react-router','@vitejs/plugin-react')
IGNORE_DIRS = {'.git','node_modules','dist','build','coverage','.next','.venv','venv',
               'private','.cache','__pycache__','target','tmp','vendor'}

class Blocked(Exception): pass

def need(ok, msg):
    if not ok: raise Blocked(msg)

def import_verified(path: Path, digest: str, name: str):
    need(path.is_file() and not path.is_symlink(), 'PINNED_V46_MODULE_UNAVAILABLE')
    need(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'PINNED_V46_MODULE_CHANGED')
    spec=importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, 'PINNED_V46_IMPORT_UNAVAILABLE')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def classify_denial(status):
    if status in GOOD_DENIAL: return 'EXPLICITLY_DENIED'
    if status == 200: return 'BOUNDARY_VIOLATION_GET_SUCCEEDED'
    return 'INCONCLUSIVE'

def get_bearer_status(token: str, url_path: str, cafile: Path):
    need(type(token) is str and len(token) >= 25 and not any(c.isspace() for c in token),
         'TOKEN_SHAPE_INVALID')
    need(url_path.startswith(f'/t/{TENANT}/') and '..' not in url_path and
         '?' in url_path and not any(x in url_path for x in ('#','\\','%')),
         'READ_ONLY_PROBE_URL_INVALID')
    ctx=ssl.create_default_context(cafile=str(cafile))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx),NoRedirect())
    req=urllib.request.Request('https://localhost:9444'+url_path,
          method='GET',headers={'Authorization':'Bearer '+token,
                 'Accept':'application/json','Cache-Control':'no-store'})
    try:
        with opener.open(req, timeout=12) as res:
            status=res.status
            res.read(1)
    except urllib.error.HTTPError as err:
        status=err.code
        err.close()
    except Exception:
        return {'httpStatus': None, 'classification': 'INCONCLUSIVE'}
    return {'httpStatus':status,'classification':classify_denial(status)}

def role_resources(rows):
    need(isinstance(rows,list), 'API_CATALOG_INVALID')
    results=[]
    ids=set()
    for row in rows:
        if type(row) is not dict: continue
        ident=row.get('identifier','')
        rid=row.get('id','')
        if not isinstance(ident,str) or not isinstance(rid,str): continue
        path=ident.split('?')[0].rstrip('/')
        if re.search(r'/o/scim2/(?:v2/)?Roles$',path):
            need(rid not in ids, 'DUPLICATE_ROLE_API_RESOURCE')
            ids.add(rid)
            results.append({'id':rid,'pathFlavor':'organization-scim2-roles'})
    return results

def inventory(repo: Path):
    packages=[]; source=[]
    repo=repo.resolve(strict=True)
    for base, dirs, files in os.walk(repo, followlinks=False):
        root=Path(base)
        depth=len(root.relative_to(repo).parts)
        dirs[:]=sorted(d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.') and depth < 6)
        if depth > 6: continue
        if 'package.json' in files and len(packages)<18:
            path=root/'package.json'
            if path.is_symlink() or path.stat().st_size > 262144: continue
            try:
                doc=json.loads(path.read_text(encoding='utf-8'))
                if not isinstance(doc,dict): continue
            except Exception: continue
            deps={**(doc.get('dependencies') or {}),**(doc.get('devDependencies') or {})}
            if not isinstance(deps,dict): deps={}
            packages.append({'path':path.relative_to(repo).as_posix(),
                  'frameworkDependencies':[x for x in APPROVED_FRAMEWORKS if x in deps],
                  'scriptNames':sorted(x for x in (doc.get('scripts') or {}) if isinstance(x,str))[:16]})
        for filename in sorted(files):
            if len(source)>=40: break
            if not filename.endswith(('.tsx','.jsx','.ts','.js','.py')): continue
            if not any(k in filename.lower() for k in ('experience','ciam','partner','admin','route','auth','server','api','app')): continue
            path=root/filename
            if path.is_symlink() or path.stat().st_size>524288: continue
            source.append(path.relative_to(repo).as_posix())
    return {'packageManifests':packages,'likelyIntegrationFiles':source,
            'repositoryInventoryReadOnly':True}

def main(argv):
    need(argv==['audit'], 'AUDIT_ONLY')
    repo=Path.cwd().resolve(strict=True)
    need((repo/'scripts/ciam-v10.sh').is_file(), 'MUST_RUN_FROM_PROJECT_ROOT')
    base=Path(__file__).resolve().with_name('verify.py')
    v46=import_verified(base,V46_SHA,'p224_v47_pinned_v46')
    # Full partner directory readback first. No management writes.
    proof=v46.main(['audit'])
    need(proof.get('status')=='VERIFIED' and
         proof.get('code')=='P2_24_PARTNER_DIRECTORY_LIVE_READBACK_VERIFIED' and
         proof.get('disabledUsersVerified')==2 and proof.get('groupsVerified')==2 and
         proof.get('exactMembershipsVerified')==2 and
         proof.get('actorSharedExclusivelyWithPartner') is True,
         'V46_LIVE_DIRECTORY_EVIDENCE_NOT_EXACT')
    source=repo/'scripts/p2/p2_24_v36_full_automatic_directory_bootstrap.py'
    impl=v46.load_module(source)
    ctx=impl.context()
    api=v46.OnlyGet(impl.Api(ctx))
    catalog=impl.catalog_rows(api)
    candidates=role_resources(catalog)
    org_roles=[]
    for row in candidates:
        rid=row['id']
        detail=api.get(impl.API_PATH+'/'+rid)
        scopes=api.get(impl.API_PATH+'/'+rid+'/scopes')
        need(type(detail) is dict and detail.get('id')==rid and type(scopes) is list and
             type(detail.get('scopes')) is list,
             'ORG_ROLES_CATALOG_SHAPE_INVALID')
        names=[x.get('name') for x in scopes if type(x) is dict]
        details=[x.get('name') for x in detail['scopes'] if type(x) is dict]
        need(len(names)==len(scopes) and len(details)==len(detail['scopes']) and
             len(names)==len(set(names)) and set(names)==set(details),
             'ORG_ROLES_CATALOG_DETAIL_DISAGREEMENT')
        org_roles.append({'resourceIdentifier':'/o/scim2/v2/Roles or /o/scim2/Roles',
             'advertisedRoleScopes':sorted(s for s in names if type(s) is str and s.startswith('internal_org_role_')),
             'otherScopesCount':len([s for s in names if not (type(s) is str and s.startswith('internal_org_role_'))])})
    v18=ctx['v18']; store=impl.Store(ctx['private']/impl.JOURNAL)
    need(store.doc is not None and store.doc.get('partnerId')==ctx['partner'] and
         store.doc.get('actorRecordCreated') is True, 'ACTOR_OWNERSHIP_NOT_VERIFIED')
    actor=ctx['m'].read_json_private(ctx['private']/v18.ACTOR_FILE)
    client,secret=v18.actor_check(ctx['m'],ctx['http'],ctx['admin'],actor,ctx['partner'])
    token=v18.actor_token(ctx['ca'],ctx['partner'],client,secret)
    # Negative-control probes use partner OAuth token but request ROOT-tenant APIs.
    # Do not assert cross-partner isolation: a second partner is not independently known.
    denial={
       'rootScimUsers':get_bearer_status(token,f'/t/{TENANT}/scim2/Users?count=1',ctx['ca']),
       'rootOrganizationManagement':get_bearer_status(token,f'/t/{TENANT}/api/server/v1/organizations?limit=1',ctx['ca'])
    }
    inventory_evidence=inventory(repo)
    critical = any(x['classification'] == 'BOUNDARY_VIOLATION_GET_SUCCEEDED' for x in denial.values())
    return {'status':'BLOCKED' if critical else 'INSPECTED',
          'code':'PARTNER_ACTOR_ROOT_API_ACCESS_BOUNDARY_VIOLATION' if critical else 'P2_24_DELEGATED_ADMIN_READINESS_RECORDED',
          'phase':'P2.24','tenant':TENANT,
          'priorDirectoryEvidence':'P2_24_PARTNER_DIRECTORY_LIVE_READBACK_VERIFIED',
          'humanDelegatedAdministratorVerified':False,
          'partnerLoginVerified':False,'businessAuthorizationVerified':False,
          'crossPartnerMutationDenialVerified':False,
          'rootReadDenialControls':denial,
          'organizationRoleApiCatalog':org_roles,
          'organizationRoleApiCandidateCount':len(org_roles),
          'currentActorScopeCount':len(v18.SCOPES),
          'existingDirectoryActorScopeUpgradeAttempted':False,
          'businessApplicationRoleSharing':'NONE_LAST_VERIFIED',
          'experienceCenterIntegration':inventory_evidence,
          'wso2ManagementWritesAttempted':0,'scimWritesAttempted':0,
          'journalWritesAttempted':0,'gitChangesAttempted':False,
          'tokenIssuedForReadOnlyProbe':True}

if __name__=='__main__':
    try: result=main(sys.argv[1:]);code=0
    except Blocked as exc:
        result={'status':'BLOCKED','code':str(exc),'phase':'P2.24',
                'managementWritesAttempted':0,'scimWritesAttempted':0};code=2
    except Exception as exc:
        safe=str(exc)
        result={'status':'BLOCKED','code':'DEPENDENCY_OR_READBACK_FAILED',
                'exceptionClass':type(exc).__name__,
                'safeDependencyCode':safe if re.fullmatch('[A-Z0-9_]{4,110}',safe) else 'REDACTED',
                'phase':'P2.24','managementWritesAttempted':0,'scimWritesAttempted':0};code=3
    print(json.dumps(result,indent=2,sort_keys=True),flush=True)
    raise SystemExit(code)
