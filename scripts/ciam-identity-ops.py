#!/usr/bin/env python3
"""Safe, read-only identity inventory and private clipboard password helper.

Never prints secrets or raw journals; inventory is a source+local-journal report,
not a substitute for live browser acceptance or remote SCIM readback.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone

BRANDS = {'aurora': 'aurora.identity.test', 'brisa': 'brisa.identity.test'}
PROFILE = 'https://api.ciam-v10.test/profile'
BUSINESS = 'urn:ciampoc:service-requests:v1'
ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home() / 'wso2-ciam-v10')))
PRIVATE = ROOT / 'private'
SEED = Path('deploy/ciam-v10/identities/seed.json')
DESIRED = Path('deploy/ciam-v10/phase4/desired.json')

class Refuse(Exception): pass


def private(name, required=True):
    p = PRIVATE / name
    if p.is_symlink() or (p.exists() and not p.is_file()):
        raise Refuse('PRIVATE_PATH_UNSAFE_'+name)
    if not p.exists():
        if required: raise Refuse('PRIVATE_FILE_MISSING_'+name)
        return None
    s = p.stat()
    if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600:
        raise Refuse('PRIVATE_MODE_OR_OWNER_UNSAFE_'+name)
    try: return json.loads(p.read_text())
    except (ValueError, UnicodeError): raise Refuse('PRIVATE_JSON_INVALID_'+name) from None


def source(path):
    if path.is_symlink() or not path.is_file(): raise Refuse('SOURCE_FILE_MISSING_'+path.name)
    try: return json.loads(path.read_text())
    except ValueError: raise Refuse('SOURCE_JSON_INVALID_'+path.name) from None


def safe(s):
    # No Markdown tables or control characters injected by arbitrary journal data.
    value = str(s)
    if len(value)>160 or not re.fullmatch(r'[\w\s.\-:/@()+,]+',value,flags=re.UNICODE):
        raise Refuse('UNSAFE_INVENTORY_TEXT')
    return value


def copy_password(args):
    if args.kind == 'super':
        if args.tenant or args.user: raise Refuse('SUPER_DOES_NOT_TAKE_TENANT_OR_USER')
        data = private('admin.private.json')
        if data.get('username') != 'admin': raise Refuse('SUPER_ADMIN_IDENTITY_MISMATCH')
        user, password = 'admin (carbon.super)', data.get('password')
    elif args.kind == 'owner':
        if not args.tenant or args.user: raise Refuse('OWNER_REQUIRES_TENANT_ONLY')
        data = private('bootstrap-tenants-v10.private.json')['tenants'][args.tenant]
        if data.get('status') != 'readback-verified': raise Refuse('OWNER_NOT_VERIFIED')
        obj = data.get('owner', {})
        if obj.get('username') != 'labtenantadmin': raise Refuse('OWNER_IDENTITY_MISMATCH')
        user, password = f"labtenantadmin@{BRANDS[args.tenant]}", obj.get('password')
    elif args.kind == 'foundation':
        if not args.tenant or args.user: raise Refuse('FOUNDATION_REQUIRES_TENANT_ONLY')
        obj = private('bootstrap-resources-v10.private.json')['tenants'][args.tenant]['user']
        if obj.get('state') != 'verified-browser-not-tested': raise Refuse('FOUNDATION_USER_NOT_VERIFIED')
        if obj.get('username') != 'ciam_'+args.tenant: raise Refuse('FOUNDATION_NAME_DRIFT')
        user, password = obj['username'], obj.get('password')
    else:
        if not args.tenant or not args.user: raise Refuse('PERSON_REQUIRES_TENANT_AND_USER')
        seed = source(SEED)
        candidates = [p for p in seed.get('people', [])
                      if args.tenant in p.get('brands', ()) and args.user in (p.get('key'),p.get('username'))]
        if len(candidates) != 1: raise Refuse('PERSON_NOT_FOUND_IN_SEED')
        actor = candidates[0]
        obj = private('bootstrap-identities-v10.private.json')['tenants'][args.tenant]['users'].get(actor['key'])
        if not isinstance(obj, dict) or obj.get('state') != 'verified' or obj.get('username') != actor['username']:
            raise Refuse('PERSON_JOURNAL_NOT_VERIFIED')
        user, password = obj['username'], obj.get('password')
    if not isinstance(password,str) or len(password)<12:
        raise Refuse('PASSWORD_MISSING_OR_INVALID')
    if sys.platform != 'darwin': raise Refuse('PB_COPY_REQUIRES_MACOS')
    subprocess.run(['pbcopy'], input=password, text=True, check=True)
    print(f'COPIED_TO_CLIPBOARD: {safe(user)}')
    print('VALUE_NOT_PRINTED; paste into the matching WSO2 login, then clear with: printf "" | pbcopy')


def inventory(args):
    seed = source(SEED)
    desired = source(DESIRED)
    ts = private('bootstrap-tenants-v10.private.json')
    foundation = private('bootstrap-resources-v10.private.json')
    oidc = private('bootstrap-oidc-v10.private.json')
    identities = private('bootstrap-identities-v10.private.json')
    business = private('bootstrap-business-v4.private.json')
    authority = private('bootstrap-authority-v10.private.json')
    adm = private('admin.private.json')
    if adm.get('username')!='admin' or authority.get('roleApiVersion')!='v2':
        raise Refuse('SUPER_OR_ROLE_API_PIN_DRIFT')
    if ts.get('domains')!=BRANDS or desired.get('businessApi',{}).get('identifier')!=BUSINESS:
        raise Refuse('DOMAIN_OR_API_SPEC_DRIFT')
    people = seed.get('people',[])
    if len(people)!=6: raise Refuse('SEED_PEOPLE_COUNT_DRIFT')
    if len({p['key'] for p in people}) != len(people):
        raise Refuse('DUPLICATE_SEED_PEOPLE')
    lines = [
      '# CIAM v5 — tenant/application/identity inventory', '',
      f'> Generated locally {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} using source manifests and private bootstrap journals. **No passwords, client secrets, or tokens are written.**',
      '> Journal status is provisioning evidence, not a live remote SCIM read or authenticated browser test.', '',
      '## Carbon Super (`carbon.super`)', '',
      '- **Role:** WSO2 server super tenant; not Aurora or Brisa and not a customer website.',
      '- **Super administrator:** `admin` configured by the private `[super_admin]` deployment setting; the password is in `~/wso2-ciam-v10/private/admin.private.json`.',
      '- **Provisioning responsibility:** root tenant creation via `/api/server/v1/tenants` and owner setup. Tenant APIs and SCIM roles are then administered using tenant-qualified accounts.',
      '- **Shared runtime:** one `wso2/wso2is:7.3.0` container, PostgreSQL identity/shared/agent databases, and the common TLS endpoint on `https://localhost:9444`.',
      '- **Important:** this source/journal inventory does *not* enumerate arbitrary applications, service accounts, system roles or APIs that may exist in Carbon Super. A read-only live Carbon audit is required to claim a complete super-tenant catalog.',
      '- **Consumer logins:** none of the four demo OIDC clients belongs to Carbon Super; their applications are tenant-local.', '',
      '## Tenants and tenant-local resources', ''
    ]
    if any(p.get('brands') and not set(p['brands']).issubset(BRANDS) for p in people):
        raise Refuse('UNKNOWN_PERSON_TENANT')
    for brand,domain in BRANDS.items():
        node=ts['tenants'][brand]
        if node.get('domain')!=domain or node.get('status')!='readback-verified': raise Refuse('TENANT_JOURNAL_NOT_VERIFIED_'+brand)
        if node.get('owner',{}).get('username')!='labtenantadmin': raise Refuse('TENANT_OWNER_MISMATCH_'+brand)
        found_id=identities['tenants'][brand]['users']
        found_business=business['tenants'][brand]
        lines += [f'### {brand.title()} — `{domain}`', '',
          f'- **Owner:** `labtenantadmin@{domain}` (tenant admin, distinct from Carbon Super admin).',
          f'- **Bootstrap SCIM user:** `ciam_{brand}` (non-super support/test identity).',
          f'- **Management M2M application:** `{safe(foundation["tenants"][brand]["management"]["name"])}` (tenant-local; used for authorized management/SCIM scope operations, not a customer login).',
          f'- **Profile API resource:** `{PROFILE}`; `ciam:profile:read`.',
          f'- **Business API resource:** `{BUSINESS}`; `ciam:cases:create`, `ciam:cases:read`, `ciam:cases:review`, `ciam:cases:approve`.',
          '- **Business case data:** BFF JSONL records tagged by brand; not a WSO2 user table.', '',
          '| OIDC channel | WSO2 application name | BFF client key | Callback |',
          '|---|---|---|---|']
        for channel,display in (('web','Web'),('app','Mobile browser')):
            app = oidc['tenants'][brand]['clients'][channel]
            if app.get('state')!='verified':raise Refuse('OIDC_NOT_VERIFIED_'+brand+'_'+channel)
            lines.append(f'| {display} | {safe(app["name"])} | `{brand}-{channel}` | `{safe(app["callback"])}` |')
        lines += ['', '| Seeded person | Username | Persona category | SCIM journal state |', '|---|---|---|---|']
        for p in people:
            if brand not in p['brands']:continue
            u = found_id.get(p['key'])
            if not isinstance(u,dict) or u.get('username')!=p['username']:
                raise Refuse('SEED_JOURNAL_USER_DRIFT_'+brand)
            lines.append('| '+ ' | '.join((safe(p['givenName']+' '+p['familyName']),
                          f'`{safe(p["username"])}`',safe(p['type']),safe(u.get('state','unknown')))) + ' |')
        lines += ['', '**Application-scoped roles and permission membership**', '',
            '| Application | Role | Members (usernames) | Scopes / permissions | State |',
            '|---|---|---|---|---|']
        roles = identities['tenants'][brand].get('roles',{})
        b_roles = found_business.get('roles',{})
        for channel in ('web','app'):
            appkey=f'{brand}-{channel}'
            for kind,label in seed.get('roleLabels',{}).items():
                members = [p['username'] for p in people if brand in p['brands'] and p['type']==kind]
                if not members:continue
                r=roles.get(channel+':'+kind, {})
                if not r: raise Refuse('BASE_ROLE_JOURNAL_MISSING_'+brand)
                perms=seed.get('implementedPermissionAssignments',{}).get(kind,[])
                lines.append(f'| `{appkey}` | `{safe(r["name"])}` | {", ".join("`"+safe(m)+"`" for m in members)} | {", ".join("`"+safe(x)+"`" for x in perms) if perms else "None (not an authorization grant)"} | {safe(r.get("state","unknown"))} |')
            for kind,perms in desired['businessApi']['rolePermissions'].items():
                members=[p['username'] for p in people if brand in p['brands'] and p['type']==kind]
                if not members:continue
                r=b_roles.get(channel+':'+kind, {})
                if not r:raise Refuse('BUSINESS_ROLE_JOURNAL_MISSING_'+brand)
                name='CIAM Business '+kind.title()+' '+channel.upper()
                lines.append(f'| `{appkey}` | `{name}` | {", ".join("`"+safe(m)+"`" for m in members)} | {", ".join("`"+safe(x)+"`" for x in perms)} | {safe(r.get("state","unknown"))} |')
        lines += ['', f'**API and application relationship:** both `{brand}-web` and `{brand}-app` are explicitly authorized to consume the profile and business resources in the **{domain}** tenant. WSO2 still decides token scopes from memberships and authorization; the BFF checks live audience and scope per call.', '']
    lines += ['## Distinctions not to collapse', '',
      '- A tenant owner, a management M2M OAuth app, and an application-scoped business administrator role are **three different authorities**.',
      '- Ana in Aurora and Ana in Brisa are **two separately provisioned WSO2 tenant accounts**, not a shared cross-tenant session or linked subject.',
      '- The same human may be a member of both Web and Mobile app roles; these are still separate OIDC applications with distinct client IDs and token audience policies.',
      '- Application roles are not equivalent to the `roles` claim in an ID token. Browser UI renders role names only when WSO2 releases the claim.',
      '- OAuth access-token audience is checked independently of `ciam:*` scopes; the four OIDC clients were configured for both profile and business audiences and each passed a positive browser read/isolation test on 2026-10-28.',
      '- Consent preference APIs, B2B child-organization delegation, successful TOTP approval, and production native-mobile SDK behavior remain unverified.',
      '- Inventory above comes from source and private journals; run the explicit management API verify steps in the E2E guide for a fresh remote readback.', '']
    text='\n'.join(lines)+'\n'
    if args.output:
        out=Path(args.output)
        if out.is_symlink(): raise Refuse('OUTPUT_SYMLINK_REFUSED')
        out.parent.mkdir(parents=True,exist_ok=True)
        if out.exists() and out.read_text()==text:
            print('INVENTORY_UNCHANGED:',out)
        else:
            out.write_text(text)
            print('INVENTORY_GENERATED:',out)
    else:
        print(text)
    print('SECRETS_EXPORTED: 0')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    sub=ap.add_subparsers(dest='command', required=True)
    p=sub.add_parser('password',help='Copy one private WSO2 credential to macOS clipboard')
    p.add_argument('--kind',choices=['person','owner','foundation','super'],default='person')
    p.add_argument('--tenant',choices=list(BRANDS))
    p.add_argument('--user',help='seed key or username, required for kind=person')
    p=sub.add_parser('inventory',help='Write sanitized source+journal inventory')
    p.add_argument('--output',help='Markdown output path (review before git commit)')
    args=ap.parse_args()
    try:
        if args.command=='password':copy_password(args)
        else:inventory(args)
    except (Refuse,KeyError,TypeError,ValueError,FileNotFoundError,subprocess.CalledProcessError) as e:
        print('REFUSED:',str(e) if isinstance(e,Refuse) else type(e).__name__,file=sys.stderr)
        sys.exit(2)

if __name__=='__main__':main()
