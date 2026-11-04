#!/usr/bin/env python3
"""P2.24 v36: guarded API-only Aurora directory M2M + partner users/groups bootstrap.

Commands:
  audit
  bootstrap 'BOOTSTRAP AURORA DIRECTORY M2M AND DISABLED USERS'

This script NEVER upgrades WSO2, deletes anything, or repeats an uncertain write.
It builds on the source-verified v17/v18 and v32 context. All secrets are stored
only in an owner-only private journal. No credentials are printed.

Requires the *existing* v32 helper at ~/Downloads/p2_24_v32_partner_actor.py.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

TENANT='aurora.identity.test'
NAME='P2 Aurora Returns Partner Directory M2M'
BASE='https://localhost:9444'
PREFIX=f'/t/{TENANT}/api/server/v1'
APP_PATH=PREFIX+'/applications'
API_PATH=PREFIX+'/api-resources'
JOURNAL='p2-aurora-directory-m2m-v33.private.json' # Preserve existing one-attempt recovery journal
APPROVAL='BOOTSTRAP AURORA DIRECTORY M2M AND DISABLED USERS'
V32_SHA='c3b769bfb9046c585724492e3c0e316f728b980e5fac3bdaed009e48c4bf24c2'
UUID=re.compile(r'^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')
FIVE_SCOPES=tuple(sorted(('internal_org_user_mgt_create','internal_org_user_mgt_list',
        'internal_org_user_mgt_view','internal_org_group_mgt_create','internal_org_group_mgt_view')))


class Block(Exception): pass

def need(ok,code):
    if not ok:raise Block(code)

def report(code,status='BLOCKED',**kw):
    print(json.dumps(dict(phase='P2.24',tenant=TENANT,code=code,status=status,
               sharingPostRetried=False,versionUpgradeAttempted=False,**kw),
               indent=2,sort_keys=True),flush=True)

def imported(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    need(spec is not None and spec.loader is not None,'DEPENDENCY_IMPORT_UNAVAILABLE')
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def context():
    p=pathlib.Path.home()/'Downloads'/'p2_24_v32_partner_actor.py'
    need(p.is_file() and not p.is_symlink() and
         hashlib.sha256(p.read_bytes()).hexdigest()==V32_SHA,'EXACT_V32_DEPENDENCY_REQUIRED')
    v32=imported(p,'p224_v33_v32')
    repo,private,v18,m,http,admin,partner=v32.context()
    v17=v18.load_v17(repo)
    _,_,_,_,v14,business,partner2,root=v17.runtime(repo,private)
    need(partner==partner2 and v17.reconcile_snapshot(m,http,admin,v14,business,partner,root)=='EXACT',
         'ROOT_PARTNER_BUSINESS_SHARE_NOT_EXACT')
    need(isinstance(admin,m.AuthorityBasic) and isinstance(admin._header,str) and
         m._approved_basic_header(admin._header),'AURORA_AUTHORITY_NOT_VERIFIED')
    ca=private/'p2-local-wso2-tls-pinned.pem'
    need(m.safe_private_file(ca,required=True),'PINNED_TLS_NOT_VERIFIED')
    need(private.is_dir() and not private.is_symlink(),'PRIVATE_DIRECTORY_NOT_VERIFIED')
    need((private.stat().st_mode & 0o077)==0,'PRIVATE_DIRECTORY_MUST_BE_0700')
    return dict(v32=v32,repo=repo,private=private,v18=v18,m=m,http=http,
                admin=admin,partner=partner,root=root,v17=v17,v14=v14,ca=ca)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class Api:
    def __init__(self,ctx):
        self.header=ctx['admin']._header
        handler=urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ctx['ca'])))
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),handler,NoRedirect())
    def call(self,method,path,body=None):
        need(method in ('GET','POST','PUT') and path.startswith(PREFIX+'/'), 'HTTP_METHOD_OR_BOUNDARY_BLOCKED')
        need(path.split('?')[0].startswith((APP_PATH,API_PATH)), 'HTTP_RESOURCE_BOUNDARY_BLOCKED')
        if method!='GET':
            need((method=='POST' and (path==APP_PATH or path.endswith('/authorized-apis') or
                         path==APP_PATH+'/share')) or
                 (method=='PUT' and path.endswith('/inbound-protocols/oidc')),
                 'UNAPPROVED_MANAGEMENT_MUTATION')
        data=json.dumps(body,separators=(',',':')).encode() if body is not None else None
        headers={'Authorization':self.header,'Accept':'application/json','Cache-Control':'no-cache'}
        if data is not None:headers['Content-Type']='application/json'
        req=urllib.request.Request(BASE+path,data=data,headers=headers,method=method)
        try:
            with self.opener.open(req,timeout=18) as res:
                status,raw,h=res.status,res.read(131073),res.headers
        except urllib.error.HTTPError as ex:
            status,raw,h=ex.code,ex.read(131073),ex.headers
        except Exception:
            raise Block('HTTP_OUTCOME_UNKNOWN_NO_AUTOMATIC_RETRY') from None
        need(len(raw)<=131072,'HTTP_RESPONSE_OVERSIZE')
        obj=None
        if raw:
            try: obj=json.loads(raw)
            except (ValueError,UnicodeError): obj=None
        return status,obj,h
    def get(self,path):
        status,doc,_=self.call('GET',path)
        need(status==200,'GET_HTTP_NOT_200')
        return doc

class Store:
    def __init__(self,path):
        self.path=path
        self.doc=None
        if path.exists() or path.is_symlink():
            s=path.lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and
                 stat.S_IMODE(s.st_mode)==0o600,'M2M_JOURNAL_PERMISSIONS_INVALID')
            self.doc=json.loads(path.read_text(encoding='utf-8'))
            need(type(self.doc)==dict and self.doc.get('schema')=='p2.24.directory-m2m.v33' and
                 self.doc.get('tenant')==TENANT and type(self.doc.get('attempts')) is dict,
                 'M2M_JOURNAL_FORMAT_INVALID')
    def create(self,partner):
        need(self.doc is None,'M2M_JOURNAL_ALREADY_EXISTS')
        self.doc={'schema':'p2.24.directory-m2m.v33','tenant':TENANT,'partnerId':partner,
                  'name':NAME,'clientId':'p224_'+secrets.token_urlsafe(22),
                  'clientSecret':secrets.token_urlsafe(48),'applicationId':None,'attempts':{},
                  'actorRecordCreated':False}
        old=os.umask(0o077)
        try:
            fd=os.open(str(self.path),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                json.dump(self.doc,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
        finally:os.umask(old)
    def save(self):
        need(self.doc is not None,'M2M_JOURNAL_MISSING')
        fd,tmp=tempfile.mkstemp(prefix='.m2m-v33-',dir=self.path.parent)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                json.dump(self.doc,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
            os.replace(tmp,self.path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    def attempt(self,stage,method,path,api,body,accepted):
        need(self.doc and stage not in self.doc['attempts'],
             'PREVIOUS_WRITE_INTENT_PRESENT_NO_RETRY_'+stage)
        self.doc['attempts'][stage]={'state':'INTENT','method':method,'path':path}
        self.save()   # durable BEFORE sending the management request
        status,obj,headers=api.call(method,path,body)
        self.doc['attempts'][stage]['httpStatus']=status
        self.doc['attempts'][stage]['state']='ACKNOWLEDGED' if status in accepted else 'RESPONSE_REQUIRES_REVIEW'
        self.save()
        need(status in accepted,'MANAGEMENT_RESPONSE_NOT_ACCEPTED_NO_RETRY_'+stage)
        return obj,headers
    def done(self,stage):
        need(stage in self.doc['attempts'],'UNOWNED_RESOURCE_CANNOT_ADOPT_'+stage)
        self.doc['attempts'][stage]['state']='VERIFIED';self.save()

def app_candidates(ctx):
    return ctx['v32'].query_candidates(ctx['http'],ctx['admin'])

class CatalogError(Block):
    def __init__(self, code, evidence=None):
        super().__init__(code)
        self.evidence = evidence or {}


def catalog_need(condition, code, evidence):
    if not condition:
        raise CatalogError(code, evidence)


def safe_next_catalog_path(href, current):
    """Accept only an after cursor for this tenant's resource collection.

    Never follow an arbitrary URL returned in a link or send credentials elsewhere.
    """
    parsed = urllib.parse.urlsplit(href)
    need(not parsed.fragment and not parsed.username and not parsed.password,
         'CATALOG_PAGINATION_LINK_INVALID')
    need((not parsed.scheme and not parsed.netloc) or
         (parsed.scheme == 'https' and parsed.hostname == 'localhost' and
          parsed.port == 9444), 'CATALOG_PAGINATION_CROSS_ORIGIN_BLOCKED')
    expected_paths={API_PATH, '/api/server/v1/api-resources'}
    need(parsed.path in expected_paths, 'CATALOG_PAGINATION_PATH_INVALID')
    params=urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    need(set(params).issubset({'after','limit'}) and len(params.get('after',[]))==1 and
         1<=len(params['after'][0])<=1024, 'CATALOG_PAGINATION_CURSOR_INVALID')
    # Reconstruct from a validated opaque cursor rather than trusting the href.
    return API_PATH + '?limit=100&after=' + urllib.parse.quote(params['after'][0],safe='')


def catalog_rows(api):
    """Read a complete WSO2 APIResources collection, bounded and cursor-safe."""
    path = API_PATH + '?limit=100'
    seen_paths=set(); ids=set(); all_rows=[]; total=None
    while len(seen_paths)<25:
        need(path not in seen_paths,'API_RESOURCE_PAGINATION_LOOP_BLOCKED')
        seen_paths.add(path)
        doc=api.get(path)
        evidence={'pagesRead':len(seen_paths),'rowsSoFar':len(all_rows),
                  'responseShape':type(doc).__name__}
        catalog_need(type(doc)==dict,'API_RESOURCE_COLLECTION_INVALID',evidence)
        evidence['responseKeys']=sorted(k for k in doc if isinstance(k,str))[:20]
        keys=[k for k in ('APIResources','apiResources','resources') if k in doc]
        evidence['recognizedCollectionKeys']=keys
        catalog_need(len(keys)==1,'API_RESOURCE_COLLECTION_KEY_UNRECOGNIZED',evidence)
        page=doc[keys[0]]
        n=doc.get('totalResults')
        evidence['pageRowCount']=len(page) if type(page)==list else None
        evidence['totalResults']=n if type(n)==int else None
        catalog_need(type(page)==list and type(n)==int and 0<=n<=10000,
                     'API_RESOURCE_COLLECTION_INVALID',evidence)
        if total is None:total=n
        catalog_need(total==n,'API_RESOURCE_TOTAL_CHANGED_WHILE_PAGING',evidence)
        catalog_need(len(all_rows)+len(page)<=total and len(all_rows)+len(page)<=10000,
                     'API_RESOURCE_COLLECTION_OVERSIZE_OR_DUPLICATE',evidence)
        for row in page:
            catalog_need(type(row)==dict,'API_RESOURCE_ROW_INVALID',evidence)
            rid=row.get('id')
            catalog_need(type(rid)==str and rid not in ids,
                         'API_RESOURCE_DUPLICATE_OR_MISSING_ID',evidence)
            ids.add(rid)
            all_rows.append(row)
        links=doc.get('links',[])
        catalog_need(type(links)==list,'API_RESOURCE_PAGINATION_LINKS_INVALID',evidence)
        evidence['linkRels']=sorted(set(str(link.get('rel')) for link in links
                                if type(link)==dict))[:20]
        forward=[link for link in links if type(link)==dict and
                 str(link.get('rel','')).lower() in ('next','after')]
        catalog_need(len(forward)<=1,'API_RESOURCE_PAGINATION_AMBIGUOUS',evidence)
        if len(all_rows)==total:
            catalog_need(not forward,'API_RESOURCE_PAGINATION_OVERFLOW',evidence)
            return all_rows
        catalog_need(len(forward)==1,'API_RESOURCE_COLLECTION_INCOMPLETE',evidence)
        href=forward[0].get('href')
        catalog_need(type(href)==str,'API_RESOURCE_PAGINATION_LINK_INVALID',evidence)
        path=safe_next_catalog_path(href,path)
    raise CatalogError('API_RESOURCE_PAGINATION_LIMIT_EXCEEDED',
                       {'pagesRead':len(seen_paths)})


def resource_discovery(api,scope_names):
    # Match the exact scoped organization APIs from a COMPLETE catalog, never a partial list.
    rows=catalog_rows(api)
    resources={}
    evidence={'catalogRows':len(rows),'apiResourcesWithRecognizedIdentifier':0,
              'candidateResourceCounts':{'Users':0,'Groups':0},
              'scopeProbeCount':0}
    for row in rows:
        rid=row.get('id')
        if not (type(rid)==str and UUID.fullmatch(rid)):
            continue
        identifier=str(row.get('identifier','')).split('?')[0].rstrip('/')
        kind=next((k for k in ('Users','Groups') if identifier.endswith('/o/scim2/'+k)),None)
        if kind is None:continue
        evidence['apiResourcesWithRecognizedIdentifier']+=1
        evidence['scopeProbeCount']+=1
        scopes=api.get(API_PATH+'/'+rid+'/scopes')
        detail=api.get(API_PATH+'/'+rid)
        catalog_need(type(scopes)==list and type(detail)==dict and
                     type(detail.get('scopes'))==list and detail.get('id')==rid,
                     'API_RESOURCE_DETAIL_OR_SCOPE_COLLECTION_INVALID',evidence)
        catalog_need(all(type(s)==dict and type(s.get('name'))==str for s in scopes) and
                     all(type(s)==dict and type(s.get('name'))==str for s in detail['scopes']),
                     'API_RESOURCE_SCOPE_SHAPE_INVALID',evidence)
        names=[s['name'] for s in scopes]
        detail_names=[s['name'] for s in detail['scopes']]
        catalog_need(len(names)==len(set(names)) and len(detail_names)==len(set(detail_names)) and
                     set(names)==set(detail_names),'API_RESOURCE_SCOPE_DETAIL_DISAGREEMENT',evidence)
        expected={s for s in scope_names if s.startswith('internal_org_'+
                          ('user' if kind=='Users' else 'group')+'_mgt_')}
        catalog_need(bool(expected) and set(names).issuperset(expected),
                     'ORGANIZATION_API_SCOPES_NOT_DISCOVERABLE',evidence)
        evidence['candidateResourceCounts'][kind]+=1
        catalog_need(kind not in resources,'AMBIGUOUS_ORGANIZATION_API_RESOURCE',evidence)
        resources[kind]=(rid,sorted(expected))
    catalog_need(set(resources)=={'Users','Groups'},
                 'TWO_ORGANIZATION_API_RESOURCES_NOT_VERIFIED',evidence)
    return resources

def app_detail(api,appid):
    doc=api.get(APP_PATH+'/'+appid)
    need(type(doc)==dict and doc.get('id')==appid and doc.get('name')==NAME and
         doc.get('isManagementApp') is True and doc.get('applicationEnabled') is not False,
         'ACTOR_APP_READBACK_NOT_EXACT')
    return doc

def oidc_state(api,app):
    status,doc,_=api.call('GET',APP_PATH+'/'+app+'/inbound-protocols/oidc')
    need(status in (200,404),'OIDC_READBACK_UNEXPECTED_HTTP')
    return doc if status==200 else None

def oidc_exact(doc,store):
    return (type(doc)==dict and doc.get('grantTypes')==['client_credentials'] and
            doc.get('publicClient') is False and doc.get('clientId')==store.doc['clientId'])

def api_authorizations(api,app):
    doc=api.get(APP_PATH+'/'+app+'/authorized-apis')
    need(type(doc)==list,'AUTHORIZED_API_LIST_INVALID')
    return doc

def authorizations_exact(rows,resources,scope_names):
    if type(rows)!=list or len(rows)!=2:return False
    pairs={}
    for row in rows:
        if type(row)!=dict or row.get('policyId',row.get('policyIdentifier'))!='RBAC':return False
        if type(row.get('authorizedScopes'))!=list:return False
        names=[x.get('name') for x in row['authorizedScopes'] if type(x)==dict]
        if not names or len(names)!=len(set(names)):return False
        pairs[row.get('id')]=set(names)
    return (len(pairs)==2 and set(pairs)=={v[0] for v in resources.values()} and
            set().union(*pairs.values())==set(scope_names) and
            all(pairs[v[0]]==set(v[1]) for v in resources.values()))

def share_exact(ctx,app):
    try:
        result=ctx['v17'].reconcile_snapshot(ctx['m'],ctx['http'],ctx['admin'],
                      ctx['v14'],app,ctx['partner'],ctx['root'])
    except Exception:return False
    return result=='EXACT'

def bootstrap(ctx,api,resources):
    store=Store(ctx['private']/JOURNAL)
    names=ctx['v18'].SCOPES
    found=app_candidates(ctx)
    need(len(found)<=1,'DUPLICATE_ACTOR_APPLICATIONS')
    if store.doc is None:
        need(not found,'EXISTING_UNOWNED_ACTOR_APP_REFUSE_AUTO_ADOPTION')
        store.create(ctx['partner'])
    need(store.doc.get('partnerId')==ctx['partner'] and store.doc.get('name')==NAME,
         'ACTOR_BOOTSTRAP_PARTNER_DRIFT')
    app=store.doc.get('applicationId')
    if not app:
        if not found:
            body={'name':NAME,'description':'P2.24 scoped Aurora partner directory operator',
                  'isManagementApp':True,'isB2BSelfServiceApp':False,'applicationEnabled':True}
            store.attempt('CREATE_APP','POST',APP_PATH,api,body,{201})
            found=app_candidates(ctx)
        need(len(found)==1 and UUID.fullmatch(str(found[0].get('applicationId',''))),
             'APP_CREATION_READBACK_NOT_EXACT_NO_POST_RETRY')
        app=found[0]['applicationId']
        store.doc['applicationId']=app;store.save()
        store.done('CREATE_APP')
    else:
        need(UUID.fullmatch(app) and len(found)==1 and found[0].get('applicationId')==app,
             'RECORDED_APP_NOT_PRESENT_OR_CHANGED')
    app_detail(api,app)
    oidc=oidc_state(api,app)
    if not oidc_exact(oidc,store):
        # A freshly created application can expose an empty/default OIDC model.
        # We may replace that model only on the application this journal created,
        # before any external API authorization, and only once.
        need('SET_OIDC' not in store.doc['attempts'],
             'OIDC_WRITE_INTENT_ALREADY_EXISTS_NO_RETRY')
        need(len(api_authorizations(api,app))==0,
             'OIDC_CHANGE_BLOCKED_APP_ALREADY_HAS_AUTHORIZATION')
        payload={'clientId':store.doc['clientId'],'clientSecret':store.doc['clientSecret'],
                 'grantTypes':['client_credentials'],'publicClient':False,
                 'callbackURLs':[],'allowedOrigins':[],'accessToken':{'type':'JWT'}}
        store.attempt('SET_OIDC','PUT',APP_PATH+'/'+app+'/inbound-protocols/oidc',api,payload,{200,201})
        oidc=oidc_state(api,app)
    need(oidc_exact(oidc,store),'OIDC_CONFIGURATION_NOT_EXACT')
    # Verify a JWT token setting if exposed; actual token must pass v18's stricter check later.
    if 'accessToken' in oidc and type(oidc['accessToken'])==dict:
        need(oidc['accessToken'].get('type')=='JWT','OIDC_TOKEN_TYPE_NOT_JWT')
    store.done('SET_OIDC') if 'SET_OIDC' in store.doc['attempts'] and store.doc['attempts']['SET_OIDC']['state']!='VERIFIED' else None
    rows=api_authorizations(api,app)
    need(all(type(r)==dict and r.get('id') in {v[0] for v in resources.values()} for r in rows),
         'PREEXISTING_UNRELATED_AUTHORIZED_API_BLOCKED')
    for kind in ('Users','Groups'):
        rid,scopes=resources[kind]
        matching=[r for r in rows if r.get('id')==rid]
        stage='AUTH_'+kind.upper()
        authorization_path=APP_PATH+'/'+app+'/authorized-apis'
        if matching:
            # Existing authorizations must be owned by this journal: do not adopt
            # unrelated permissions, even when their visible scopes happen to match.
            need(len(matching)==1 and stage in store.doc['attempts'] and
                 store.doc['attempts'][stage].get('method')=='POST' and
                 store.doc['attempts'][stage].get('path')==authorization_path and
                 store.doc['attempts'][stage].get('httpStatus') in (200,201),
                 'PREEXISTING_AUTHORIZATION_NOT_JOURNAL_OWNED')
        else:
            need(stage not in store.doc['attempts'],
                 'PREVIOUS_AUTHORIZATION_ATTEMPT_NO_POST_RETRY_'+stage)
            payload={'id':rid,'policyIdentifier':'RBAC','scopes':scopes}
            # GA may return HTTP 200 instead of the documented 201. Status alone
            # never verifies authorization; require an independent exact GET below.
            store.attempt(stage,'POST',authorization_path,api,payload,{200,201})
            rows=api_authorizations(api,app)
        matched=[r for r in rows if type(r) is dict and r.get('id')==rid]
        need(len(matched)==1 and type(matched[0].get('authorizedScopes')) is list and
             len(matched[0]['authorizedScopes'])==len(scopes) and
             all(type(x) is dict and type(x.get('name')) is str
                 for x in matched[0]['authorizedScopes']) and
             len(set(x['name'] for x in matched[0]['authorizedScopes']))==len(scopes) and
             set(x['name'] for x in matched[0]['authorizedScopes'])==set(scopes) and
             matched[0].get('policyId',matched[0].get('policyIdentifier'))=='RBAC' and
             len(rows)<=2 and
             all(type(r) is dict and r.get('id') in {v[0] for v in resources.values()}
                 for r in rows), 'AUTHORIZATION_EXACT_GET_READBACK_REQUIRED_'+stage)
        if store.doc['attempts'][stage]['state']!='VERIFIED':
            store.done(stage)
    rows=api_authorizations(api,app)
    need(authorizations_exact(rows,resources,names),'AUTHORIZED_SCOPES_NOT_EXACT')
    if not share_exact(ctx,app):
        # Do not broaden an already shared actor application. These two root GET
        # responses may be {} on GA before the first share: only tolerate that
        # ambiguous state on a uniquely v33-created app with no prior share intent.
        for suffix,field in (('/share?limit=100','organizations'),('/shared-apps','sharedApplications')):
            status,doc,_=api.call('GET',APP_PATH+'/'+app+suffix)
            need(status==200 and type(doc)==dict,'ACTOR_PRE_SHARE_READBACK_FAILED')
            rows=doc.get(field)
            need((rows is None and doc=={}) or (type(rows)==list and len(rows)==0),
                 'ACTOR_PRE_SHARE_NOT_EMPTY_OR_AMBIGUOUS')
        need(store.doc['applicationId']==app and 'CREATE_APP' in store.doc['attempts'] and
             store.doc['attempts']['CREATE_APP']['state']=='VERIFIED',
             'ACTOR_SHARE_CANNOT_USE_UNOWNED_APP')
        # A prior 202 cannot be retried: after asynchronous completion a later run
        # will pass share_exact above and continue without repeating this POST.
        need('SHARE_ACTOR' not in store.doc['attempts'],
             'ACTOR_SHARE_PREVIOUSLY_ATTEMPTED_PENDING_READBACK_NO_POST_RETRY')
        payload=ctx['v17'].body_for(app,ctx['partner'])
        store.attempt('SHARE_ACTOR','POST',APP_PATH+'/share',api,payload,{202})
    need(share_exact(ctx,app),'ACTOR_SHARE_ASYNC_PENDING_GET_ONLY_RECONCILIATION_REQUIRED')
    if 'SHARE_ACTOR' in store.doc['attempts'] and store.doc['attempts']['SHARE_ACTOR']['state']!='VERIFIED':
        store.done('SHARE_ACTOR')
    record=ctx['v32'].app_record(ctx['v18'],ctx['partner'],app,store.doc['clientId'],store.doc['clientSecret'])
    # Must prove real partner-only access before materializing v18 actor record.
    ctx['v32'].actor_proof(ctx['v18'],ctx['m'],ctx['http'],ctx['admin'],ctx['private'],ctx['partner'],record)
    actorfile=ctx['private']/ctx['v18'].ACTOR_FILE
    if not actorfile.exists():
        ctx['v32'].atomic_new_private(actorfile,record)
    else:
        need(ctx['m'].safe_private_file(actorfile,required=False) and
             ctx['m'].read_json_private(actorfile)==record,'EXISTING_ACTOR_RECORD_DRIFT')
    store.doc['actorRecordCreated']=True;store.save()
    # Hand over the four partner SCIM mutations to the pre-existing at-most-once v18 journals.
    result=subprocess.run([sys.executable,str(ctx['repo']/'scripts/p2/partner_directory_v18.py'),'bootstrap'],
                          cwd=str(ctx['repo']),capture_output=True,text=True,timeout=150)
    if result.returncode!=0:raise Block('V18_DIRECTORY_BOOTSTRAP_ERROR_REVIEW_PRIVATE_JOURNALS_NO_RETRY')
    try:out=json.loads(result.stdout)
    except (ValueError,TypeError):raise Block('V18_RESULT_NON_JSON_REVIEW_PRIVATE_JOURNALS') from None
    need(type(out)==dict,'V18_RESULT_INVALID')
    need(out.get('status')=='VERIFIED' and out.get('code')=='V18_PARTNER_DIRECTORY_OBJECTS_VERIFIED' and
         out.get('sharingVerified') is True and out.get('partnerDirectoryVerified') is True,
         'V18_DIRECTORY_NOT_YET_VERIFIED_NO_AUTOMATIC_RETRY')
    return {'directoryVerified':True,'actorVerified':True,'businessAppSharingVerified':True,
            'disabledUsersExpected':2,'groupsExpected':2}

def main(argv):
    need(argv and (argv==['audit'] or argv==['bootstrap',APPROVAL]),
         'USAGE_audit_OR_bootstrap_EXACT_APPROVAL_PHRASE')
    mode=argv[0]
    ctx=context()
    api=Api(ctx)
    need(tuple(ctx['v18'].SCOPES)==FIVE_SCOPES,
         'V18_FIVE_SCOPE_CONTRACT_NOT_INSTALLED')
    resources=resource_discovery(api,ctx['v18'].SCOPES)
    store=Store(ctx['private']/JOURNAL)
    found=app_candidates(ctx)
    if mode=='audit':
        return {'code':'AUTOMATED_ACTOR_BOOTSTRAP_PREFLIGHT_READY','status':'PREFLIGHT_VERIFIED',
                'appCandidates':len(found),'journalPresent':store.doc is not None,
                'apiResourcesVerified':sorted(resources),'requiredScopes':list(ctx['v18'].SCOPES),
                'managementWritesAttempted':0}
    outcome=bootstrap(ctx,api,resources)
    return {'code':'AUTOMATED_ACTOR_AND_DIRECTORY_VERIFIED','status':'VERIFIED',**outcome,
            'managementWritesAttempted':'SEE_PRIVATE_V33_AND_V18_JOURNALS'}

if __name__=='__main__':
    mode=sys.argv[1] if len(sys.argv)>1 else '?'
    try:
        result=main(sys.argv[1:]);rc=0
    except CatalogError as e:
        result={'code':str(e),'status':'BLOCKED','catalogEvidence':e.evidence,'managementWritesAttempted':
                0 if mode=='audit' else 'UNKNOWN_REVIEW_PRIVATE_V33_AND_V18_JOURNALS'};rc=2
    except Block as e:
        result={'code':str(e),'status':'BLOCKED','managementWritesAttempted':
                0 if mode=='audit' else 'UNKNOWN_REVIEW_PRIVATE_V33_AND_V18_JOURNALS'};rc=2
    except Exception as e:
        result={'code':'UNEXPECTED_DEPENDENCY_ERROR','status':'BLOCKED',
                'exceptionType':type(e).__name__,'managementWritesAttempted':
                0 if mode=='audit' else 'UNKNOWN_REVIEW_PRIVATE_V33_AND_V18_JOURNALS'};rc=3
    report(**result)
    raise SystemExit(rc)
