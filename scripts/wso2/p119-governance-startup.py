#!/usr/bin/env python3
"""Reconcile two approved WSO2 lab policies; no user/database operations."""
import os,sys,json,re,base64,subprocess,http.client,importlib.util
from pathlib import Path
from urllib.parse import quote

R=Path(__file__).resolve().parents[2]
V={'aurora':'aurora.identity.test','brisa':'brisa.identity.test'}
T=('SelfRegistration.Enable','Recovery.Notification.Password.Enable')
S=('SelfRegistration.LockOnCreation','Recovery.Notification.InternallyManage')
J=R/'var/wso2/p119-rollback.private.json'

class Stop(Exception):pass

def need(ok,msg):
    if not ok:raise Stop(msg)

def smtp():
    try:
        r=subprocess.run(
            ['docker','exec','wso2-ciam-v10-is-1','sh','-c',
             'cat "$HOME"/wso2is-7.3.0/repository/conf/deployment.toml'],
            capture_output=True,text=True,timeout=15
        )
        if r.returncode or len(r.stdout)>262144:return False
        fields={};section=''
        for l in r.stdout.splitlines():
            l=l.strip()
            if l.startswith('[') and l.endswith(']'):
                section=l[1:-1].lower()
            elif section=='output_adapter.email' and '=' in l:
                k,v=l.split('=',1)
                if k.strip() in (
                    'hostname','port','from_address',
                    'username','password','enable_authentication'
                ):
                    fields[k.strip()]=v.split('#',1)[0].strip().strip('"\'')
        port=fields.get('port','')
        return bool(
            fields.get('hostname') and fields.get('from_address')
            and port.isdecimal() and 1<=int(port)<=65535
            and (fields.get('enable_authentication')!='true'
                 or (fields.get('username') and fields.get('password')))
        )
    except (OSError,subprocess.TimeoutExpired):
        return False

def encoded(s):
    need(
        isinstance(s,str)
        and re.fullmatch(r'[A-Za-z0-9_+/-]{1,160}={0,2}',s),
        'UNSAFE_API_ID'
    )
    return quote(s,safe='')

def request(ctx,domain,creds,method,path='',payload=None):
    need(domain in V.values() and method in ('GET','PATCH'),'UNSAFE_REQUEST')
    auth=base64.b64encode((creds[0]+':'+creds[1]).encode()).decode()
    headers={
        'Accept':'application/json',
        'Authorization':'Basic '+auth
    }
    if payload is not None:
        headers['Content-Type']='application/json'

    conn=http.client.HTTPSConnection(
        'localhost',9444,context=ctx,timeout=12
    )
    try:
        conn.request(
            method,
            f'/t/{domain}/api/server/v1/identity-governance'+path,
            body=json.dumps(payload) if payload else None,
            headers=headers
        )
        response=conn.getresponse()
        code=response.status
        media=(response.getheader('Content-Type') or '').lower()
        content=response.read(262145)
    finally:
        conn.close()

    need(len(content)<=262144,'RESPONSE_TOO_BIG')

    if method=='PATCH':
        need(code in (200,204),'PATCH_HTTP_'+str(code))
        return

    need(code==200 and 'json' in media,
         'GOVERNANCE_GET_FAILED_'+str(code))
    value=json.loads(content)
    need(isinstance(value,(list,dict)),'BAD_RESPONSE')
    return value

def read(ctx,brand,creds):
    domain=V[brand]
    root=request(ctx,domain,creds,'GET')
    cats=root if isinstance(root,list) else root.get('categories',[])
    need(isinstance(cats,list) and 1<=len(cats)<=30,
         'INVALID_CATEGORIES')
    found={}

    def scan(x,c):
        if isinstance(x,list):
            for a in x:scan(a,c)
        if isinstance(x,dict):
            if isinstance(x.get('properties'),list) and isinstance(x.get('id'),str):
                for p in x['properties']:
                    if isinstance(p,dict) and p.get('name') in T+S+(
                        'SelfRegistration.NotifyAccountConfirmation',
                        'SelfRegistration.Notification.InternallyManage'
                    ):
                        key=p['name']
                        value=p.get('value')
                        if isinstance(value,bool):
                            value=str(value).lower()
                        need(
                            value in ('true','false') and key not in found,
                            'POLICY_AMBIGUITY_'+key
                        )
                        found[key]=(value,c,x['id'])
            for k,v in x.items():
                if k in ('connectors','subCategories','categories','items'):
                    scan(v,c)

    for cat in cats:
        c=cat['id']
        path='/'+encoded(c)
        count=len(found)
        scan(request(ctx,domain,creds,'GET',path),c)
        if count==len(found):
            scan(request(ctx,domain,creds,'GET',
                         path+'/connectors'),c)

    need(all(k in found for k in T+S),'POLICIES_NOT_FOUND')
    return found

def save(state):
    need(J.parent.is_dir() and not J.is_symlink(),
         'STATE_LOCATION_UNSAFE')
    tmp=J.with_suffix('.tmp')
    need(not tmp.exists(),'STATE_TEMP_EXISTS')
    fd=os.open(tmp,os.O_WRONLY|os.O_EXCL|os.O_CREAT,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(state,f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp,J)

def patch(ctx,brand,owner,records,key,value):
    before,category,connector=records[key]
    need(before!=value and before in ('true','false'),
         'BAD_PRIOR_POLICY')
    request(
        ctx,V[brand],owner,'PATCH',
        '/'+encoded(category)+'/connectors/'+encoded(connector),
        {'operation':'UPDATE',
         'properties':[{'name':key,'value':value}]}
    )
    new=read(ctx,brand,owner)
    need(new[key][0]==value,'PATCH_READBACK_FAILED')
    return new

def run(mode):
    need(mode in ('test','email','plan','apply',
                  'startup','check','rollback'),'BAD_COMMAND')

    if mode=='test':
        assert encoded('YWJj==')=='YWJj%3D%3D'
        print('P119_OFFLINE_TEST_OK')
        return

    ready=smtp()

    if mode=='email':
        print(json.dumps({
            'smtp_config_present':bool(ready),
            'delivery_proven':False
        }))
        return

    if mode=='startup' and not ready:
        print('P119_EMAIL_DELIVERY_UNVERIFIED_LOCAL_LAB_ONLY')

    need(
        'internal_login' in
        (R/'services/identity-bff/src/server.js').read_text(),
        'BFF_SCOPE_PATCH_MISSING'
    )

    loc=Path(__file__).with_name('p119-owner-helper.py')
    need(loc.is_file() and not loc.is_symlink(),
         'OWNER_HELPER_MISSING')

    spec=importlib.util.spec_from_file_location('owner',loc)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    home=Path(os.environ.get(
        'CIAM_V10_HOME',
        str(Path.home()/'wso2-ciam-v10')
    ))
    need(home.is_dir() and not home.is_symlink(),
         'V10_HOME_MISSING')

    owners=m.private_journal(
        home/'private/bootstrap-tenants-v10.private.json'
    )
    ctx=m.tls_context()
    data={b:read(ctx,b,owners[b]) for b in V}

    if mode=='plan':
        print(json.dumps({
            'status':'P119_PLAN_READ_ONLY',
            'smtp':bool(ready),
            'tenants':{
                b:{k:data[b][k][0] for k in T+S}
                for b in V
            }
        },indent=2))
        return

    for brand in V:
        need(
            all(data[brand][k][0]=='true' for k in S),
            'SAFETY_POLICY_FALSE_'+brand
        )
        disabled_notifications = [
            k for k in (
                'SelfRegistration.NotifyAccountConfirmation',
                'SelfRegistration.Notification.InternallyManage'
            ) if data[brand].get(k,('unknown',))[0] == 'false'
        ]
        if disabled_notifications:
            marker = Path.home() / 'Library/Application Support/ciam-p119-lab-mode/approval.private.json'
            need(marker.is_file() and not marker.is_symlink()
                 and marker.stat().st_mode & 0o077 == 0,
                 'LOCAL_LAB_APPROVAL_MISSING')
            approved = json.loads(marker.read_text())
            need(approved == {
                'schema': 1,
                'mode': 'configuration-only-without-email',
                'repository': str(R.resolve()),
                'tenants': V,
                'accept_locked_unconfirmed_users': True,
            }, 'LOCAL_LAB_APPROVAL_INVALID')
            print('P119_LAB_ONLY_CONFIRMATION_UNAVAILABLE_'+brand+
                  ': '+','.join(disabled_notifications))

    if mode=='check':
        need(
            all(
                data[b][k][0]=='true'
                for b in V for k in T
            ),
            'NOT_READY'
        )
        print('P119_GOVERNANCE_CONFIG_CHECK_PASSED_EMAIL_DELIVERY_UNVERIFIED')
        return

    if mode=='rollback':
        need(
            J.is_file() and not J.is_symlink()
            and not J.stat().st_mode&0o077,
            'NO_SAFE_ROLLBACK'
        )
        state=json.loads(J.read_text())
        need(
            state.get('version')==1
            and state.get('status') in ('applying','applied'),
            'BAD_ROLLBACK_STATE'
        )
        for b,k in reversed(state['attempted']):
            need(b in V and k in T,'BAD_ROLLBACK_SCOPE')
            if data[b][k][0]=='true':
                data[b]=patch(ctx,b,owners[b],data[b],k,'false')
            else:
                need(data[b][k][0]=='false','ROLLBACK_DRIFT')
        state['status']='rolled_back'
        save(state)
        print('P119_ROLLBACK_PASSED')
        return

    if not ready:
        print('P119_EMAIL_DELIVERY_UNVERIFIED_LOCAL_LAB_ONLY')

    pending=[
        (b,k) for b in V for k in T
        if data[b][k][0]!='true'
    ]

    if not pending:
        print('P119_ALREADY_READY')
        return

    need(
        all(data[b][k][0]=='false' for b,k in pending),
        'UNKNOWN_POLICY'
    )

    if J.exists():
        need(
            not J.is_symlink()
            and not J.stat().st_mode&0o077
            and json.loads(J.read_text()).get('status')
                in ('rolled_back','applied'),
            'UNRESOLVED_PARTIAL_CHANGE'
        )

    state={
        'version':1,
        'status':'applying',
        'attempted':[]
    }
    save(state)

    for b,k in pending:
        state['attempted'].append([b,k])
        save(state)
        data[b]=patch(ctx,b,owners[b],data[b],k,'true')

    state['status']='applied'
    save(state)
    print('P119_APPLY_AND_READBACK_PASSED')

if __name__=='__main__':
    mode=sys.argv[1] if len(sys.argv)==2 else ''
    lock=R/'var/wso2/p119-governance.lock'
    locked=False

    try:
        if mode in ('apply','startup','rollback'):
            fd=os.open(
                lock,
                os.O_EXCL|os.O_CREAT|os.O_WRONLY,
                0o600
            )
            os.close(fd)
            locked=True
        run(mode)
    except Exception as error:
        msg=str(error) if isinstance(error,Stop) else type(error).__name__
        print('P119_STOP: '+msg,file=sys.stderr)
        sys.exit(2)
    finally:
        if locked:
            lock.unlink(missing_ok=True)
