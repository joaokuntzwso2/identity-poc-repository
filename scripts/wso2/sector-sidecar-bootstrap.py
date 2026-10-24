#!/usr/bin/env python3
"""Guarded local-only HTTPS sector hosting for the two existing WSO2 lab tenants.

Modes: check (read-only), ensure (Docker sidecar + WSO2 trust + restart same
container), status (read-only). Never touches H2, tenant ownership, or Basic auth.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.request

ROOT = Path.cwd()
PRIVATE = ROOT / 'var/wso2/sector-host'
TLS = PRIVATE / 'tls'
SECTOR = PRIVATE / 'data'
CERT = TLS / 'sector.pem'
KEY = TLS / 'sector-key.pem'
CONFIG = PRIVATE / 'nginx.conf'
TRUST_MARKER = PRIVATE / 'trust-change-pending.json'
CONTAINER = 'wso2-identity-server-1'
SIDE = 'wso2-lab-sectors-v1'
NETWORK = 'wso2_default'
IMAGE = 'nginx:1.27-alpine'
# WSO2 7.3 ships PKCS12 by default, but a supported JKS layout may also exist.
# Resolve the configured truststore, never the primary signing/TLS keystore.
HOME = str(Path('/', 'home', 'wso2carbon', 'wso2is-7.3.0'))
SECURITY = HOME+'/repository/resources/security'
DEPLOYMENT = HOME+'/repository/conf/deployment.toml'
STORES = {'client-truststore.p12': 'PKCS12', 'client-truststore.jks': 'JKS'}
ALIAS = 'wso2lab-sectors-v1'
HOSTS = {'aurora': 'aurora-sector.identity.test', 'brisa': 'brisa-sector.identity.test'}
ENVS = {'DEMO_AURORA_SECTOR_BASE_URL': 'https://aurora-sector.identity.test',
        'DEMO_BRISA_SECTOR_BASE_URL': 'https://brisa-sector.identity.test',
        'WSO2_LAB_SECTOR_BRIDGE': 'docker-sidecar-v1',
        'WSO2_LAB_LOCAL_HTTP_CALLBACKS': 'allow-loopback-v1'}

class Stop(RuntimeError):
    pass

def cmd(*parts, ok=True, timeout=60, **kwargs):
    try:
        res = subprocess.run(parts, capture_output=True, text=True, timeout=timeout, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Stop('LOCAL_TOOL_OR_TIMEOUT_'+parts[0]) from exc
    if ok and res.returncode:
        raise Stop('COMMAND_FAILED_'+parts[0]+'_'+(parts[1] if len(parts)>1 else ''))
    return res

def docker(*args, ok=True, timeout=90):
    return cmd('docker', *args, ok=ok, timeout=timeout)

def inspect_container():
    a=json.loads(docker('inspect',CONTAINER).stdout)[0]
    if not a.get('State',{}).get('Running') or a.get('Mounts'):
        raise Stop('WSO2_CONTAINER_LAYOUT_CHANGED')
    nets=a.get('NetworkSettings',{}).get('Networks') or {}
    if NETWORK not in nets:
        raise Stop('WSO2_NETWORK_NOT_WSO2_DEFAULT')
    ports=[p for items in a.get('NetworkSettings',{}).get('Ports',{}).values() for p in (items or [])]
    if not ports or any(p.get('HostIp') not in ('127.0.0.1','::1') for p in ports):
        raise Stop('WSO2_NOT_LOOPBACK_BOUND')
    return a

def verify_backup():
    for d in sorted((ROOT/'var/wso2/backups').glob('*'), reverse=True):
        m=d/'metadata.json'
        if m.is_file() and not (d/'INCOMPLETE').exists() and (d/'repository/conf/deployment.toml').is_file():
            try: content=json.loads(m.read_text())
            except (OSError,ValueError): continue
            if content.get('backupMode')=='COLD_COPY_STOPPED_CONTAINER':return
    raise Stop('VERIFIED_COLD_BACKUP_REQUIRED')

def private_dir(p):
    if p.is_symlink():raise Stop('PRIVATE_DIRECTORY_IS_SYMLINK')
    p.mkdir(parents=True,exist_ok=True,mode=0o700)
    if p.is_symlink():raise Stop('PRIVATE_DIRECTORY_IS_SYMLINK')
    os.chmod(p,0o700)

def exclusive_bytes(p,content):
    if p.exists() or p.is_symlink():
        if p.is_symlink() or p.read_bytes()!=content:raise Stop('IMMUTABLE_SECTOR_FILE_CHANGED_'+p.name)
        return False
    f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(f,'wb') as out:out.write(content);out.flush();os.fsync(out.fileno())
    return True

def callbacks():
    script='''import {config,deploymentPlan} from './scripts/wso2/domain.mjs';
const apps=deploymentPlan(config(),process.env).apps;
const obj={};for(const brand of ['aurora','brisa']){
  const items=apps.filter(x=>x.brand===brand);
  if(items.length!==2)throw Error('TWO_CLIENTS_REQUIRED_'+brand);
  obj[brand]=items.map(x=>x.callback);
}
console.log(JSON.stringify(obj));'''
    r=cmd('node','--env-file=var/wso2/lab.env','--input-type=module','-e',script)
    try:data=json.loads(r.stdout)
    except ValueError as e:raise Stop('CALLBACK_PLAN_NOT_JSON') from e
    for brand in HOSTS:
        values=data.get(brand)
        if not isinstance(values,list) or len(values)!=2 or len(set(values))!=2:
            raise Stop('TWO_DISTINCT_CALLBACKS_REQUIRED_'+brand)
        from urllib.parse import urlsplit
        for value in values:
            u=urlsplit(value)
            if not (u.scheme=='http' and u.hostname=='127.0.0.1' and u.port and not u.username and not u.password and not u.fragment):
                raise Stop('LOCAL_CALLBACK_ORIGIN_NOT_EXPECTED_'+brand)
    return data

def nginx_config():
    v='''events { worker_connections 128; }
http {
  access_log off;
  server_tokens off;
  %s
}
'''
    servers=[]
    for brand,host in HOSTS.items():
        servers.append('''server {
 listen 443 ssl;
 server_name %s;
 ssl_certificate /etc/nginx/sector-tls/sector.pem;
 ssl_certificate_key /etc/nginx/sector-tls/sector-key.pem;
 location = /sector.json {
   default_type application/json;
   add_header Cache-Control "no-store" always;
   alias /etc/nginx/sector-data/%s.json;
 }
 location / { return 404; }
}'''%(host,brand))
    return (v%'\n'.join(servers)).encode()

def ensure_files(data):
    for d in (PRIVATE,TLS,SECTOR):private_dir(d)
    for brand,values in data.items():
        exclusive_bytes(SECTOR/(brand+'.json'), (json.dumps(values,separators=(',',':'))+'\n').encode())
    exclusive_bytes(CONFIG,nginx_config())
    if CERT.exists() != KEY.exists():raise Stop('PARTIAL_SECTOR_TLS_CERTIFICATE')
    if not CERT.exists():
        cmd('openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','825',
            '-subj','/CN=aurora-sector.identity.test',
            '-addext','subjectAltName=DNS:aurora-sector.identity.test,DNS:brisa-sector.identity.test',
            '-addext','basicConstraints=critical,CA:FALSE',
            '-keyout',str(KEY),'-out',str(CERT))
        os.chmod(KEY,0o600);os.chmod(CERT,0o600)
    if KEY.is_symlink() or CERT.is_symlink():raise Stop('SECTOR_TLS_SYMLINK')
    result=cmd('openssl','x509','-in',str(CERT),'-noout','-checkend','604800',ok=False)
    if result.returncode:raise Stop('SECTOR_TLS_CERT_EXPIRING_SOON_MANUAL_REVIEW')
    x=ssl._ssl._test_decode_cert(str(CERT))
    dns={val for typ,val in x.get('subjectAltName',[]) if typ=='DNS'}
    if dns!=set(HOSTS.values()):raise Stop('SECTOR_TLS_IDENTITY_MISMATCH')

def sidecar():
    old=docker('inspect',SIDE,ok=False)
    if old.returncode==0:
        item=json.loads(old.stdout)[0]
        labels=(item.get('Config') or {}).get('Labels') or {}
        aliases=(item.get('NetworkSettings') or {}).get('Networks',{}).get(NETWORK,{}).get('Aliases',[])
        if labels.get('wso2.lab.sector-host')!='v1' or not item['State']['Running'] or not set(HOSTS.values()).issubset(set(aliases)):
            raise Stop('SECTOR_CONTAINER_EXISTS_DIFFERENT_CONFIG')
        return
    # Nothing in this command touches or recreates the WSO2 container.
    docker('run','-d','--name',SIDE,'--network',NETWORK,
        '--network-alias',HOSTS['aurora'],'--network-alias',HOSTS['brisa'],
        '--label','wso2.lab.sector-host=v1','--restart','unless-stopped',
        '-p','127.0.0.1:18443:443',
        '--mount',f'type=bind,src={TLS},dst=/etc/nginx/sector-tls,readonly',
        '--mount',f'type=bind,src={SECTOR},dst=/etc/nginx/sector-data,readonly',
        '--mount',f'type=bind,src={CONFIG},dst=/etc/nginx/nginx.conf,readonly',
        IMAGE,timeout=240)

def host_https_proof(max_wait_seconds=45):
    """Wait for the just-started sidecar, but never retry TLS or content errors.

    Docker reports 'running' before nginx is necessarily listening. Only curl
    transport failures commonly caused by startup may be retried. A TLS failure,
    unexpected HTTP status, invalid JSON, or mismatched sector callback list
    always stops before any WSO2 truststore change or application POST.
    """
    if max_wait_seconds <= 0 or max_wait_seconds > 120:
        raise Stop('SECTOR_HTTPS_WAIT_BOUND_INVALID')
    for brand,domain in HOSTS.items():
        url=f'https://{domain}/sector.json'
        expected=json.loads((SECTOR/(brand+'.json')).read_text())
        deadline=time.monotonic()+max_wait_seconds
        waiting_logged=False
        while True:
            r=cmd('curl','--silent','--show-error','--fail','--noproxy','*',
                  '--max-time','4','--cacert',str(CERT),
                  '--connect-to',f'{domain}:443:127.0.0.1:18443',url,
                  ok=False,timeout=10)
            if r.returncode == 0:
                if len(r.stdout)>32768:
                    raise Stop('SECTOR_HOST_RESPONSE_TOO_LARGE_'+brand)
                try:
                    content=json.loads(r.stdout)
                except ValueError as exc:
                    raise Stop('SECTOR_HOST_INVALID_JSON_'+brand) from exc
                if content!=expected:
                    raise Stop('SECTOR_HOST_HTTPS_DOCUMENT_MISMATCH_'+brand)
                print('SECTOR_HTTPS_DOCUMENT_VERIFIED_'+brand)
                break
            # curl 7=connect failed, 28=timeout, 52=empty reply, 56=recv failed.
            # All other errors (notably 22=HTTP error, 35=TLS and 60=certificate)
            # stop immediately and never weaken TLS validation or change trust.
            if r.returncode not in (7,28,52,56):
                raise Stop('SECTOR_HOST_HTTPS_FAILED_'+brand+'_CURL_EXIT_'+str(r.returncode))
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise Stop('SECTOR_HOST_HTTPS_NOT_READY_'+brand+'_CURL_EXIT_'+str(r.returncode))
            if not waiting_logged:
                print('SECTOR_HTTPS_WAITING_FOR_NGINX_'+brand, file=sys.stderr)
                waiting_logged=True
            time.sleep(min(2,remaining))

def configured_truststore_name():
    """Read only the trusted [truststore] name/type; never expose configuration secrets."""
    raw=docker('exec',CONTAINER,'cat',DEPLOYMENT).stdout
    if len(raw)>262144:raise Stop('WSO2_DEPLOYMENT_CONFIG_TOO_LARGE')
    matches=list(re.finditer(r'(?m)^\s*\[truststore\]\s*(?:#.*)?$',raw))
    if len(matches)>1:raise Stop('WSO2_DUPLICATE_TRUSTSTORE_SECTIONS')
    if not matches:return None
    text=raw[matches[0].end():]
    text=re.split(r'(?m)^\s*\[',text,maxsplit=1)[0]
    def field(name):
        rows=re.findall(r'(?m)^\s*'+re.escape(name)+r'\s*=\s*[\"\']([^\"\']+)[\"\']\s*(?:#.*)?$',text)
        # Even malformed or repeated declarations are unsafe to interpret.
        mentions=re.findall(r'(?m)^\s*'+re.escape(name)+r'\s*=',text)
        if len(mentions)!=len(rows) or len(rows)>1:raise Stop('WSO2_TRUSTSTORE_CONFIG_AMBIGUOUS_'+name)
        return rows[0] if rows else None
    name=field('file_name')
    kind=field('type')
    if name is not None and name not in STORES:
        raise Stop('WSO2_TRUSTSTORE_CUSTOM_FILENAME_NEEDS_REVIEW')
    if kind is not None and kind.upper() not in ('JKS','PKCS12'):
        raise Stop('WSO2_TRUSTSTORE_UNSUPPORTED_TYPE')
    if kind and not name:raise Stop('WSO2_TRUSTSTORE_TYPE_WITHOUT_FILENAME')
    if name and kind and kind.upper()!=STORES[name]:
        raise Stop('WSO2_TRUSTSTORE_NAME_TYPE_MISMATCH')
    return name

def truststore():
    """Read-only, strict selection: configured name, or exactly one stock file."""
    selected=configured_truststore_name()
    names=[selected] if selected else list(STORES)
    hits=[]
    for name in names:
        path=SECURITY+'/'+name
        r=docker('exec',CONTAINER,'sh','-c',
                 'test -f "$1" && test ! -L "$1"','sh',path,ok=False)
        if r.returncode==0:hits.append(name)
    if not hits:raise Stop('WSO2_CONFIGURED_CLIENT_TRUSTSTORE_NOT_FOUND')
    if len(hits)!=1:raise Stop('WSO2_CLIENT_TRUSTSTORE_AMBIGUOUS')
    return SECURITY+'/'+hits[0],STORES[hits[0]]

def trust_password():
    # The lab's stock WSO2 truststore uses the documented default; customized
    # stores can be enabled with a private environment override (never logged).
    return os.environ.get('WSO2_LAB_TRUSTSTORE_PASSWORD','wso2carbon')

def trust_alias_present():
    path,kind=truststore()
    r=docker('exec','-u','0',CONTAINER,'keytool','-exportcert','-rfc',
             '-alias',ALIAS,'-keystore',path,'-storetype',kind,
             '-storepass',trust_password(),ok=False)
    if r.returncode:return False
    import hashlib
    pem=r.stdout
    begin=pem.find('-----BEGIN CERTIFICATE-----');end=pem.find('-----END CERTIFICATE-----')
    if begin<0 or end<0:raise Stop('TRUST_ALIAS_UNREADABLE')
    text=pem[begin:end+len('-----END CERTIFICATE-----')]
    expected=hashlib.sha256(ssl.PEM_cert_to_DER_cert(CERT.read_text())).hexdigest()
    found=hashlib.sha256(ssl.PEM_cert_to_DER_cert(text)).hexdigest()
    if expected!=found:raise Stop('TRUST_ALIAS_COLLISION')
    return True

def install_trust():
    path,kind=truststore()
    if trust_alias_present():return False
    # Pre-write snapshot and marker. Never discard evidence after interruption.
    if TRUST_MARKER.exists():raise Stop('TRUST_CHANGE_PENDING_RECOVER_REQUIRED')
    backup=PRIVATE/('original-client-truststore-'+secrets.token_hex(12)+Path(path).suffix)
    if backup.exists() or backup.is_symlink():raise Stop('TRUST_BACKUP_NAME_COLLISION')
    docker('cp',f'{CONTAINER}:{path}',str(backup))
    os.chmod(backup,0o600)
    marker={'schema':1,'container':CONTAINER,'truststore':path,
            'backupFile':backup.name,
            'backupSha256':hashlib.sha256(backup.read_bytes()).hexdigest(),
            'certificateSha256':hashlib.sha256(CERT.read_bytes()).hexdigest()}
    exclusive_bytes(TRUST_MARKER,(json.dumps(marker)+'\n').encode())
    docker('cp',str(CERT),f'{CONTAINER}:/tmp/wso2-sector-v1.pem')
    stat=docker('exec',CONTAINER,'stat','-c','%u:%g %a',path).stdout.strip().split()
    if len(stat)!=2 or not re.fullmatch(r'[0-9]+:[0-9]+',stat[0]) or not re.fullmatch(r'[0-7]{3,4}',stat[1]):
        raise Stop('TRUSTSTORE_OWNER_AND_MODE_UNKNOWN')
    docker('exec','-u','0',CONTAINER,'keytool','-importcert','-noprompt',
           '-alias',ALIAS,'-file','/tmp/wso2-sector-v1.pem','-keystore',path,
           '-storetype',kind,'-storepass',trust_password())
    docker('exec','-u','0',CONTAINER,'chown',stat[0],path)
    docker('exec','-u','0',CONTAINER,'chmod',stat[1],path)
    if not trust_alias_present():raise Stop('TRUST_IMPORT_READBACK_FAILED')
    return True

def ready():
    ca=ROOT/'var/wso2/tls/wso2-local.pem'
    ctx=ssl.create_default_context(cafile=str(ca))
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        try:
            with urllib.request.urlopen('https://localhost:9443/t/brisa.identity.test/oauth2/token/.well-known/openid-configuration',context=ctx,timeout=6) as r:
                if r.status==200 and json.load(r).get('issuer')=='https://localhost:9443/t/brisa.identity.test/oauth2/token':return
        except (OSError,ValueError):pass
        time.sleep(3)
    raise Stop('WSO2_NOT_READY_AFTER_TRUSTSTORE_CHANGE')

def wso2_document_probe():
    # Real Java HTTPS/hostname verification from WSO2 container's network namespace
    # using the configured JKS or PKCS12 truststore we journaled and imported into.
    path,kind=truststore()
    source=ROOT/'scripts/wso2/SectorProbe.java'
    if not source.is_file() or source.is_symlink():raise Stop('JAVA_SECTOR_PROBE_SOURCE_MISSING')
    docker('cp',str(source),f'{CONTAINER}:/tmp/SectorProbe.java')
    for brand,domain in HOSTS.items():
        r=docker('exec',CONTAINER,'java',
                 '-Djavax.net.ssl.trustStore='+path,
                 '-Djavax.net.ssl.trustStoreType='+kind,
                 '-Djavax.net.ssl.trustStorePassword='+trust_password(),
                 '/tmp/SectorProbe.java',f'https://{domain}/sector.json',timeout=60)
        if json.loads(r.stdout)!=json.loads((SECTOR/(brand+'.json')).read_text()):
            raise Stop('WSO2_JAVA_SECTOR_DOCUMENT_DIFFERENT_'+brand)

def check():
    inspect_container();verify_backup()
    if TRUST_MARKER.exists():raise Stop('TRUST_CHANGE_PENDING_RECOVER_REQUIRED')
    if cmd('openssl','version',ok=False).returncode:raise Stop('OPENSSL_REQUIRED')
    if cmd('curl','--version',ok=False).returncode:raise Stop('CURL_REQUIRED')
    path,kind=truststore()
    java=docker('exec',CONTAINER,'java','--list-modules',ok=False)
    if java.returncode or 'jdk.compiler@' not in java.stdout:
        raise Stop('WSO2_JAVA_SOURCE_LAUNCHER_REQUIRED')
    if docker('exec','-u','0',CONTAINER,'keytool','-list',
              '-keystore',path,'-storetype',kind,'-storepass',trust_password(),ok=False).returncode:
        raise Stop('WSO2_TRUSTSTORE_PASSWORD_OR_READ_FAILED')
    callbacks()
    return {'result':'SAFE_SECTOR_SIDE_CAR_ELIGIBLE','truststoreFile':Path(path).name,
            'truststoreType':kind,'dockerNetwork':NETWORK,
            'callbackPolicy':'HTTP_127_0_0_1_ONLY','wso2Recreation':False,'changes':0}

def ensure():
    if os.environ.get('WSO2_LAB_CONFIRM')!='CREATE_SYNTHETIC_RESOURCES':raise Stop('WRITE_CONSENT_REQUIRED')
    check()
    ensure_files(callbacks())
    sidecar();host_https_proof()
    updated=install_trust()
    if updated:
        docker('restart','-t','60',CONTAINER,timeout=120)
        ready()
        # The pending marker is removed only after successful HTTPS probe below.
    wso2_document_probe()
    if updated:TRUST_MARKER.unlink()
    return {'result':'SECTOR_HTTPS_VERIFIED','sectorHosts':list(HOSTS.values()),
            'wso2ContainerRecreated':False,'sameContainerRestartedForTrust':updated,
            'basicAuthConfigurationChanged':False,'oidcAppsCreated':0,'secretsPrinted':False}

def recover():
    """Restore the pre-import truststore from a checksum-verified private copy.

    Never remove/replace a WSO2 container, touch H2, or alter Basic auth.
    """
    if os.environ.get('WSO2_LAB_CONFIRM')!='CREATE_SYNTHETIC_RESOURCES':raise Stop('WRITE_CONSENT_REQUIRED')
    inspect_container()
    if not TRUST_MARKER.is_file() or TRUST_MARKER.is_symlink():raise Stop('NO_SAFE_TRUST_RECOVERY_MARKER')
    data=json.loads(TRUST_MARKER.read_text())
    recorded=data.get('truststore')
    if data.get('schema')!=1 or data.get('container')!=CONTAINER or \
       recorded not in (SECURITY+'/client-truststore.jks',SECURITY+'/client-truststore.p12'):
        raise Stop('TRUST_RECOVERY_MARKER_UNRECOGNIZED')
    path,kind=truststore()
    if recorded!=path:raise Stop('TRUST_RECOVERY_PATH_CONFIG_MISMATCH')
    name=data.get('backupFile')
    if not isinstance(name,str) or not re.fullmatch(r'original-client-truststore-[0-9a-f]{24}\.(?:jks|p12)',name) or not name.endswith(Path(path).suffix):
        raise Stop('TRUST_BACKUP_NAME_INVALID')
    backup=PRIVATE/name
    if backup.is_symlink() or not backup.is_file():raise Stop('TRUST_BACKUP_UNAVAILABLE')
    if hashlib.sha256(backup.read_bytes()).hexdigest()!=data.get('backupSha256'):
        raise Stop('TRUST_BACKUP_CHECKSUM_MISMATCH')
    staging='/tmp/wso2-sector-original-truststore'+Path(path).suffix
    docker('cp',str(backup),f'{CONTAINER}:{staging}')
    # Both names have passed an exact allowlist; no user-supplied shell fragment.
    docker('exec','-u','0',CONTAINER,'sh','-c',
           'set -eu; chown --reference='+path+' '+staging+'; '
           'chmod --reference='+path+' '+staging+'; '
           'mv -f '+staging+' '+path)
    docker('restart','-t','60',CONTAINER,timeout=120)
    ready()
    TRUST_MARKER.unlink()
    return {'result':'ORIGINAL_WSO2_TRUSTSTORE_RESTORED',
            'sameContainerRestarted':True,'secretsPrinted':False}

def status():
    exists=docker('inspect',SIDE,ok=False).returncode==0
    return {'sidecarExists':exists,'trustRecoveryPending':TRUST_MARKER.exists(),
            'hosts':list(HOSTS.values()),'writes':0}

def main():
    mode=sys.argv[1] if len(sys.argv)==2 else None
    try:
        if mode=='check':obj=check()
        elif mode=='status':obj=status()
        elif mode=='ensure':obj=ensure()
        elif mode=='recover':obj=recover()
        else:raise Stop('EXPECTED_check_status_ensure_recover')
        print(json.dumps(obj,indent=2));return 0
    except (Stop,ValueError,OSError) as e:
        print('SECTOR_BOOTSTRAP_ERROR:',str(e) if isinstance(e,Stop) else type(e).__name__,file=sys.stderr)
        return 1
if __name__=='__main__':sys.exit(main())
