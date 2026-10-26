#!/usr/bin/env python3
"""Guarded *local* v10 BFF restart. Never accesses Docker, WSO2 or databases.

Requires exact PID, process owner, executable, cwd and listening port match.
An unknown listener or PID drift always blocks. Explicit confirmation required.
"""
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parents[3]
ROOT = Path(os.environ.get('CIAM_V10_HOME', str(Path.home()/'wso2-ciam-v10'))).expanduser()
PRIVATE = ROOT/'private'
PIDFILE = PRIVATE/'bff-v10.pid'
PORT = 4400
CONFIRM = 'RESTART_ONLY_VERIFIED_V10_BFF_4400'

class Refuse(Exception): pass

def shell(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=6, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refuse('PROCESS_INSPECTION_UNAVAILABLE') from None

def lsof_pids():
    r = shell(['lsof','-nP','-t',f'-iTCP:{PORT}','-sTCP:LISTEN'])
    if r.returncode not in (0,1): raise Refuse('PORT_INSPECTION_FAILED')
    lines = r.stdout.splitlines()
    if any(not line.isdecimal() for line in lines):raise Refuse('LISTENER_PID_INVALID')
    return set(map(int,lines))

def command_field(pid,field):
    r = shell(['ps','-ww','-p',str(pid),'-o',f'{field}='])
    return r.stdout.strip() if r.returncode==0 else ''

def process_cwd(pid):
    r = shell(['lsof','-nP','-a','-p',str(pid),'-d','cwd','-Fn'])
    if r.returncode: return None
    values=[line[1:] for line in r.stdout.splitlines() if line.startswith('n')]
    return values[0] if len(values)==1 else None

def recognized_process(*, pid, pids, owner, comm, args, cwd):
    """Identity gate is pure so negative cases can be unit tested."""
    if pids != {pid} or owner != os.getuid(): return False
    if Path(comm).name != 'node': return False
    try: tokens=shlex.split(args)
    except ValueError: return False
    if len(tokens)!=2 or Path(tokens[0]).name!='node' or tokens[1]!='services/identity-bff/src/server.js':
        return False
    return cwd is not None and Path(cwd).resolve()==REPO.resolve()

def get_private_pid():
    try: s=PIDFILE.lstat()
    except FileNotFoundError: return None,None
    if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_uid!=os.getuid():
        raise Refuse('BFF_PIDFILE_UNSAFE')
    raw=PIDFILE.read_text().strip()
    if not raw.isdecimal() or not 2<=int(raw)<=2**31-1:raise Refuse('BFF_PIDFILE_INVALID')
    return int(raw),s.st_ino

def inspect():
    if not (ROOT/'compose.yaml').is_file() or not (REPO/'services/identity-bff/src/server.js').is_file():
        raise Refuse('UNEXPECTED_V10_PROJECT')
    pid,inode=get_private_pid()
    listeners=lsof_pids()
    if pid is None: return {'status':'UNMANAGED_OR_STOPPED','pid':None,'ready':False,
                              'port4400Listening':bool(listeners)}
    owner=command_field(pid,'uid')
    owner=int(owner) if owner.isdecimal() else None
    com=command_field(pid,'comm')
    args=command_field(pid,'command')
    cwd=process_cwd(pid)
    ready=recognized_process(pid=pid,pids=listeners,owner=owner,comm=com,args=args,cwd=cwd)
    return {'status':'VERIFIED_V10_BFF' if ready else 'UNVERIFIED_PROCESS_REFUSE',
            'pid':pid,'inode':inode,'ready':ready,'port4400Listening':bool(listeners),
            'start':command_field(pid,'lstart') if ready else None}

def report(snapshot):
    return {'stage':'CIAM_V10_BFF_RUNTIME_PLAN','pidRecorded':snapshot['pid'] is not None,
            'port4400Listening':snapshot['port4400Listening'],
            'exactProcessOwnershipVerified':snapshot['ready'],
            'decision':'MAY_RESTART_WITH_EXPLICIT_CONFIRMATION' if snapshot['ready'] else 'REFUSE_NO_CHANGES',
            'effect':'Replaces only verified local v10 Node process; existing BFF sessions expire; no WSO2 or database writes'}

def http_check(path):
    req=urllib.request.Request(f'http://127.0.0.1:{PORT}{path}',headers={'Accept':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=2) as r: return r.status,json.loads(r.read(65536))
    except urllib.error.HTTPError as e:
        try:return e.code,json.loads(e.read(65536))
        except (ValueError,UnicodeDecodeError):return e.code,{}
    except (OSError,ValueError):return None,{}

def run(command):
    first=inspect()
    if command=='bff-runtime-plan':
        print(json.dumps(report(first),indent=2));return
    if command!='bff-restart':raise Refuse('UNKNOWN_COMMAND')
    if os.environ.get('WSO2_CIAM_V10_BFF_RESTART_CONFIRM')!=CONFIRM:
        raise Refuse('EXPLICIT_V10_BFF_RESTART_CONFIRMATION_REQUIRED')
    if not first['ready']:raise Refuse('V10_PROCESS_NOT_VERIFIED_NO_SIGNAL_SENT')
    # Reinspect immediately before the signal to limit PID reuse/time-of-check drift.
    second=inspect()
    if (not second['ready'] or second['pid']!=first['pid'] or
        second['inode']!=first['inode'] or second['start']!=first['start']):
        raise Refuse('PROCESS_IDENTITY_CHANGED_NO_SIGNAL_SENT')
    os.kill(first['pid'],signal.SIGTERM)  # Never SIGKILL, never Docker control.
    for _ in range(50):
        if first['pid'] not in lsof_pids() and not command_field(first['pid'],'lstart'):
            break
        time.sleep(.2)
    else:raise Refuse('PROCESS_DID_NOT_EXIT_NO_RESTART')
    if lsof_pids():raise Refuse('PORT_ALREADY_REUSED_NO_RESTART')
    pid,inode=get_private_pid()
    if pid!=first['pid'] or inode!=first['inode']:
        raise Refuse('PIDFILE_CHANGED_NO_RESTART')
    PIDFILE.unlink()
    result=subprocess.run([sys.executable,str(REPO/'deploy/ciam-v10/oidc/bootstrap.py'),
                            'start-bff','--repo',str(REPO)],cwd=str(ROOT),
                           capture_output=True,text=True,timeout=65,check=False)
    if result.returncode:raise Refuse('V10_BFF_START_FAILED_INSPECT_BFF_DIAGNOSE')
    for _ in range(50):
        me,identity=http_check('/api/identity/me')
        scenarios,demo=http_check('/api/scenarios')
        if (me==200 and identity.get('evidence')=='LIVE_INTROSPECTION_PER_REQUEST' and
            scenarios==503 and demo.get('syntheticFallback') is False):
            print(json.dumps({'stage':'CIAM_V10_BFF_RESTARTED_IN_LIVE_MODE',
                              'identityMode':'live-wso2',
                              'syntheticScenariosHttp':503,'remoteWrites':0,
                              'existingBffSessions':'INVALIDATED'},indent=2));return
        time.sleep(.2)
    raise Refuse('BFF_STARTED_BUT_LIVE_MODE_NOT_VERIFIED')

if __name__=='__main__':
    try:
        if len(sys.argv)!=2:raise Refuse('EXPECTED_bff-runtime-plan_OR_bff-restart')
        run(sys.argv[1])
    except (Refuse, OSError, ValueError, subprocess.TimeoutExpired) as e:
        print('CIAM_V10_BFF_STOP: '+(str(e) if isinstance(e,Refuse) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
