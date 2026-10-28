#!/usr/bin/env python3
"""Summarize sanitized callback binding evidence; never prints raw tokens/IDs."""
from pathlib import Path
import datetime as dt
import json
import os
import sys

KEYS = {'aurora-web','aurora-app','brisa-web','brisa-app'}
RUN_ID = os.environ.get('WSO2_CIAM_BINDING_RUN_ID', '')
HOME = Path(os.environ.get('CIAM_V10_HOME',str(Path.home()/'wso2-ciam-v10')))
EVIDENCE = HOME/'inspection/ciam-v10-binding-evidence.jsonl'

def check(path=EVIDENCE, at=None):
    at = at or dt.datetime.now(dt.timezone.utc)
    if not (12 <= len(RUN_ID) <= 96 and all(c.isalnum() or c in '_-' for c in RUN_ID)):
        return {'status':'BLOCKED','reason':'RUN_ID_NOT_SET','channels':{}}
    if path.is_symlink() or not path.is_file():
        return {'status':'BLOCKED','reason':'NO_PRIVATE_EVIDENCE','channels':{}}
    info=path.stat()
    if (os.name == 'posix' and (info.st_uid!=os.getuid() or (info.st_mode & 0o077))) or info.st_size>262144:
        return {'status':'BLOCKED','reason':'EVIDENCE_PERMISSIONS_OR_SIZE','channels':{}}
    latest={}
    for line in path.read_text().splitlines():
        try:
            entry=json.loads(line)
            if (entry.get('schema')!='ciam-v10.binding.v1' or entry.get('key') not in KEYS
                    or entry.get('runId') != RUN_ID):continue
            when=dt.datetime.fromisoformat(entry['at'].replace('Z','+00:00'))
            if when.tzinfo is None:continue
            if when>at+dt.timedelta(minutes=2) or at-when>dt.timedelta(hours=2):continue
            key=entry['key']
            if key not in latest or when>latest[key][0]:latest[key]=(when,entry.get('state'))
        except (KeyError,ValueError,TypeError,json.JSONDecodeError):
            continue
    channels={key:latest.get(key,(None,'NO_RECENT_LIVE_LOGIN'))[1] for key in sorted(KEYS)}
    complete=all(x=='EXACT_SESSION_TOKEN_SUBJECT_BOUND' for x in channels.values())
    return {'status':'READBACK_BOUND_NOT_BUSINESS_ACCEPTANCE' if complete else 'BLOCKED',
            'channels':channels,'note':'Callback-specific live evidence; does not prove business scope issuance'}

if __name__=='__main__':
    report=check()
    print(json.dumps(report,indent=2))
    sys.exit(0 if report['status']=='READBACK_BOUND_NOT_BUSINESS_ACCEPTANCE' else 2)
