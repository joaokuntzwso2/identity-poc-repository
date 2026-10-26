#!/usr/bin/env python3
"""Privacy-safe, read-only v10 BFF HTTP probes; no session cookies or OAuth values.

A 401 on the anonymous protected path is a negative gate only: this script
cannot claim a positive authenticated or revocation acceptance result.
"""
import json
import urllib.error
import urllib.request

BASE = 'http://127.0.0.1:4400'
PROBES = {
    'anonymousIdentity': '/api/identity/me',
    'auroraWebWithoutSession': '/api/protected/profile?client=aurora-web',
    'auroraAppWithoutSession': '/api/protected/profile?client=aurora-app',
    'brisaWebWithoutSession': '/api/protected/profile?client=brisa-web',
    'brisaAppWithoutSession': '/api/protected/profile?client=brisa-app',
    'syntheticConsentDisabled': '/api/consent',
    'syntheticScenarioDisabled': '/api/scenarios',
    'syntheticRetailDisabled': '/api/retail/customers',
}

def request(path):
    req=urllib.request.Request(BASE+path, headers={'Accept':'application/json','Cache-Control':'no-store'})
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            return r.status,json.loads(r.read(65537))
    except urllib.error.HTTPError as e:
        try: return e.code,json.loads(e.read(65537))
        except (ValueError,UnicodeDecodeError):return e.code,{}

def run():
    output={'stage':'CIAM_V10_ANONYMOUS_NEGATIVE_ACCEPTANCE','origin':BASE,
            'methods':['GET'],'remoteWrites':0,'credentialsUsed':False,'results':{},'liveAuthorization':'NOT_VERIFIED'}
    passed=True
    for key,path in PROBES.items():
        try:
            code,body=request(path)
            if key=='anonymousIdentity':
                ok=(code==200 and body.get('authenticated') is False
                    and body.get('evidence')=='LIVE_INTROSPECTION_PER_REQUEST')
                output['runtimeEvidence']=body.get('evidence') if body.get('evidence') in (
                    'LIVE_INTROSPECTION_PER_REQUEST','BROWSER_CALLBACK_REQUIRED',
                    'BFF_VALIDATED_SIGNED_ID_TOKEN') else 'UNRECOGNIZED'
            elif key.endswith('WithoutSession'):
                ok=code==401 and body.get('allowed') is not True
            else:
                ok=code==503 and body.get('syntheticFallback') is False
            output['results'][key]={'http':code,'pass':ok}
            passed&=ok
        except (OSError,TimeoutError,ValueError) as e:
            output['results'][key]={'http':'UNAVAILABLE','pass':False}
            passed=False
    output['status']='NEGATIVE_HTTP_GATES_PASSED' if passed else 'BLOCKED_OR_NEGATIVE_GATES_FAILED'
    print(json.dumps(output,indent=2))
    if not passed:raise SystemExit(1)

if __name__=='__main__':run()
