#!/usr/bin/env python3
"""No preference/marketing consent is claimed without update + configuration proof."""
import json, os, sys
try: level=int(os.getenv('WSO2_IS73_VERIFIED_UPDATE_LEVEL','-1'))
except ValueError: level=-1
config=os.getenv('WSO2_IS73_CONSENT_V2_ENABLED')=='true'
status='ELIGIBLE_FOR_API_AND_BROWSER_TESTS' if level>=12 and config else 'BLOCKED_NOT_VERIFIED'
print(json.dumps({'component':'CONSENT_V2','status':status,
 'verifiedUpdateLevel':level if level>=0 else 'UNKNOWN',
 'explicitEnablementProvided':config,
 'note':'Environment values are operator declarations, not independent WSO2 runtime proof'},indent=2))
if status!='ELIGIBLE_FOR_API_AND_BROWSER_TESTS':sys.exit(2)
