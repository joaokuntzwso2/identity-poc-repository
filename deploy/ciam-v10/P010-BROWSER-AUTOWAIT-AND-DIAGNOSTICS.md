# P0.10 browser autowait and privacy-safe failure diagnosis (v7)

The prior runner required a terminal Enter after each WSO2 browser login; when Enter was pressed before the callback had completed, it could run a BFF fetch from the WSO2 origin and collapse the error to `BROWSER_UNEXPECTED_ERROR`. Also, a known `LIVE_LOGIN_NOT_VERIFIED_aurora-web` code was incorrectly rejected by a uppercase-only error filter.

The updated runner uses Playwright URL detection to await the exact expected BFF portal, without manual terminal input. It records only a bounded failure stage, allowlisted failure code, HTTP status, and origin-class; no URL/query, OAuth code, state, token, password, cookie or TOTP seed. A login on the wrong client or without the expected scope is still denied.

It does not alter production BFF, user data, WSO2 policies, or Git. The live runner is still separately opt-in and may create a durable acceptance request.

If blocked, report only `LIVE_ACCEPTANCE_NOT_PASSED`, `SANITIZED_FAILURE_STAGE`, `SANITIZED_BROWSER_LOCATION` and the status fields from the private evidence file (never paste raw auth URLs).
