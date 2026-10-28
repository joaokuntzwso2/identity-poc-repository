# P0.10 — UserInfo versus business profile permission

Status: **implementation candidate**; live browser UserInfo is not attested until rerun.

The former P0.10 browser runner called `GET /api/brands/:brand/profile`, an endpoint
that deliberately requires the independent business permission `ciam:profile:read`
and `WSO2_BUSINESS_API_AUDIENCE`. The Cases API scopes are not that permission.
An authenticated OIDC customer may have a valid `openid` scope and yet receive
403 or 503 from the business profile route. The runner reported this as UserInfo failure.

The new **GET `/api/oidc/userinfo?client=aurora-web`** (four exact client keys only)
is separate from business authorization. It is allowed only after an active WSO2
access-token introspection whose subject, client, issuer, and expiration match
the existing signature-verified OIDC session. The introspected scope must contain
`openid`. The BFF then fetches the Discovery-pinned HTTPS UserInfo endpoint and
requires an exact `sub` match, returning only allowlisted public profile claims.
UserInfo authorization is **never** used to grant `ciam:cases:*`, `ciam:profile:read`,
or other business permissions. No raw subject, bearer, cookie, token or password
is returned in the new response or the browser evidence.

The original `/api/brands/:brand/profile` and `/api/protected/profile` business
permission gates remain unchanged. The deny-by-default API allowlist adds only
GET `/api/oidc/userinfo`; all unsupported methods and unlisted routes stay denied.

## Validation

Install guarded v8, run full BFF and CIAM tests, then use existing scoped v5
`configure-bff` command to restart with the validated assurance environment.
Rerun the interactive browser acceptance with the existing explicit case-write
confirmation. A real WSO2 login and UserInfo readback remain mandatory; a 403
from the new route means missing `openid`, 502 means real UserInfo retrieval or
subject verification failed, 503 means WSO2 introspection unavailable.

No WSO2 policy writes, Brisa changes, business record mutations or Git operations
are part of this source repair. No live result is claimed from offline tests.
