# CIAM v5 — end-to-end testing runbook (WSO2 Identity Server 7.3)

**Target:** local Docker project `wso2-ciam-v10`, WSO2 IS `https://localhost:9444`, Node BFF `http://127.0.0.1:4400`. Last positive evidence: **2026-10-28**. The Web/Mobile views use four different **browser OIDC clients**. This guide never treats source-only tests as live-user evidence.

## 0. Rules and prerequisites

- Begin from the existing running lab; do **not** run `fresh`, schema installers, Docker volume removal, or SCIM/role `apply` to run tests.
- All identity data, roles, scopes, client identities, audience and TOTP evidence must come from WSO2. No fake persona selection, injected bearer tokens, local role switches or simulated MFA/consent.
- For reliable client-specific results, use a new **private browser window** for each login test (separate tenant/channel), and sign in with the correct tenant credential. The BFF session cookie is per browser session; opening the same profile in an unrelated CLI won't authenticate it.
- Never print access/refresh/ID tokens, passwords, cookies, raw session JSON (may include CSRF) or private journals in logs or issue trackers. The test snippets below print only statuses, scopes, and safe result fields.
- HTTP 403 for a wrong-brand or wrong-role request is **expected success of a denial test**. A full identity profile is **not** expected until WSO2 attribute-release settings are configured.

## 1. Read-only infrastructure / provisioning smoke tests

From repository root:

```bash
cd "$HOME/wso2mi/Projects/Demo/poc-implementation"
./scripts/ciam-v10.sh status
./scripts/ciam-v10.sh bff-diagnose
bash scripts/live-experience-v5-acceptance.sh
python3 scripts/ciam-v5-four-client-readback.py
python3 deploy/ciam-v10/phase4/business-bootstrap.py verify
python3 scripts/ciam-carbon-super-readback.py
node --test tests/live-userinfo.test.mjs tests/live-cases-v4.test.mjs tests/live-experience-v5.test.mjs
python3 scripts/zero-mock-gate.py .
```

**Expected:** BFF ready on 4400; all v5 routes HTTP 200; anonymous protected endpoints 401; synthetic endpoints disabled; four OIDC app records show JWT/profile+business audiences/RBAC; business bootstrap readback verified; Node tests pass; zero-mock gate passes. Carbon Super readback is **independent**: `FULL_FIRST_PAGE` means only a complete bounded first-page response for that endpoint; `UNVERIFIED_*` means no claim can be made about its contents. The Carbon audit does not change WSO2 configuration.

Additional profile/role source verification when inspecting drift (no writes):

```bash
export WSO2_CIAM_V10_ROLE_API=v2
export WSO2_CIAM_V10_ROLE_V2_CONFIRM=USE_DEPRECATED_ROLE_V2_FOR_NEW_CIAM_V10_ROLES
python3 deploy/ciam-v10/identities/bootstrap.py verify
python3 deploy/ciam-v10/phase4/business-bootstrap.py verify
```

The existing v10 role journal is pinned to SCIM v2: do **not** change API version to make a failing check pass.

## 2. Get a password without displaying it

The repository CLI reads the **existing private password journal** and copies only the requested password to your macOS clipboard. It will not write a credential to the README or terminal.

```bash
# Ana (Aurora): choose the exact tenant
python3 scripts/ciam-identity-ops.py password --kind person --tenant aurora --user ana.costa

# Ana (Brisa): a separate WSO2 account and password
python3 scripts/ciam-identity-ops.py password --kind person --tenant brisa --user ana.costa

# Marcos, seller (Aurora)
python3 scripts/ciam-identity-ops.py password --kind person --tenant aurora --user marcos.oliveira

# Any other person: inspect generated inventory for exact user/tenant first
python3 scripts/ciam-identity-ops.py password --kind person --tenant aurora --user luiza.ferreira

# Tenant-level bootstrap non-admin users (not customer personas)
python3 scripts/ciam-identity-ops.py password --kind foundation --tenant aurora
python3 scripts/ciam-identity-ops.py password --kind foundation --tenant brisa

# Tenant owners (admin login; do not use in retail scenarios)
python3 scripts/ciam-identity-ops.py password --kind owner --tenant aurora
python3 scripts/ciam-identity-ops.py password --kind owner --tenant brisa

# Carbon Super admin (server/root-tenant operations ONLY; highly privileged)
python3 scripts/ciam-identity-ops.py password --kind super
```

The user for a seeded person is their real `username`, e.g. `ana.costa`. Tenant owner: `labtenantadmin@aurora.identity.test` or `labtenantadmin@brisa.identity.test`; Carbon Super administrator: `admin` on the super tenant, not a brand OIDC client. **Paste only into the matching WSO2-hosted login**. Clear clipboard after each use:

```bash
printf '' | pbcopy
```

The CLI refuses absent/unverified user or journal mismatch. If a password has changed in WSO2 since bootstrap, the journal's original value will no longer log in; do not assume credential freshness or reset users automatically.

## 3. All four real customer website logins

Open the [guided lab](http://127.0.0.1:4400/lab) and choose the prominent **Entrar com WSO2** login link for each channel. Direct destinations:

| Order | Browser URL | Client key | WSO2 account | Expected tenant |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:4400/portal/aurora/web` | `aurora-web` | `ana.costa` (Aurora password) | `aurora.identity.test` |
| 2 | `http://127.0.0.1:4400/portal/aurora/mobile` | `aurora-app` | `ana.costa` (Aurora password) | `aurora.identity.test` |
| 3 | `http://127.0.0.1:4400/portal/brisa/web` | `brisa-web` | `ana.costa` (Brisa password) | `brisa.identity.test` |
| 4 | `http://127.0.0.1:4400/portal/brisa/mobile` | `brisa-app` | `ana.costa` (Brisa password) | `brisa.identity.test` |

Each login starts a real WSO2 authorization-code/PKCE redirect, not a local form that stores a password in the BFF UI. Mobile means *responsive mobile browser experience*, not native app authentication.

### Browser test: current page, correct tenant/client, live profile, business read, cross-brand denial

After login, use Developer Tools → Console and paste the **entire** code block below. It derives the tenant/client from the current path and refuses other pages:

```javascript
(async () => {
  const m = /^\/portal\/(aurora|brisa)\/(web|mobile)$/.exec(location.pathname);
  if (!m) throw new Error('Open one of the four explicit /portal/{brand}/{channel} pages');
  const [ , brand, channel ] = m;
  const client = `${brand}-${channel === 'mobile' ? 'app' : 'web'}`;
  const other = brand === 'aurora' ? 'brisa' : 'aurora';
  const options = { credentials: 'same-origin', cache: 'no-store' };
  const meRes = await fetch('/api/identity/me', options);
  const me = await meRes.json();
  const session = me.clients?.[client];
  const scopes = session?.permissions ?? [];
  const profile = await fetch(`/api/brands/${brand}/profile?client=${client}`, options);
  const cases = await fetch(`/api/brands/${brand}/cases?client=${client}`, options);
  const data = await cases.json();
  const denial = await fetch(`/api/brands/${other}/cases?client=${client}`, options);
  const result = {
    brand, client,
    authenticated: session?.authenticated === true,
    scopes,
    profileHTTP: profile.status,
    casesHTTP: cases.status,
    visibility: data.visibility ?? null,
    oppositeBrandHTTP: denial.status,
    passed:
      session?.authenticated === true &&
      scopes.includes('ciam:profile:read') &&
      scopes.includes('ciam:cases:create') &&
      scopes.includes('ciam:cases:read') &&
      !scopes.includes('ciam:cases:approve') &&
      profile.status === 200 && cases.status === 200 &&
      data.visibility === 'OWNER_ONLY' && denial.status === 403
  };
  console.log(JSON.stringify(result, null, 2));
})();
```

**Acceptance:** for each channel `passed: true`, profile 200, cases 200, `OWNER_ONLY`, correct client, expected scopes, and opposite-brand 403. Record **only** the sanitized object printed by the snippet. The four actual tests passed on 2026-10-28; rerun after upgrades or source changes.

## 4. Positive business persistence (Aurora Customer → Aurora Seller)

**Mutating operation.** Execute once as Ana in **Aurora Web**, using the same authenticated browser session. It creates one persistent request. Copy the returned UUID for seller review; no synthetic case is used.

```javascript
(async () => {
  const client = 'aurora-web';
  if (location.pathname !== '/portal/aurora/web') throw Error('Use Aurora Web');
  const opts = { credentials: 'same-origin', cache: 'no-store' };
  const me = await (await fetch('/api/identity/me', opts)).json();
  if (!me.clients?.[client]?.authenticated ||
      !me.clients[client].permissions.includes('ciam:cases:create')) throw Error('Not authorized');
  const url = `/api/brands/aurora/cases?client=${client}`;
  const r = await fetch(url, { ...opts, method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf },
    body: JSON.stringify({title:'E2E atendimento real', description:'Teste de criação e persistência WSO2 CIAM'}) });
  const created = await r.json();
  const listResponse = await fetch(url, opts);
  const listing = await listResponse.json();
  console.log(JSON.stringify({ createHTTP:r.status, uuid:created.id ?? null,
    readHTTP:listResponse.status, visibility:listing.visibility,
    persisted: r.status === 201 && listResponse.status === 200 &&
      listing.records?.some(x=>x.id === created.id && x.status === 'OPEN') === true
  },null,2));
})();
```

**Acceptance:** `createHTTP=201`, UUID returned, `readHTTP=200`, visibility `OWNER_ONLY`, `persisted=true`.

Now open a **different private browser session** as `marcos.oliveira` on Aurora Web. Copy his password using the CLI above. In the Console, set the UUID to the previously returned value and run:

```javascript
(async () => {
  const caseId = 'REPLACE_WITH_REAL_CREATED_CASE_UUID';
  if (!/^[0-9a-f-]{36}$/.test(caseId)) throw Error('Paste a real case UUID');
  const client='aurora-web', url=`/api/brands/aurora/cases?client=${client}`;
  const opts={credentials:'same-origin',cache:'no-store'};
  const me=await (await fetch('/api/identity/me',opts)).json();
  const u=me.clients?.[client];
  if (!u?.authenticated || !u.permissions.includes('ciam:cases:review'))
    throw Error('Seller not authenticated/authorized');
  const read=await fetch(url,opts); const data=await read.json();
  if (read.status !== 200 || data.visibility !== 'BRAND_REVIEW' ||
      !data.records?.some(x=>x.id===caseId)) throw Error('Read/review failed; not attempting create');
  const write=await fetch(url,{...opts,method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf},
    body:JSON.stringify({title:'Negative permission test',description:'Must fail'})});
  const body=await write.json();
  console.log(JSON.stringify({reviewHTTP:read.status,visibility:data.visibility,
    anaCaseVisible:true,sellerCreateHTTP:write.status,denial:body.error ?? null,
    passed:write.status===403 && body.error==='wso2_scope_denied'},null,2));
})();
```

If Marcos unexpectedly has `ciam:cases:create`, this script may create a record. Treat that as a **critical RBAC defect**; stop and examine WSO2 roles instead of accepting it. Do not use a super/tenant admin account as the seller.

## 5. MFA gate: approve scope does not mean MFA success

Use Marcos's authenticated Aurora Web browser with `ciam:cases:approve`. Create a **nonexistent UUID** (never use Ana's actual case ID) and attempt approval:

```javascript
(async () => {
  const client='aurora-web';
  const me=await (await fetch('/api/identity/me',{credentials:'same-origin'})).json();
  const u=me.clients?.[client];
  if (!u?.authenticated || !u.permissions?.includes('ciam:cases:approve')) throw Error('No verified approval scope');
  const missingId=crypto.randomUUID();
  const r=await fetch(`/api/brands/aurora/cases/${missingId}/approve?client=${client}`,
    {method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':me.csrf}});
  const data=await r.json();
  console.log(JSON.stringify({testTarget:'NONEXISTENT_CASE',http:r.status,
    reason:data.error ?? null,passed:r.status===403 && data.error==='fresh_wso2_totp_required'},null,2));
})();
```

**Acceptance without fresh WSO2 TOTP:** HTTP 403 `fresh_wso2_totp_required`. This negative gate passed on 2026-10-28. **Do not claim positive TOTP approval** until an authenticator is genuinely enrolled, WSO2 completes a challenge, and the BFF verifies `totp` in a validated `amr` plus `auth_time` no older than 300 seconds. The current gate is a verification requirement, not an automated step-up redirect.

## 6. Carbon Super acceptance (server administration only)

```bash
python3 scripts/ciam-carbon-super-readback.py
python3 scripts/ciam-identity-ops.py inventory --output docs/CIAM_V5_TENANT_INVENTORY.md
```

Check the root tenant enumeration includes Aurora and Brisa (but note: this endpoint may not list the built-in Carbon Super domain as an ordinary tenant). Check super applications, API resources, SCIM users and roles using the status fields. A 401/403/404/unknown schema is **not** proof that none exist; it is `UNVERIFIED` and requires further investigation. This script is **GET-only** and logs no admin password. Never log into a brand OIDC client as Carbon Super `admin`.

## 7. Guided Experience Center acceptance checklist

- Open `/lab`. Confirm six guided journeys, real sign-in links for all four sites, and navigation back to lab from storefronts.
- Use the appropriate tenant/user. The page session and available actions must update from `/api/identity/me`, not locally chosen personas.
- Open UserInfo; confirm actual response from WSO2, even if it contains only `sub`.
- Verify cases listing uses WSO2 scopes and tenant isolation; safe denial should not be replaced with synthetic fallback.
- Confirm legacy fake `/api/experience/meta` remains HTTP 503 and old synthetic standalone pages remain disabled.
- Mark privacy preferences/consent, B2B delegated admin, token-exchange agents, and successful MFA workflows **Not Implemented / Not Verified** until their real APIs and positive tests exist.

## 8. Recording results / failure decisions

Maintain a test record with date, server version, repo SHA, tenant, client, account alias (not password), actual status codes, pass/fail and known limitations. The source-only tests and management readbacks are not substitutes for browser OIDC acceptance.

If a protected call is 401, inspect WSO2 introspection audience and issuer, as we did for the business API; do **not** turn off validation. If 403, inspect live granted scopes and role audience/membership. If a bootstrap journal says `*-started`, reconcile the remote record by GET before any new write. Do not rerun `apply` blindly.

### Known outstanding scenarios

Successful TOTP approval and enrollment; B2B organization delegation/readback; privacy preference management; names/email claim release; verified ID-token role claims; native mobile app integration; agent token exchange; cross-tenant pairwise identity correlation; production-grade session/case storage, backup/restore and observability. These are separate requirements, not implied by four successful customer browser flows.
