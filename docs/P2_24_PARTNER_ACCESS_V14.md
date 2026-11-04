# P2.24 V14 — Aurora partner application sharing inspection

## Verified baseline
V13 created `Aurora Returns & Fulfillment Partner` under the Aurora tenant. Its journal
holds the immutable WSO2 organization ID and the verified parent. V12 created a
separate creator client. V8 created the view-only M2M. No Brisa or Carbon state is
used to perform these checks.

## V14 behavior and boundaries

At ordinary BFF startup, after V13 `ensure` has successfully verified the Aurora
partner, V14 performs GET-only application and sharing inspection using the
existing tenant-qualified administrative credential loader, the pinned certificate
and the exact `/t/aurora.identity.test/api/server/v1/applications` path.

It excludes management applications and M2M-only clients from business-app
candidates; it never selects an app automatically for sharing. Sharing lists are
bounded and paginated, with cursor paths rebuilt inside Aurora. Results are
sanitized (counts and evidence category only, no client secrets or identifiers).
A shared-application result does **not** establish business API authorization or a
partner's ability to sign in. These require signed user-token, organization,
role, scope and negative-test evidence in a future increment.

The GET API is `/t/aurora.identity.test/api/server/v1/applications/{id}/share`
(requires `internal_shared_application_view` for OAuth clients). The actual
WSO2 7.3.0 GA response must be verified in the environment; missing permission
is labeled pending, not interpreted as an empty shared list.

## Commands

```sh
python3 scripts/p2/partner_access_v14.py status
python3 scripts/p2/partner_access_v14.py audit
```

`status` is part of both BFF startup paths and emits a distinct pending result if
application sharing is absent or the specific sharing-view permission has not
been demonstrated. Unexpected drift or unsafe response shapes fail closed.
`audit` exits nonzero unless WSO2 readback demonstrates at least one specifically
selected, role-scoped share to the verified Aurora partner; even this result
**is not** business access acceptance.

## Next approved increment needed

Choose or register a purpose-built **Aurora partner business application**, verify
its login flow and role audience, and grant **only** the selected organization
access with `internal_shared_application_create` in a separate approved workflow.
The current V14 installer does not make this grant and does not create partner
users, roles, permissions or apps. Async sharing `202` is not evidence of
completion; follow with observed GET state and access-denial tests.

## Sources
- WSO2 Identity Server application management API, application sharing GET and
  specific organization sharing: https://is.docs.wso2.com/en/latest/apis/application-rest-api/
- WSO2 Identity Server organization app sharing guide:
  https://is.docs.wso2.com/en/latest/guides/organization-management/share-applications/
