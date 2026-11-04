# P2.24 V15 — GA application-sharing cross-check (read only)

Prerequisites: Aurora V13 partner has `VERIFIED` journal, V14.1 source pin
is `874b5643937417a05eef8e3cbc646c8651f0f54548779965c78fe4f12368c938`,
and the existing WSO2 image and HTTPS anchor remain unchanged.

The existing V14 GET /share may omit an organizations collection on WSO2 7.3 GA.
V15 uses a second documented GET `/t/aurora.identity.test/api/server/v1/applications/{id}/shared-apps`
for the **same verified, non-management application candidates**. It detects
explicit mapping arrays, omitted mappings, policy omissions, duplicate mappings,
and references to the partner or other organizations. Responses never grant
partner business access or delegated administration.

The proposed future app name is **P2 Aurora Returns Partner Business Portal**.
This is a planning label, not registration or an approval to share an existing app.

Startup after V13 and V14 runs V15 `status`; pending evidence does not block
existing customer journeys. Unexpected malformed WSO2 data, changed source pin,
identity drift, or foreign / unsafe transport fails closed. Only GET requests are
made to management APIs; no application creation, scope registration, sharing,
member creation, group creation, or grants occur.

Follow-up creation/sharing requires an explicit separate, narrowly scoped approval.
New app configuration must be complete (OIDC redirect, roles, selected partner,
no future child inheritance), staged behind a durable journal and independently
read back. Neither V14 nor V15 alone authorizes anything.
