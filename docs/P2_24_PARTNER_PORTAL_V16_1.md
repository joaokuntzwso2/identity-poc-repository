# V16.1 — Callback evidence diagnosis and safe startup

V16's WSO2 creation never occurred in the captured live run: it stopped at
`V16_CALLBACK_NOT_IMPLEMENTED_IN_BFF`, before creating its durable intent.
The existing source check requires a literal callback path or URL in non-test
BFF source. Dynamic route construction may legitimately lack that literal.
Conversely, an OIDC redirect URI registered in WSO2 does **not** itself prove
that the BFF implements the route. Do not guess, synthesize or silently accept
it. V16 registration remains blocked until independently proven.

V16.1 adjusts both existing BFF startup gates to use `partner_portal_v16_1.py
bootstrap`. This invokes the original V16 one-time guarded `ensure` unchanged.
A missing literal BFF callback is `PENDING` **only** if the V16 write-ahead
journal is absent; normal unrelated customer journeys can continue. Any other
V16 error, tampering, ambiguous write or existing journal remains a hard block.
When actual callback evidence is fixed, the gate automatically attempts the
approved at-most-once registration on the next startup, with V16's original
prior intent and independent WSO2 readback.

Run the read-only diagnostic (sanitized: no redirect URLs, client IDs, raw
server responses, source lines, tokens, passwords or person data):

```
python3 scripts/p2/partner_portal_v16_1.py diagnose
```

`exactCallbackPathLiteralPresent` proves *only a textual occurrence*, not a
working route. `dynamicCallbackConstructionCandidate` is only a clue. Neither
is used to authorize creation. An actual BFF route implementation and its
client/issuer/PKCE/state validation must be reviewed before relaxing V16's
check. Avoid plugging the existing Aurora customer callback into a new OAuth
client without a sound client binding and callback strategy.

Safety: no sharing, role or user writes, no Brisa or Carbon Super changes,
no image upgrades, and no registration POST from V16.1 itself. V13–V15
startups remain in place. If an INTENT exists, keep it; use the original
GET-only V16 recovery, never delete it or blindly POST again.
