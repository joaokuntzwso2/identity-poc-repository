# Requirements 24–31: current evidence and next priority (not a completion certificate)

| Requirement | Supported live proof known from user output | Remaining before DoD |
|---|---|---|
| 24 B2B/delegation | Verde child org; app sharing; least-privilege role/group; actual delegated end-user token; GET Verde Users HTTP 200; root/Brisa/role admin denied | New delegated create (this increment **pending live run**), usable partner-facing admin UI, membership changes, second verified partner denial, deactivation and business access |
| 25 Consent | Prior app-local consent tests are not WSO2 consent proof | Consent Management v2 update-level gate, supported acceptance environment, purpose/version, grant/decline/revoke and downstream enforcement |
| 26 Adaptive | Existing assurance/step-up unit tests | Real conditional WSO2 authentication policy, live ACR/AMR/auth_time evidence and negative cases |
| 27 Passkeys | No live end-to-end evidence | FIDO2 enrollment, authentication, lifecycle and recovery with hardware/browser |
| 28 Federation | No controlled external IdP proof | Real IdP configuration, mapped claims, login, cancellation, isolation and outage |
| 29 Lifecycle | WSO2 user creation/readback foundation; this increment adds a delegated ordinary user **once live verified** | Scoped profile updates, suspension, deactivation, revocation, ongoing session denial |
| 30 Audit | Business evidence and verification tests | Native WSO2 events/logs correlated with business timeline |
| 31 Branding | Existing Aurora/Brisa Experience Center foundation | Advanced production-supported narratives, app journeys and stakeholder KPI evidence |

WSO2 version is not to be upgraded implicitly. This is a truth-preserving work ledger, not fabricated pass/fail coverage. Only the user's WSO2 live output can move a planned gate to verified.
