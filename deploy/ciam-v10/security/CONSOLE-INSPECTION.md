# WSO2 IS 7.3 GA — Console inspection for Magalu risk

The native Console does **not** automatically display Java/OSGi service state,
internal per-tenant risk scores, campaign correlations, SQL events, or decision
history. Do not claim an invented Console "Risk Dashboard" or a verified UI.

Once **security-verify** confirms management GET/readback, sign in to the exact
v10 Console at **https://localhost:9444/console** as the applicable tenant admin.
Do not use the Update18+ :9443 lab.

1. **Applications → aurora-web → Login Flow**: Basic step 1, TOTP step 2,
   conditional authentication enabled, `magaluRiskCheck` script call.
2. Repeat for **aurora-app, brisa-web, brisa-app** in the *corresponding root
   tenant*. Brisa must be checked independently; Aurora's original ACR-triggered
   seller approval flow must still be present.
3. **Login & Registration → Login Security → Login Attempts**: check tenant
   account-lock status and thresholds after the guarded security-bootstrap applies and reads them back. The
   two tenants have different configured failure thresholds and durations.
   **Readback alone is not proof of actual lock timing**: run live tests.
4. Use `./scripts/ciam-v10.sh security-verify` for a machine-readable
   GET-only inspection report. It does not prove actual DENY, STEP_UP, absence
   of a token or delivery of security events: those require live login tests.

**Not visible inside stock IS Console:** detailed risk score per request,
account baseline, rotated-IP campaign, event spool, cross-node PostgreSQL health
and audit retry. A separate secured administrative UI or a supported Console
extension is necessary to display these visually; none is verified on this GA
build. The bundled test/debug output must not be exposed unauthenticated.

For security acceptance, complete signed-token negative tests against WSO2
itself, not the BFF, before classifying the risk implementation as enforced.
