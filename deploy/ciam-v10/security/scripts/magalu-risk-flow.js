/* NOT FOR UNGUARDED INSTALL. All four apps require Basic(1) and TOTP(2).
 * Called after verified Basic auth and before success/token issuance.
 * This script preserves Aurora's existing requested seller-approval ACR conditional.
 * ACTION CHALLENGE is mapped to native TOTP, fail-safe if not enrolled.
 * ACTION DELAY is a deny/retry rather than a thread sleep; no token is issued.
 * Step-up only completes after the TOTP authenticator succeeds.
 * GA 7.3 script integration must be verified by live auth tests.
 */
var onLoginRequest = function (context) {
    executeStep(1, {
        onSuccess: function (context) {
            var user = context.steps[1].subject.username;
            // Function must be server-registered by the exact GA binary-compatible OSGi component.
            var action = magaluRiskCheck(context, user);
            if (action === 'DENY' || action === 'DELAY' || action === null) {
                fail({'errorCode': 'access_denied', 'errorMessage': 'Authentication could not be completed'});
                return;
            }
            var sellerApproval = context.requestedAcr === 'urn:magalu:aurora:seller-approval:totp';
            if (action === 'CHALLENGE' || action === 'STEP_UP' || sellerApproval) {
                executeStep(2); // no onFail callback: an incomplete TOTP must not be bypassed
                return;
            }
        }
    });
};
